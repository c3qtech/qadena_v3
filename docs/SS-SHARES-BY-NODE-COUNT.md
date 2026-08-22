# SS interval keys: what N nodes actually buys you

Answers the questions: with 1 node, 2, 3, 4, 5 — what gets generated and who can
reconstruct it?  And: many nodes exist, a new one joins, the first node is dead.

Read from `cmd/qadenad_enclave/enclave.go` (`getThreshold`, `addSSShare`,
`GenerateSecretShare`, `planSSReconstruct`, `runSSReconstruct`, `SetPublicKey`)
and confirmed against the running single-node devnet.

---

## 1. The threshold curve

`addSSShare` takes `shareCount = len(getAddressablePioneers())` and asks
`getThreshold(shareCount)`.  An "addressable" pioneer is one with a non-empty
`ExternalIPAddress`, which `updateIsValidator` publishes on the node's first
proposed block after bonding — so the count moves on its own schedule, not the
operator's.

| Pioneers | Threshold | Splits (distinct share values) | What each owner actually receives | Reconstruct needs |
|---|---|---|---|---|
| 1 | 1 | **0 — not split** (1 value, 1 copy) | **the whole private key** | 1 owner |
| 2 | 1 | **0 — not split** (1 value, 2 copies) | **the whole private key** (identical copy) | 1 owner |
| 3 | 1 | **0 — not split** (1 value, 3 copies) | **the whole private key** (identical copy) | 1 owner |
| 4 | 2 | 4 | a real Shamir share | 2 owners |
| 5 | 2 | 5 | a real Shamir share | 2 owners |
| 6 | 2 | 6 | a real Shamir share | 2 owners |
| 7–10 | 3 | 7–10 (= N) | a real Shamir share | 3 owners |
| 11–15 | 4 | 11–15 (= N) | a real Shamir share | 4 owners |
| 16+ | 5 | N | a real Shamir share | 5 owners |

**Below four pioneers there is no secret sharing at all.** `addSSShare` does not
call `shamir.Split` — it loops and hands every owner the same plaintext `privK`:

```go
if threshold == 1 {
    for i := 0; i < shareCount; i++ {
        shares = append(shares, privK)   // not a share; the key itself
    }
} else {
    byteShares, err = shamir.Split([]byte(privK), shareCount, threshold)
}
```

This is forced, not a choice: hashicorp's `shamir.Split` refuses a threshold
below 2, so "1-of-N" has to be spelled as N copies of the secret.

**Reading the splits column.**  `shamir.Split(privK, shareCount, threshold)`
always produces exactly `shareCount` pieces, one per owner -- so from four
pioneers up, splits == N and every owner's piece is different.  Below four the
call never happens, so there is only ever ONE value in existence, replicated N
times.  N copies of one secret is not an N-way split, and the distinction is the
whole security story: three pioneers means three complete keys, not three
thirds.

Four owners is where the meaning of the word "share" changes for every receiver.
`addSSShare` logs the crossing on purpose:

```
addSSShare pubKID=<id> owners=<n> threshold=<t> split=<bool>
```

That `split=` field is the one to grep for when reasoning about any historical
key.

---

## 2. Answering the questions directly

**One node — does it generate all the SS?**  Yes.  `InitEnclave` generates the
SS interval key, the jar key and the regulator key.  `getAddressablePioneers()`
returns just itself, so `shareCount=1`, `threshold=1`, and the single "share" is
the entire private key held by that one node.

Confirmed on the running devnet — every SS interval key ever minted here has
exactly one owner:

```
qadena1565dr5e6tsxd9zg3dsyc3uzzzhpr7leeaqt4px  ownerCount=1  owners=pioneer1
qadena1l8eez4gv8unw2tk6m39cde7wa83t9a69mta68k  ownerCount=1  owners=pioneer1
qadena1q66xewux72mxk6383s02xpk3wt4yl49zr7hz62  ownerCount=1  owners=pioneer1
qadena1tpagswkdrunwl2n2sut3e8czfejrhxdzmm9uy5  ownerCount=1  owners=pioneer1
```

**Two nodes.**  At the next rotation the new key has 2 owners and threshold 1.
Both hold a complete copy of the key.  Either one alone can reconstruct;
either one alone is also a total compromise.

**Three nodes.**  Same shape — 3 complete copies, threshold still 1.

**Four nodes.**  The first genuinely split key.  `shamir.Split(privK, 4, 2)`;
any 2 of the 4 reconstruct, any 1 alone learns nothing.

**Five nodes.**  2-of-5.  Note the threshold does *not* track the fleet: it
stays at 2 through six pioneers, so growing 4→6 adds redundancy but not
confidentiality.

---

## 3. The part that matters: owner sets are frozen at mint time

A rotation runs every `keyUpdateFrequency` (555) blocks, on the proposer only:

```go
if in.Height%keyUpdateFrequency == 0 {
    go func() { s.updateSSIntervalKey() }()
}
```

`updateSSIntervalKey` calls `GenerateSecretShare`, which mints a **brand-new**
key and shares it to whoever is addressable **at that moment**.

It never re-shares an **existing** key to a newly grown pioneer set.  There are
exactly two writers of the owner/share table in the whole enclave —
`addSSShare` at generation (`enclave.go:651`) and `SetPublicKey` when the
broadcast lands (`enclave.go:5356`) — and no refresh, re-share or
redistribution path of any kind.

So each interval key carries the owner set of its own era, permanently:

```
era with 1 addressable pioneer  -> owners = {that one},  threshold 1
era with 3                      -> owners = {those 3},   threshold 1
era with 5                      -> owners = {those 5},   threshold 2
```

`planSSReconstruct` recomputes `getThreshold(len(job.owners))` from the *stored*
owner list, so reconstruction is always evaluated against the era's set, not
today's fleet.  A fleet of fifty nodes does not make a genesis-era key any more
recoverable than it was on day one.

---

## 4. New node joins, first node is dead

Three things a joiner needs.  Only the third is a problem.

**Chain data** — genesis, node ID, peers, state-sync RPC servers.  Any healthy
node serves these.  Node 1 is not special.

**`sync-enclave`** — the jar and regulator private keys plus the seed's active
trusted-identity set, which is the joiner's root of trust.  Any *promoted*
pioneer can serve this; the keys were copied to each one when it was promoted.
Node 1 is not special here either — **but the tooling implies it is.**
`add_full_node.sh:775` passes `--genesis-pioneer-first-ip-address` straight in
as the seed:

```sh
qadenad_alias enclave sync-enclave $PIONEER $ADVERTISE_IP_ADDRESS \
    "tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657"
```

The parameter is operator-supplied and any live pioneer works, but the name says
"genesis pioneer first", so the obvious reading is "point this at node 1".  With
node 1 dead, the fix is to pass a surviving pioneer — the flag name is the only
thing standing in the way.

**Private-state seeding — this is where node 1 can be fatal.**  `sync-enclave`
deliberately withholds the share table:

```
// do not send the SSIntervalShares
// do not send our local private key cache
```

So the joiner must reconstruct every historical interval key itself, by asking
that key's own owner set.  `SeedStorePage` calls the real
`SetProtectKey`/`SetRecoverKey`, which decrypt each row's VShare with the
interval key that was current **when that row was created** (backlog item 100).

Therefore, per era:

| Era the row was created in | Owners | Survives node 1's death? |
|---|---|---|
| ≥ 4 addressable pioneers | 4+ | yes — needs any 2 of them |
| 2–3 addressable pioneers | 2–3 | yes — needs any 1 of them |
| **exactly 1 (the genesis era)** | **{node 1}** | **no — the key is gone permanently** |

For the genesis era node 1 is the sole owner of the key, and nothing ever copied
it anywhere else.  If node 1's `enclave_secrets` is gone, every row created in
that era is undecryptable by anyone, forever — and per item 100 a single
undecryptable ProtectKey/RecoverKey row halts the joiner during seeding.  The
symptom is "Encryption generic error" on a ProtectKey row, which names neither
the cause nor the era.

This is not a state-sync bug and no amount of fleet growth fixes it.  The window
is small — it is only the blocks between `InitEnclave` and the second pioneer
becoming addressable — but any AML/credential row minted inside it is pinned to
a key with a single custodian for the life of the chain.

Worth stressing: **"node 1 is dead" is the survivable case if its secrets survive.**
The fatal case is node 1's *sealed secrets store* being lost — and because
`MustSeal` binds to the enclave and the CPU, that store cannot be restored from
a backup taken on different hardware, nor from a node rebuild.  Losing the
machine is losing the key.

---

## 5. Things worth deciding

1. **Does the genesis era have live rows?**  On a chain whose real traffic began
   well after the fleet reached 4 pioneers, the exposure may be zero rows and
   the whole issue is theoretical.  That is a query, not a guess, and it should
   be answered before anything is built.
2. **Consider not serving traffic until ≥4 addressable pioneers.**  It converts
   the problem from "mitigate" to "cannot arise".
3. **A re-share path** — re-distributing an existing key to the current pioneer
   set — is the general fix, and does not exist today. It is also the most
   invasive, since it changes an owner set that everything else treats as
   immutable.
4. **Rename the `add_full_node.sh` flag**, or accept any pioneer explicitly.
   Cheap, and removes the one place the tooling points a joiner at a node that
   may be dead.
5. **Minor, and not a live bug:** `addSSShare` stores `shares[0]` as the
   generator's own share, but the generator is `pioneers[i]` for whatever `i`
   the store iteration gives it, not necessarily 0.  `SetPublicKey` overwrites
   it with the correct share when the broadcast executes, so steady state is
   fine.  If that broadcast never lands, the generator is left holding another
   pioneer's share and would contribute a duplicate x-coordinate at combine
   time — Shamir has no integrity check, so the failure would surface as the
   `isPrivKHex` rejection rather than as anything naming the cause.
