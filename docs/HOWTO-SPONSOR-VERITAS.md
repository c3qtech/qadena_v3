# Sponsoring VERITAS — the Qadena Foundation's procedure

What the **foundation** does to bring up the SEC PH VERITAS deployment on a launch chain.

This is the counterpart to [HOWTO-SEC-VERITAS.md](HOWTO-SEC-VERITAS.md), which is SEC's half —
`veritas_scripts/step_1.sh`, `step_2.sh` and `step_3.sh`.
It is deliberately a separate document, because the two sides never run each other's commands and
neither holds the other's keys — that separation is the point of the whole structure, and a single
runbook covering both would obscure it.

> **This is not `testscripts/setup_veritas.sh`.** That script is a test harness: it plays both roles
> at once, holds every key in one keyring, and funds everything with `tx bank send --from treasury`
> because on the devnet `treasury` is a single key the primary holds. **On a launch chain no such
> key exists.** Every bucket is an N-of-M multisig whose members are on separate machines by design,
> so each foundation spend below is a ceremony, not a transaction.

---

## Who does what, and in what order

The two sides alternate. Neither can proceed without the other's previous output.

| # | who | action | hands over |
|---|---|---|---|
| 1 | **FOUNDATION** | `sec_veritas_before_step_1.sh --stage prepare` | `foundation-veritas-appsvr` + `foundation-veritas-users` addresses, chain-id |
| 2 | SEC | `step_1.sh` | SEC's **admin address** |
| 3 | **FOUNDATION** | `sec_veritas_after_step_1.sh --sec-admin <addr>` | — |
| 4 | SEC | `step_2.sh` | **two proposal ids** |
| 5 | **FOUNDATION** | `sec_veritas_after_step_2.sh <id> <id>` | — |
| 6 | both | wait for both proposals to reach **PASSED** | — |
| 7 | SEC | `step_3.sh` | the **sponsor pool**, as a paste block |
| 8 | **FOUNDATION** | `sec_veritas_after_step_3.sh --pool-addresses <file>` | the two sponsor addresses, confirmed |

**Every foundation script is named for the step it follows**, so `ls` gives you the order without
opening anything:

```
foundation_scripts/                     veritas_scripts/
  sec_veritas_before_step_1.sh            step_1.sh
  sec_veritas_after_step_1.sh             step_2.sh
  sec_veritas_after_step_2.sh             step_3.sh
  sec_veritas_after_step_3.sh
```

`sec_veritas_after_step_2.sh` is a thin wrapper on `sec_veritas_before_step_1.sh --stage approve` --
one implementation, because it shares that script's whole multisig ceremony, but two entry points so
a stage is never hidden behind a flag on a file named for a different moment.

**Why the foundation must run 3, 5 and 8 rather than delegating them.** A fee grant is signed by its
*granter*, and `authz` cannot be sub-delegated. So even with the step 3 authorisation, SEC cannot
issue grants *as* the foundation for the app-server's pool. Moving steps 3, 5 or 8 into SEC's scripts
would put a foundation private key on a SEC machine — the one thing this structure exists to prevent.

---

## The funding model

Everything below is **foundation-sponsored** -- the same word the node bring-up uses
(`add_full_node.sh --foundation-sponsored`). The foundation pays, by fee grant, and SEC never
holds tokens: no SEC treasury, no transfer, no AML whitelist exemption. It is the default in every
script, settled once in `scripts/setup_env.sh` as `VERITAS_FUND_MODE`, which also accepts the older
spelling `feegrant`.

`VERITAS_FUND_MODE=banksend` restores the retired path where a `sec-treasury` is funded and fans
tokens out per wallet. It is kept only for a deployment mid-migration.

> Until 2026-09-05 the three step scripts each declared their **own** default and disagreed --
> step_2 said `banksend` while step_3 and `create_user.sh` said otherwise. With the variable unset,
> step_2 waited forever for funds in a treasury the sponsored flow never fills. Only
> `setup_veritas.sh` exporting the value hid it. One default, one place, now.

---

## What SEC hands over, and when

Three handoffs, each printed by the step that produces it. SEC keeps its own working directory
(`~/sec-veritas`, or `$VERITAS_SEC_HOME`) holding `variables.json`, `mnemonics.json` and
`pool_addresses.json` — the counterpart to the foundation's `~/launch`.

| after | SEC gives you | you use it in |
|---|---|---|
| `step_1.sh` | the **admin address** (`sec-veritas-admin`) — zero balance, by design | `sec_veritas_after_step_1.sh --sec-admin` |
| `step_2.sh` | **two proposal ids** | `sec_veritas_after_step_2.sh <id> <id>` |
| `step_3.sh` | the **sponsor pool**, as a paste block | `sec_veritas_after_step_3.sh --pool-addresses` |

Nothing else crosses between the two sides. No key, no mnemonic, and — in foundation-sponsored
mode — no tokens.

---

## Before you start

- **A launch chain**, built and producing blocks. See
  [HOWTO-LAUNCH-CHAIN-BRINGUP.md](HOWTO-LAUNCH-CHAIN-BRINGUP.md).
- **The bucket multisigs exist in your keyring**, along with enough member keys to meet each
  threshold. `foundation_scripts/derive_launch_keys.sh` creates them.
- **`jq` and `python3`.**
- **The chain-id**, if `qadenad status` cannot reach a node: `export QADENA_CHAIN_ID=qadena_482-1`.

### Which buckets pay, and why it is not a choice

`tokenomics/allocations.csv` is the authority (HARD RULE 1) and it already names them:

| bucket | account | role here | custody | stakes |
|---|---|---|---|---|
| 10 Public Sector Programs | `pubsec` | funds the two sponsor accounts | **5-of-7** | no |
| 03 Foundation Treasury | `foundation` | deposit + vote on the proposals | 3-of-5 | **yes** |

Bucket 10's own notes read *"Sub-allocations: **SEC PH VERITAS 60M**; future MOUs; OTC swap reserve.
Entities only, never individuals. **Funds feegrant sponsor account**"*, and its `permanent_home`
column names `foundation-veritas-appsvr`/`foundation-veritas-users` outright. Bucket 03 is the **only** bucket with
`stakes = yes`, so voting power can come from nowhere else — pubsec could fund the deployment but
could never vote it through.

Funding VERITAS out of Adoption or Node Operations would spend an allocation earmarked for something
else, against the file everyone reconciles against later. Override only with a decision recorded
somewhere: `--fund-bucket` / `--stake-bucket`.

---

## `sec_veritas_before_step_1.sh` — stake and fund

```sh
foundation_scripts/sec_veritas_before_step_1.sh --stage prepare \
    --coord-home       ~/launch/coord \
    --keyring-backend  file \
    --mnemonics-dir    ~/launch/mnemonics \
    --pubsec-members   pubsec-m1,pubsec-m2,pubsec-m3,pubsec-m4,pubsec-m5 \
    --members          foundation-m1,foundation-m2,foundation-m3
```

`--coord-home` is not optional in practice: the bucket multisigs live in the **coordinator**
keyring `derive_launch_keys.sh` created, never the node's -- `init.sh` runs `rm -rf $QADENAHOME`.
Without it you get `no key 'pubsec' in the keyring`. `--mnemonics-dir` is required whenever a
sponsor account does not exist yet; the script refuses to mint a key whose mnemonic has nowhere
safe to go. Both are asked for once and reused, using the same single passphrase
`derive_launch_keys.sh` set.

Three things happen:

1. **Creates `foundation-veritas-appsvr` and `foundation-veritas-users`** if they do not exist, as ordinary
   `eth_secp256k1` keys — not multisigs. They are the *granter of record* for fee grants and must be
   able to sign alone. Existing keys are reused, never re-minted: their addresses are what SSM and
   the deployment's `.env` already point at.
2. **Funds each with 100,000 QDN from `pubsec`** (`--amount` to change). Two separate ceremonies.
   `testscripts/setup_veritas.sh` uses 2,000,000 for the same two accounts on the devnet; that
   figure is about fee volume, not endowment. **Top up rather than overfund** -- another transfer
   from `pubsec` is one more ceremony, but getting money back *out* of a sponsor account needs a
   governance proposal, because it is not a wallet and not on the AML whitelist (code 1159).
3. **Delegates from `foundation`** enough to carry an **expedited** vote later.

### Why two sponsor accounts rather than one

They behave differently, and separating them is worth the extra account:

- **`foundation-veritas-appsvr`** — SEC's own operational wallets. A **fixed** set, known at deployment, so
  they are granted directly and once.
- **`foundation-veritas-users`** — citizen wallets. These appear continuously (every onboarding, QR scan and
  key rotation mints one), so the app-server issues their grants at runtime via `authz`. That
  delegation is unbounded by nature; keeping it on a separate account confines it to the user float.

It also makes usage independently observable: appsvr burn tracks SEC's processing, users burn tracks
citizen activity, and a divergence between them is a real anomaly signal.

### How much stake, and why it is computed

An expedited proposal needs `expedited_threshold` (**0.667**) of the votes cast. Voting power follows
**bonded** stake and is credited to the **delegator**, not the validator. If the foundation is the
only voter, its bonded stake must exceed twice everyone else's:

```
self / (self + other) > 2/3    <=>    self > 2 × other
```

The script reads the staking pool, subtracts what `foundation` has already bonded, and delegates the
difference plus a 20% margin — which absorbs a validator joining mid-ceremony. It is computed rather
than hardcoded because the answer changes every time a node joins.

> The arithmetic runs in Python, not the shell. These are **aqdn**: 504M QDN is 5.04×10²⁶, and zsh
> truncates integers past 20 digits — `2 * other * 12` evaluates *negative* at real magnitudes, which
> would silently skip the delegation. HARD RULE 3.

Override with `--stake <qdn>` if you know better, or `--validator <valoper>` to pick the delegate
(default: the largest bonded validator).

**Hand SEC** the two addresses and the chain-id, printed at the end. Then they run `step_1.sh`.

---

## `sec_veritas_after_step_1.sh` — delegate grant authority

```sh
foundation_scripts/sec_veritas_after_step_1.sh \
    --sec-admin <SEC's ADMIN address -- see below> \
    --foundation-appsvr foundation-veritas-appsvr
```

### Which address is "SEC's admin" -- and it is NOT sec-treasury

**Do not use the address `step_1.sh` prints.** That is `sec-treasury`, and it belongs to the
retired *banksend* model. In the sponsored flow nothing uses it: `step_2.sh:53` and `step_3.sh:73`
both repoint `treasuryname` at the foundation account and say so on screen -- *"sec-treasury is not
used"* -- and `sec_veritas_after_step_3.sh` never mentions a treasury at all. `step_1.sh`'s closing message
("When QFI grants the necessary amount to sec-treasury...") is stale.

The admin is a **different key, defined by holding nothing**:

| property | value |
|---|---|
| balance | **zero, permanently** -- that is the design, not a starting state |
| authz | granted by this step to send `MsgGrantAllowance` **as** the foundation |
| feegrant | granted by this step for `MsgExec`, so it never needs a balance to sign |
| created by | **no script** -- see the gap below |

A zero-balance account can sign because the fee grant covers it; `testscripts/test_toll_free.sh`
exercises exactly this (`fresh_key` creates the key with no funding, and `tx authz exec --from
secadmin --fee-granter foundation-users` then succeeds).

**`step_1.sh` now creates it and prints exactly one address.** In the default
foundation-sponsored mode it creates `sec-veritas-admin`, skips the treasury entirely, and ends
with:

```
SEND THIS ONE ADDRESS TO QFI:
    sec-veritas-admin : qadena1...
    export VERITAS_SEC_ADMIN=sec-veritas-admin
```

That address is what `--sec-admin` takes. `--fund-mode banksend` restores the old treasury path.

> **STILL UNPROVEN END TO END.** `testscripts/test_authz_feegrant.sh` proves the *mechanism* --
> a genuinely distinct signer, secadmin ending at exactly 0 balance, and a repeat failing after
> revoke. But `setup_veritas.sh` has never exported `VERITAS_SEC_ADMIN`, so in every full
> bring-up run `grant_as_foundation` took its no-signer branch and signed directly as the
> foundation. **The wiring through step_1..3 has not been exercised.** Expect to debug it on the
> first real run, and check a transaction's `fee.granter` before you suspect the grant -- the
> recurring cause of `spendable balance 0aqdn` is a transaction that does not NAME the grant.

This replaces the old "QFI grants tokens to sec-treasury" handoff. **Nothing is transferred. SEC
holds no tokens at all.** What it receives is a revocable permission to spend the foundation's money
on *fees*, and nothing else.

Concretely, SEC may send `/cosmos.feegrant.v1beta1.MsgGrantAllowance` as the foundation, and have the
foundation pay for those `MsgExec` transactions. It is needed because `step_3.sh` must grant every
wallet it creates — a wallet holds nothing on a toll-free chain and cannot even claim its own
credential without a grant — so without this, step 3 would need a foundation key on a SEC machine.

**Understand what you are signing.** `GenericAuthorization` cannot cap an amount or restrict a
recipient. This is a real trust grant, bounded by three things and no others:

- its **expiry** — one year by default; `--expiration <unix-seconds>` to shorten it,
- the **spend limits SEC puts on the grants it issues**,
- your ability to **revoke it instantly**: `qadenad tx authz revoke <sec-admin>
  /cosmos.feegrant.v1beta1.MsgGrantAllowance --from foundation-veritas-appsvr`.

Shorten the expiry for a pilot. A year is chosen to avoid stranding a production deployment, not
because a year is safe.

---

## `sec_veritas_after_step_2.sh` — approve the proposals

`step_2.sh` prints two proposal ids — one for the identity service provider, one for DSVS.

```sh
foundation_scripts/sec_veritas_after_step_2.sh 12 13 \
    --members foundation-m1,foundation-m2,foundation-m3
```

Deposits 10,000,000 QDN and votes **yes** on each, from `foundation` — the deposit needs liquid
tokens and the vote needs bonded ones, and bucket 03 is the only bucket with both.

Then watch each to `PASSED` before SEC runs `step_3.sh`:

```sh
provider_scripts/query_service_provider_proposal.sh 12 --wait
provider_scripts/query_service_provider_proposal.sh 13 --wait
```

On a launch chain with the real governance clock this is **6 hours** expedited, 72 hours if the
expedited track fails and it falls back. On a testnet rendered with `--test-gov-timings` it is
about 30 seconds. Plan the handoff accordingly — this is the step where a bring-up waits.

---

## `sec_veritas_after_step_3.sh` — authorise the sponsor pool

SEC's `step_3.sh` ends by printing a **paste block**. Paste it into your terminal exactly as given:

```sh
cat > /tmp/veritas-pool.json <<'POOLEOF'
{
  "chain_id": "qadena_4824-1",
  "sponsor_base": "sec-create-wallet-sponsor",
  "count": 30,
  "pool": [ {"name": "...", "address": "qadena1..."}, ... ]
}
POOLEOF
foundation_scripts/sec_veritas_after_step_3.sh --pool-addresses /tmp/veritas-pool.json \
    --coord-home ~/launch/coord
```

Per pool wallet it sends **two** transactions, both `--from foundation-veritas-users`:

| grant | effect |
|---|---|
| `authz grant <wallet> --msg-type MsgGrantAllowance` | the wallet may issue fee grants **as** `foundation-veritas-users` |
| `feegrant grant <users> <wallet> --allowed-messages MsgExec` | the foundation pays for those `MsgExec` transactions |

At `count: 30` that is **62 transactions**. Neither moves money; both are revocable in one transaction.

### Why a pool, and why both grants

The app-server picks an **arbitrary pool member per request**, so several onboardings proceed in
parallel without colliding on one account's sequence number. It sets the inner
`MsgGrantAllowance.Granter` to `foundation-veritas-users`, wraps it in a `MsgExec` **signed by the
sponsor wallet**, and names the foundation as fee payer. The first grant makes that exec resolve;
the second makes it payable. Both are load-bearing — this was confirmed against the app-server
source, which lives outside this repo.

### The file is checked, not trusted

Every failure here is silent and per-wallet: a short or stale pool means onboarding works for *some*
citizens and not others, which is the hardest shape to diagnose from a support ticket. So the file is
validated **before any keyring is touched** — a bad block is refused without even asking for a
passphrase:

| problem | result |
|---|---|
| file from another chain | `REFUSING: generated on chain 'qadena_482-1', this node is 'qadena_4824-1'` |
| `count` disagrees with the list | `REFUSING: declares count=30 (so 31 wallets) but lists 2` |
| address mangled in transit | `REFUSING: 'b' has address 'cosmos1nope', which is not a qadena address` |
| duplicate entry | `REFUSING: qadena1uu29… appears twice` |
| wallet never created | `NOT ON CHAIN: … / REFUSING: 1 of 2 pool addresses have no account` |
| good | `pool file verified: 31 wallets, chain qadena_4824-1, all present on chain` |

The count comes **from the file**, so a short pool is impossible rather than a silent partial
authorisation. `--sponsor-base` / `--count` still work for a devnet where one keyring holds both
sides' keys, but on a real deployment the foundation does not hold SEC's wallet keys and the paste
block is the only route.

---

## The multisig ceremonies

Every bucket spend above is build → sign (once per member) → combine → broadcast. The script drives
all four when the member keys are in your keyring.

**Members on the command line, or interactively.** `--members` / `--pubsec-members` take a
comma-separated list of key names. Omit either and you are prompted, with the bucket's threshold
shown.

**Members on separate machines.** Use `--print-ceremony`. Nothing is signed locally; you get the
exact command each member runs, and you collect the shares. No key, share or mnemonic ever crosses
the wire — only the account number/sequence and the fully signed transaction, which is public by
definition since the next thing that happens to it is broadcast to every validator.

**Two traps the script already handles**, and a hand-rolled ceremony does not:

- **The threshold is per bucket.** `pubsec` is **5-of-7**; most others are 3-of-5. Passing three
  members to a 5-of-7 bucket fails at `combine`, at the *end* of the ceremony.
- **The sequence.** Every signature commits to the bucket's account sequence, and it is written when
  a share is *signed*. Two transactions signed in one sitting both carry the current sequence, so the
  second is invalid the moment the first lands. The script signs consecutive spends at +0, +1, +2 …
  and every share of one transaction must agree on the number.

**If your workstation cannot reach the RPC** — a filtered VPN, or an outbound policy that permits
dynamically-linked binaries while denying Go ones — add `--via-ssh user@node`. Only the chain-touching
reads and the final broadcast run remotely; signing stays local.

---

## What can stop you

| symptom | cause |
|---|---|
| `no key 'pubsec' in this keyring` | you are not on the coordinator host, or `derive_launch_keys.sh` has not run |
| `combine` fails after every member signed | too few members for the threshold — `pubsec` is 5-of-7 |
| a spend broadcasts, the next fails | sequence collision; the script handles this, a manual ceremony must pass `--sequence-offset` |
| code **1159** on a transfer | the recipient is neither a wallet nor whitelisted. Fee grants are *not* bank sends and do not need the exemption — this is why no `whitelist_bank_send` step appears above |
| proposal never reaches quorum | `foundation` is not bonded enough; re-run `--stage prepare`, which recomputes and tops up |
| `cannot determine the chain-id` | no reachable node; `export QADENA_CHAIN_ID=…` |

---

## What this costs the foundation

| item | amount | from |
|---|---|---|
| `foundation-veritas-appsvr` float | 100,000 QDN | `pubsec` |
| `foundation-veritas-users` float | 100,000 QDN | `pubsec` |
| proposal deposits | 2 × 10,000,000 QDN | `foundation` — **returned** when a proposal passes |
| delegation | computed | `foundation` — **not spent**, and unbondable later |

Against bucket 10's 60M QDN VERITAS sub-allocation, the 200,000 float is the only outlay that leaves
the foundation.

### What a user actually costs -- measured, not estimated

Differenced across two complete 9-stage runs in `~/veritas-flow-evidence/` (both identical to the
aqdn):

| stage | fee |
|---|---|
| `cred-personal` | 234.677 QDN |
| `cred-email` | 58.669 QDN |
| `cred-phone` | 58.669 QDN |
| everything else (wallet creation, claims, signing) | 0.001 QDN |
| **one full onboarding** | **352.016 QDN** |

**Credential issuance is 99.99% of the cost.** Wallet creation, claims and signing are noise
beside it. So the float is really a credential budget:

| float | onboardings |
|---|---|
| 100,000 QDN | ~284 |
| 200,000 QDN (both accounts) | ~568 |
| 2,000,000 QDN | ~5,681 |

Two caveats. Those runs had all four wallet incentives at **zero**, so nothing was subsidised by
endowment -- these are true costs, not net-of-subsidy. And `testscripts/setup_veritas.sh`'s
`2,000,000` figure is **not** a sizing: it was deliberate headroom for a test chain, and should not
be cited as a mainnet basis.

Top up rather than overfund. Another transfer from `pubsec` is one more ceremony; getting money
back *out* of a sponsor account needs a governance proposal, because it is not a wallet and not on
the AML whitelist (code 1159). Credential issuance is by far the most expensive operation on this chain (measured at
~5.9×10¹⁹ aqdn, against ~3.2×10¹⁴ for a document signature), which is why the sponsor accounts are
sized well above the per-provider amounts SEC's own `step_1.sh` uses.
