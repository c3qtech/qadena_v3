# Adding a node to a running chain — sponsored or self-funded, scripted or by hand

The operator's document.  [HOWTO-FLEET-BRINGUP.md](HOWTO-FLEET-BRINGUP.md) drives the same
steps through `testscripts/nth_node_bringup.sh`, which exists **for testing a fleet from a
workstation** — it ssh-es into both machines and watches them from outside.  A real operator
runs the steps below on their own node, and someone holding the sponsor bucket's keys runs the
funding ceremony wherever those keys live.  Both paths were exercised end-to-end on
2026-09-01/02: M2 joined sponsored, M3 joined self-funded, peer agreement passed on both.

## First, decide two things

**1. Sponsored or self-funded?**  This is who pays the node's transaction fees, forever.

| | sponsored | self-funded |
|---|---|---|
| gas | a bucket's recurring FEE GRANT pays every fee | the node's own balance |
| liquid balance held | **zero** | a working balance (~100,100 QDN by the launch design) |
| what the funder sends | grant (no coins) + the bond if validating | one transfer: bond + working balance |
| lives as | agency: can act, cannot hold value | ordinary operator |

**2. Full node or validator?**  A full node needs NO stake, ever.  Validating needs a real
self-bond of exactly `min-self-delegation` (10,000 QDN — read the authoritative value from the
node's own `config.yml`, `validators.first().app.min-self-delegation`, a bare aqdn integer).
A fee grant can never supply it: grants pay fees, and staked principal is neither.

**The money is one-way.**  A funded pioneer address holds no eKYC credential, so it can bond
and pay gas but CANNOT transfer out (AML code 1159).  Send the exact amounts; a mistyped
recipient needs a governance whitelist proposal to recover.

---

## The manual path

### 0. Install the release package  (on the new node)

Build nothing here.  The primary builds, packages (`buildscripts/package_release.sh`), and you
install the tarball **as the user who will own the node — not sudo**:

```sh
tar xzf qadena-full-<ver>-<commit>.tar.gz
./qadena-full-<ver>-<commit>/install.sh
```

The installer prints the enclave's uniqueID.  It must already be registered and `active` on the
chain (`qadenad query qadena list-enclave-identity`) or sync-enclave will be refused.

### 1. Mint the pioneer key and stop  (on the new node)

Pick a pioneer name that has NEVER been used on this chain — names are burned forever, even
after a node is wiped (`qadenad query qadena list-interval-public-key-id` shows the taken ones).

```sh
~/qadena/scripts/add_full_node.sh \
    --pioneer <name> \
    --advertise-ip-address <this node's ip> \
    --genesis-pioneer-first-ip-address <primary's ip> \
    --stop-for-funding \
    [--foundation-sponsored [<granter-address>]]
```

Interactive, needs a real terminal.  It wipes any prior node state, mints the key, prints the
address, and exits.  Pass `--foundation-sponsored` if that is the plan — it changes what the
node later *waits for* (a grant instead of a balance).

Give the printed address to whoever holds the money.

### 2. The funding ceremony  (wherever the bucket's keys live)

The sponsor bucket (`nodeops` — sponsoring nodes is what that bucket is for) is an N-of-M
multisig, so nothing here runs on the primary.  `scripts/multisig_sign.sh` drives it; set
`QADENA_NODE=tcp://<primary>:26657` and `QADENA_CHAIN_ID`.

**Sponsored** — the grant, plus the bond only if this node will validate:

```sh
multisig_sign.sh build-feegrant --granter nodeops --grantee <addr> \
    --msgs "<LIFE_MSGS>" --out grant.json
multisig_sign.sh build-send --from nodeops --to <addr> --amount 10000qdn --out bond.json
# each member, independently:
multisig_sign.sh sign --tx grant.json --multisig nodeops --from nodeops-mN --out gN.json
multisig_sign.sh sign --tx bond.json  --multisig nodeops --from nodeops-mN --out bN.json --sequence-offset 1
# then once:
multisig_sign.sh combine --tx grant.json --multisig nodeops --out sg.json g1.json g2.json g3.json
multisig_sign.sh broadcast --tx sg.json
multisig_sign.sh combine --tx bond.json --multisig nodeops --out sb.json b1.json b2.json b3.json
multisig_sign.sh broadcast --tx sb.json
```

`LIFE_MSGS` (the full lifetime set — a join-only or expiring grant silently stops SS
re-sharing, and a grant without MsgVote makes the fleet ungovernable):

```
/qadena.qadena.MsgPioneerAddPublicKey,/qadena.qadena.MsgPioneerUpdateIntervalPublicKeyID,
/qadena.qadena.MsgPioneerUpdatePioneerJar,/cosmos.staking.v1beta1.MsgCreateValidator,
/qadena.qadena.MsgPioneerUpdatePublicKey,/qadena.qadena.MsgPioneerUpdateJarRegulator,
/cosmos.gov.v1.MsgVote
```

`--sequence-offset 1` goes on **sign**, on every share of the second tx — the sequence is
written when a share is signed, not at build.  Drop it if the first tx already landed.

**Self-funded** — one transfer: `--amount 110100qdn` (10,000 bond + 100,100 working balance,
the launch design's own figure) and no grant.  Same sign/combine/broadcast, no offset needed.

### 3. Resume the join  (on the new node)

Re-run the same `add_full_node.sh` command **without** `--stop-for-funding`.  Answer
`[c]ontinue` — it keeps the funded key; `[s]tart from scratch` mints a new address and strands
what you just sent.  It fetches genesis, waits for the grant (sponsored) or the balance, and
runs `sync-enclave`.  Answer **n** to "start the node now?" and start it yourself:

```sh
~/qadena/scripts/start_qadena.sh
```

### 4. Verify it is a live full node

- blocks advance against the WALL CLOCK — `catching_up` lies on a halted node
- `query qadena list-interval-public-key-id` shows your pioneer name
- `curl -s localhost:26657/status` reports the right chain-id and moniker

A full node is done here.  Stop unless it should validate.

### 5. Convert to validator  (on the new node, optional, any time later)

```sh
~/qadena/scripts/convert_to_validator.sh --validator-stake 10000 \
    [--foundation-sponsored [<granter-address>]]
```

Sponsored, it bonds exactly `min-self-delegation` and pays the fee from the grant; the bond
coins must already be on the address (step 2).  Self-funded, it bonds `--validator-stake` from
the working balance.  Afterwards the validator appears in `query staking validators`, and —
because a pioneer publishes its address only on its first PROPOSED block — the node only now
becomes addressable to the SS re-share audit.

**Quorum warning:** with N equal-bonded validators, the chain halts if more than a third of
them die, and it cannot jail its way out (jailing needs blocks).  At N=2 a single loss is
fatal — proven 2026-09-01.  Do not linger at small equal-stake counts; skew power by
delegation or add the next validator promptly.

---

## The scripted path (test fleets)

The same steps, driven from a workstation:

```sh
testscripts/nth_node_bringup.sh --primary <ip> --joiner <ip> --pioneer <name> \
    --until 3 [--foundation-sponsored <granter-addr>] [--convert-to-validator]
# ...run the step-2 ceremony above (phase 3 prints it, amounts included)...
testscripts/nth_node_bringup.sh --primary <ip> --joiner <ip> --pioneer <name> \
    --from 5 --until 8 <same flags>
```

Pass the SAME flags on both runs — they select what phase 3 tells you to sign and what phase 5
waits for.  Phases 4 and 7 skip money already delivered, so the ceremony is never repeated.
See [HOWTO-FLEET-BRINGUP.md](HOWTO-FLEET-BRINGUP.md) for the phase list and its traps —
above all: never re-run phase 3 with a DIFFERENT pioneer name against a joined node; it wipes.
