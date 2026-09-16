# Adding a node to a running LAUNCH chain — sponsored or self-funded

> **Joining an existing chain.** To create one, see
> [HOWTO-LAUNCH-CHAIN-GENESIS.md](HOWTO-LAUNCH-CHAIN-GENESIS.md).


For mainnet, and for a mainnet-parameter testnet — the procedure is the same, and so are the
requirements: every launch-chain node runs a real SGX enclave
([HOWTO-LAUNCH-CHAIN-GENESIS.md](HOWTO-LAUNCH-CHAIN-GENESIS.md) §Every node runs SGX), and the
package this node installs must be the one built on the primary, so the measurements match by
construction.

**The operator's document, and it is manual throughout.**  A real operator runs the steps below on
their own node, and someone holding the sponsor bucket's keys runs the funding ceremony wherever
those keys live — which is a different person on a different machine, by design.  The test fleet
drives the same steps from a workstation through `testscripts/nth_node_bringup.sh`; that is test
tooling and lives in [HOWTO-TEST-FLEET-BRINGUP.md](HOWTO-TEST-FLEET-BRINGUP.md).  Both paths were exercised end-to-end on
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

### 0. Build the package  (on a node that already has the build)

Nothing is built on the new node. Package the artifacts that are already installed and running,
on the primary or any node with the toolchain:

```sh
cd <the checkout>
./buildscripts/package_release.sh --out /tmp/pkg
```

It packages **what `install.sh` puts on a node** — `qadenad`, both enclaves, `libwasmvm`,
`cosmovisor`, `scripts/`, `config/` — because binaries alone are not enough and the easy omissions
fail late rather than loudly. It prints a manifest: the commit, each binary's version, and the
enclave `unique_id` and `signer`. Keep that output; step 0b checks the new node against it.

It **refuses to package an unsigned enclave from a machine that has SGX and ego**, because doing
that by accident ships a debug measurement — a different `unique_id` on chain, which the seed will
not accept. If the build was *deliberately* `--no-sgx` on SGX hardware, say so:

```sh
./buildscripts/package_release.sh --out /tmp/pkg --allow-debug
```

`testscripts/1st_node_bringup.sh --only 7` does all of this and forwards `--allow-debug` for you
when the run was `--no-sgx`; the bare command above is for when you are not using that path.
`--help` lists the rest (`--only`, `--changed-since`).

**If the enclave is NEW to the chain**, register it before installing anywhere — the packaging
output prints the exact command:

```sh
testscripts/test_update_enclave_identity.sh <unique-id> <signer-id> unvalidated
```

### 0b. Copy it to the new node and install

The primary usually cannot reach the new node directly, so the tarball goes via your workstation:

```sh
scp <packaging-host>:/tmp/pkg/qadena-full-<ver>-<commit>.tar.gz /tmp/
scp /tmp/qadena-full-<ver>-<commit>.tar.gz <new-node>:/tmp/
```

### 0c. Install the release package  (on the new node)

Install the tarball **as the user who will own the node — not sudo**:

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
multisig, so nothing here runs on the primary.

**If the foundation holds the whole coordinator keyring**, one command does it — build, sign with
each member, combine, broadcast, for both the grant and the bond:

```sh
foundation_scripts/sponsor_node.sh --grantee <addr> \
    --coord-home <coordinator dir> --keyring-passfile <its passphrase file> \
    --node tcp://<a node>:26657 \
    [--granter nodeops] [--self-bond 10000qdn]
```

It reads the threshold off the bucket and signs as `nodeops-m1..m<threshold>` (`--members`
overrides), issues the same seven-message non-expiring grant as the single-key script, and handles
the `--sequence-offset` below for you. Add `--print-ceremony` to emit the per-member commands and
send nothing — which is what to do when the members are separate people.

**The hand-driven ceremony**, for exactly that case. `scripts/multisig_sign.sh` drives it; set
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

**If your granter is a SINGLE KEY**, none of the above applies — one command replaces the whole
ceremony, run on the box holding that key:

```sh
testscripts/foundation_sponsor_node.sh --node <addr>                      # grant only
testscripts/foundation_sponsor_node.sh --node <addr> --self-bond 10000qdn # grant + bond
```

It issues the identical `LIFE_MSGS` grant — the seven messages below are its own default — as a
`PeriodicAllowance` of `1000qdn` per 30 days, and with `--self-bond` it also sends the bond,
because no fee grant covers staked principal. The granter defaults to `foundation-nodes`
(`$QADENA_FOUNDATION_NODES`, or `--granter`).

`add_full_node.sh` prints this exact command at its funding gate, so the new node's operator can
paste it into the request rather than describing the address.

**Do not pass `--join-only`.** It narrows the grant to the four join-time messages, which is enough
to get the node running and silently stops SS re-sharing later; the omission surfaces months after
the join, far from anything naming a permission. Same for `--expiration`.

**On a test fleet holding every member key**, `testscripts/foundation_multisig_sponsor_node.sh
--node <addr> --granter nodeops --via <user@node>` performs the multisig ceremony above
unattended. That works only because one workstation holds all of `nodeops-m1..mN`, which is the
arrangement a real bucket exists to prevent — so it is a fleet shortcut, never an operator
procedure.

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

## Doing this on a test fleet instead

`testscripts/nth_node_bringup.sh` drives these same steps from a workstation, ssh-ing into both
machines.  It is test tooling and it is documented with the rest of it, in
[HOWTO-TEST-FLEET-BRINGUP.md](HOWTO-TEST-FLEET-BRINGUP.md#adding-one-node-to-an-existing-test-fleet).
Nothing on this page depends on it.
