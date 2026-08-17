# HOWTO: test enclave state-sync on two non-SGX machines

A handoff document. It assumes you have not seen this branch before.

**What you are testing.** A node that joins by CHAIN state-sync restores chain state at height H
without executing blocks 1..H, so it never produces the enclave-private tables that only block
execution writes — the AML rolling window, the credential uniqueness index and its superseded
aliases, and the sub-wallet/recovery maps. Nothing on chain encodes them. Without them the node
runs with an empty AML window, reaches different accept/reject verdicts than the rest of the
network on threshold-straddling transfers, and **forks silently** — the mirror store hashes agree
after seeding, so everything looks healthy.

The branch adds an attested, paged, compressed enclave-to-enclave transfer of those tables at a
single height, plus a halt for when it cannot happen. **None of it has ever run against two real
nodes.** It has 47 unit tests and a two-node BLOCK-SYNC validation (which exercises none of it).
That is the gap you are closing.

---

## 0. Verify this FIRST, before building anything

**State-sync and the private-state transfer are meant to work REGARDLESS OF SGX.** Nothing in the
design is SGX-specific: the transfer is height-pinned, attested, paged and compressed, and none of
those depend on real hardware. A debug build is a legitimate environment for this feature, not a
degraded stand-in — so a result you get here is a result about the feature, and **a failure here is
a defect to report, not a reason to stop.**

### How enclave identity works on a debug build

Attestation between two debug enclaves **works by design**, and it is worth understanding the
mechanism because the failure mode below hinges on it:

- `uniqueID` and `signerID` are not empty on a debug build — they are `go:embed`-ed placeholders
  from `cmd/qadenad_enclave/test_unique_id.txt` and `test_signer_id.txt` (currently `unique047` and
  `signer051`). The real-hardware measurements only *overwrite* them inside `if *realEnclave`.
- A debug report is the literal string `TRUST-ME:<uniqueID>:<signerID>:<hash>:<data>`, so it carries
  those placeholders.
- `buildscripts/build_enclave.sh` rewrites `enclaveIdentityList` in `genesis.json` with whatever ids
  the build produced — the placeholders on a debug build, the real measurements on SGX.
- So `getEnclaveIdentity("unique047", "signer051", …)` finds an active row and verification
  succeeds.

(The `SignerID: "*"` / `UniqueID: "*"` a debug build sends in its `init-enclave` registration —
now built in-process, see `cmd/qadenad/cmd/enclave_selfstart.go` — is a different thing from the
genesis identity. Do not be misled by it, as an earlier draft of this document was.)

### The check that actually matters: do the two machines agree on the placeholder?

This is the debug analogue of SGX's "measurement must match genesis", and it is the thing to verify
before investing in a bring-up.

`build_enclave.sh --update-test-unique-id` **increments** those files (`unique047` → `unique048`,
and bumps `version.txt`). So two machines that were built at different times, or from trees where
that flag was used, can carry **different placeholder ids** — and the joiner's enclave will then
present an id the chain has never registered. Every enclave-to-enclave call fails closed:
`sync-enclave`, `getSSPrivK`'s share fetch, and the private-state transfer alike.

```sh
# on BOTH machines -- these must be identical
cat cmd/qadenad_enclave/test_unique_id.txt cmd/qadenad_enclave/test_signer_id.txt

# and the chain must record that same pair
jq '.app_state.qadena.enclaveIdentityList' $QADENAHOME/config/genesis.json
```

If they differ, rebuild the joiner from the **same tree** as the primary (or copy the two files
across and rebuild) — do not edit genesis to match a stray binary.

If attestation still fails once those agree, *that* is a finding worth reporting: the feature is
meant to work without SGX, so a debug-only identity failure is a defect, not an environment limit.
Do not paper over it — capture the log line (`couldn't find an active enclave identity for uniqueID`
is the one to grep for) and report it.

---

## 1. Why non-SGX is the right place to test this

The feature is SGX-independent by design, so a non-SGX pair is a first-class environment for it —
and debug builds can prove things SGX **cannot**:

| | SGX | debug |
|---|---|---|
| `ExportPrivateState` | refused (`RealEnclave && !testSeal`) | **works** — you can dump and diff private state directly |
| `enclave update-ss-interval-key` | refused | **works** — `test_ss_key_rotation.sh` actually runs |
| rollback evidence | store hashes only | **wallet present → absent**, the direct proof |
| build | 3 reproducible docker builds, ~30 min, needs ego+docker | plain `go build`, minutes |
| identity must match genesis | **yes** — real MRENCLAVE | **yes** — the embedded placeholder (§0) |

The last row is NOT a difference in kind, only in what has to match. On SGX the joiner must be
installed from a package **built on the primary**, because the measurement is a hash of the binary
and `EnclaveIdentity` is keyed by it. On debug you may build on each machine separately — but only
from the SAME TREE, because the embedded placeholder ids must still match what genesis recorded
(§0). Building independently from trees where `--update-test-unique-id` was used gives you two
different ids and every enclave-to-enclave call fails closed.

The first row is the big testing win: **you can diff the two nodes' private state directly**, which
is impossible on SGX. Use it — see §5.

**What does NOT carry over from a debug result.** Sealing, and only sealing. `MustSeal` uses the
product key (CPU-bound) and `MustSealStable` a per-node secret, so the "unseal at source, re-seal at
destination" property of the transfer is exercised differently here. Everything else — the height
pinning, the cursor and paging, window pruning at export, the attestation flow, the halt-vs-fetch
decision, the atomicity markers — behaves identically. There is already a unit test asserting the
re-seal property across two different sealing secrets
(`TestPrivateStateTransferReSealsForTheDestination`), so the one thing debug cannot show is the one
thing already covered elsewhere.

---

## 2. Bring up the two nodes

There is a harness that encodes the traps: `testscripts/nth_node_bringup.sh`. Read its header
comment before doing anything by hand; every trap in it cost real time to find. Run
`--help` for the phase list. It was written against SGX nodes: its phase 1 reads measurements with
`ego uniqueid`, which does not exist on a debug build, so that check needs swapping for the
placeholder comparison in §0.

Broad shape:

```sh
# node A (primary): build, genesis, start
buildscripts/init.sh --advertise-ip-address <A>     # NO --build-sgx
scripts/start_qadena.sh
testscripts/regression.sh --with-setup              # get real state on the chain

# node B (joiner): build, then join
buildscripts/init.sh --advertise-ip-address <B>     # or install from a package
scripts/add_full_node.sh --pioneer pioneer2 \
    --advertise-ip-address <B> \
    --genesis-pioneer-first-ip-address <A>
```

**Traps that will cost you an hour each if you skip them:**

1. **Never `pkill -f <pattern>` over ssh** when the pattern appears in the command line you just
   sent — the remote shell running it matches and kills itself. The same flaw silently inflates
   `pgrep -cf` counts. Kill by PID; use a bracket class (`[r]egression`) when you must match.
2. **`add_full_node.sh` requires a real PTY.** Every prompt guards against EOF and exits rather
   than looping (hardening added after a FIFO-driven run spun at 100% CPU for 2.5 hours). Feeding
   it from a pipe dies at the first prompt. Use `script -qec`.
3. **Answer `n` to "start the node now?" and start it yourself.** The in-script start is launched
   several process layers under a PTY that exits moments later; observed to report "Running in
   background" and then produce *no output anywhere*. Started standalone it works first try.
4. **Fund the joiner's pioneer key BEFORE running the join.** The funding prompt polls 120×3s then
   gives up. Funding first turns a race into a lookup.
5. **Quiesce continuous regression on the primary first.** `enclave-rollback` and `enclave-crash`
   stop and restart the chain by design, so the primary's RPC vanishes for minutes and the joiner
   sees a wall of `connection refused` that looks like a network fault.
6. **The node scripts are zsh and `qadenad_alias` is a zsh alias** — `bash -lc` gives
   `command not found`. (`bash -lc` is the fix for a *different* problem: a non-login shell missing
   `/usr/local/go/bin` during builds. Don't confuse them.)
7. **`~` under `sudo` is `/root`.** Resolve paths as the login user, then pass absolute paths.

Confirm the pair is healthy before going further:

```sh
testscripts/test_peer_agreement.sh    # must COMPARE, not print "NOTHING COMPARED"
qadenad --home $QADENAHOME enclave height   # prepared == confirmed on both
```

`test_peer_agreement.sh` **exits 0 when it has no peers**, printing `NOTHING COMPARED` and saying
to treat that as "not tested". Never take its exit code alone as evidence.

---

## 3. Make the chain worth state-syncing to

State-sync only offers snapshots at multiples of `snapshot-interval` (2000, keeping 3), so the
chain needs a few thousand blocks. More importantly it needs **real AML window state**, or the test
proves nothing.

```sh
# lower the interval on the primary so you are not waiting for 2000 blocks
#   $QADENAHOME/config/app.toml:  snapshot-interval = "200"
testscripts/run_regression_continually.sh    # builds credentials, wallets, transfer history
```

Let it run until the primary has several thousand blocks and a non-trivial window. Verify:

```sh
qadenad --home $QADENAHOME enclave export-private-state | jq '.ScanTransferHistoryMap | length'
# must be > 0.  If it is 0 there is no AML window and the whole test is vacuous.
```

That field only exists on this branch — it was added precisely because its absence made the
2026-08-09 fork undiagnosable.

---

## 4. The actual test: state-sync the joiner

Wipe the joiner's chain **and** enclave data (keep the binaries), then re-join with state-sync on.
`add_full_node.sh` only configures state-sync when a **second** genesis-pioneer IP is supplied — on
a two-node network, pass the primary's IP **twice**:

```sh
scripts/add_full_node.sh --pioneer pioneer2 \
    --advertise-ip-address <B> \
    --genesis-pioneer-first-ip-address <A> \
    --genesis-pioneer-second-ip-address <A>
```

Then start the node yourself and watch for this specific sequence:

```sh
grep -aE "OfferSnapshot|rejecting chain snapshot|private state|imported private state|halt" \
    $QADENAHOME/logs/qadena-*.log
```

**What correct looks like:**

- `App.OfferSnapshot` accepts (or REJECTs and tries another height — that is also correct).
- The first `BeginBlock` after restore fetches private state from the peer, **before** any
  transaction of that block runs, and logs `imported private state at height H from <peer>`.
- `qadenad enclave height` afterwards shows `earliestHeight == H+1`. A state-synced node **cannot**
  roll back below its join height; that is expected, not a bug.
- `test_peer_agreement.sh` compares clean.

**What a real failure looks like:** the node halts with `this enclave has no committed height, but
the chain has already committed height N`. That is the safety net working — it refuses to run with
empty private tables rather than forking. Read the panic text; it names both causes and remedies.

Expect the first block after restore to take **minutes**. It is blocking and synchronous by
necessity — `BeginBlock` is the last point before the block's transactions read the AML window.
(The old `delayed_init_enclave.sh` stall watchdog existed to tolerate exactly this; it is gone,
and nothing kills a slow first block anymore.)

---

### 4.1 A green run that proves nothing looks exactly like one that proves everything

This has now happened three times during this work, by three different mechanisms. Read this section
before believing any positive result.

**The state must exist AT THE SNAPSHOT HEIGHT, not at the tip.** Observed on the ARM pair: a joiner
state-synced to snapshot 12000 and logged

```
imported private state at height 12000 from <peer>: 0 rows over 1 pages
```

No panic, no error, and the node then executed 12001+ normally, rebuilt every table itself, caught up
and agreed with its peer. Perfect-looking, and it tested nothing — the chain's wallets and protect
keys were created around 12965, while the newest retained snapshot was 12000.

The gap is structural, not bad luck: snapshots exist only at multiples of `snapshot-interval`, and
only `snapshot-keep-recent` of them survive, so the newest offered snapshot can be up to
`interval × keep-recent` behind the tip — **6000 blocks at the defaults**. A chain can look richly
stateful when you measure it and still offer only snapshots from before any of that existed.

So assert **both**, and read the height from the log rather than assuming which snapshot was picked
(the joiner chooses among those offered):

```sh
# the height the joiner actually accepted
grep -a "Snapshot accepted" $QADENAHOME/logs/qadena-*.log

# on the PRIMARY: was there anything to send at that height?
qadenad --home $QADENAHOME enclave export-private-state --height <accepted> \
  | jq '{scan: (.ScanTransferHistoryMap|length), hash: (.CredentialHashMap|length)}'

# on the JOINER: did the transfer actually move anything?
grep -a "imported private state at height" $QADENAHOME/logs/qadena-*.log
```

`0 rows` with an empty export is **not a pass** — it is "the scenario never happened". `0 rows` with
a non-empty export is a real bug.

The other two instances of this shape, for calibration: a `qadena_status` change was verified green
via a code path the change did not touch, and an unfixed build passed a state-sync run on a chain
whose `list-protect-key` was 0. In all three the check was green for a reason other than the one
under test.

### 4.2 Two things that will cost you an afternoon

**`comet reset-state` does NOT prepare a node for state-sync.** It leaves `application.db` behind and
the restore aborts with `multistore restore: import failed: found database at version N, must be 0`.
Remove `data/` wholesale.

**After a panic, qadenad is dead but the enclave and signer_enclave survive.** `is_qadena_running`
therefore still reports true, and `start_qadena.sh` answers "Qadena is already running" and does
nothing at all. Run `stop_qadena.sh --all` before restarting. Nothing in the output tells you this.

**Re-joining cannot reuse the pioneer name.** `add_full_node.sh` aborts with "The Pioneer pioneer2
already exists" because the registration from the first join is still on chain — and the guard runs
*after* it has wiped `data/`, `enclave_config/`, `enclave_data/` and `keyring-test`, so a failed
re-join leaves the node un-joined and keyless. Either use a fresh pioneer name and fund a new key, or
skip `add_full_node.sh` entirely for a re-join: wipe `data/` and `enclave_data/`, **keep**
`enclave_config/`, and restart. The params are already valid and the pioneer is already registered,
so re-registering is precisely the step you do not want.

---

## 5. The negative control — do not skip this

A green result here means nothing on its own. If the scenario never actually occurred, a passing
test and a broken feature are indistinguishable.

**Positive:** with the import working, put a **threshold-straddling** transfer through — several
sub-threshold sends from one wallet to one destination that only cross the AML threshold in
aggregate. Then assert:

- exactly **one** suspicious transaction reaches chain state (not zero, not two), and
- `test_peer_agreement.sh` compares clean at a height above it.

**Negative:** disable the import (easiest: point the joiner at no reachable peer for the fetch, or
patch `fetchEnclavePrivateState` to no-op), re-run the identical scenario, and assert the peers
**DO diverge**. If they do not diverge, your straddling transfer never exercised the window and the
positive result was empty.

On debug you have a sharper instrument than app-hash comparison — **diff the private state
directly**, which is impossible on SGX:

```sh
# on both nodes, at the same height
qadenad --home $QADENAHOME enclave export-private-state --height H > node.json
jq -S '.ScanTransferHistoryMap' node.json    # compare across nodes
```

A state-synced node's window is pruned to the rolling window at H while a from-genesis node's may
still hold dead entries for wallets that have not transacted since (pruning is lazy). So compare
the **live** entries, not the raw table — that asymmetry is by design and is why the code has a
canonical `privateStateDigest` that prunes before hashing.

---

## 6. What to write down

Whatever happens, record:

- **The §0 check** — did both machines carry the same embedded placeholder ids, and did genesis
  record them? Everything enclave-to-enclave is downstream of that.
- Whether `OfferSnapshot` accepted or rejected, and at what height.
- Whether the import ran, how many rows/pages, and how long the first block took.
- **The negative control result.** Without it, the positive result is not evidence.

If something fails, prefer the panic text over inference — the halts on this branch were written to
name their own remedy. And if you find yourself explaining a failure without evidence, say "I don't
know yet" instead; two confident explanations were offered during this branch's development and
both were disproven by the next command.

---

## 7. Background you may want

- `docs/HOWTO-CHAIN-RECOVERY.md` §2.2 — the join-path model: what key material a joining node can
  and cannot obtain, and why block-sync joiners are correct while state-sync ones need the transfer.
- `cmd/qadenad_enclave/enclave_private_state_sync.go` — the transfer itself. The header comment
  explains why it is a single height rather than a history, why it cannot be a byte copy, and how
  page size interacts with the 4 MiB gRPC limit on every hop.
- `x/qadena/keeper/enclave_grpc_client.go` — `classifyEnclaveHeight` and the case table above
  `reconcileEnclaveHeight`. Case F is the state-sync case.
- `testscripts/nth_node_bringup.sh` — the harness, and its header comment listing the traps.
