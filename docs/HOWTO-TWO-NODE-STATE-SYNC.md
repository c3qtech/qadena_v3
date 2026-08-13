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

That matters for how you read the next question.

**Does `verifyRemoteReport` succeed between two DEBUG (non-SGX) enclaves?**

Everything here depends on it: the private-state transfer, `sync-enclave`, and `getSSPrivK`'s
cross-node share fetch all refuse a peer whose report does not verify. And there is a specific
reason to doubt it on a debug build:

- `uniqueID` and `signerID` are package vars in `cmd/qadenad_enclave/enclave.go` assigned **only**
  inside `if *realEnclave`. On a debug build they stay `""`.
- A debug report is the literal string `TRUST-ME:<uniqueID>:<signerID>:<hash>:<data>`
  (`getRemoteReport`), so it carries **empty** ids.
- `verifyRemoteReportInternal` ends at `getEnclaveIdentity(localUniqueID, signerID, false)`, which
  looks up `EnclaveIdentityKey(uniqueID)` and requires `ActiveStatus`.
- But `init_enclave.sh` registers the identity as `SIGNER_ID="*"` / `UNIQUE_ID="*"` on a debug
  build, and **there is no wildcard matching anywhere in the enclave code** — `"*"` is stored and
  compared as a literal.

So a lookup of `""` against a row keyed `"*"` plausibly misses, and every enclave-to-enclave call
fails closed. It may well be that two-node debug has simply never been exercised.

Check it before investing in a full bring-up:

```sh
# on node A, with both nodes up and peered
qadenad --home $QADENAHOME query qadena list-enclave-identity -o json | jq '.enclaveIdentity[]'
# what did the chain actually record -- "*", "", or something else?
```

Then force a real cross-node attested call and watch node B's log:

```sh
# any of these exercise verifyRemoteReport across nodes
qadenad --home $QADENAHOME query qadena enclave-secret-share ...   # getSSPrivK path
grep -a "remote report\|couldn't find an active enclave identity" $QADENAHOME/logs/qadena-*.log
```

**If attestation does NOT work between debug enclaves, that is your first finding — report it as a
bug, do not work around it.** Since the feature is meant to work regardless of SGX, an identity
lookup that cannot match on a debug build is a defect in the debug identity path, and it blocks
every enclave-to-enclave call (`sync-enclave`, `getSSPrivK`'s share fetch, and the private-state
transfer alike). Two-node debug may simply never have been exercised.

Do not patch it silently to get the test moving: whether `""` should match `"*"`, or the debug
build should report the wildcard as its own id, or the chain should register `""` — that is a
design decision with security consequences, and it belongs to the owner. Write up what you
observed, propose the options, and let them choose.

Record the answer at the top of your notes either way. It is the single highest-value fact here,
and it is worth finding on day one rather than after a full bring-up.

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
| measurement must match genesis | **yes**, strictly | no (wildcards) — so no package-transfer dance |

The last row is the big operational saving: on SGX the joiner must be installed from a package
**built on the primary**, because `EnclaveIdentity` is keyed by measurement. On debug you can build
on each machine independently.

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

There is a harness that encodes the traps: `testscripts/two_node_bringup.sh`. Read its header
comment before doing anything by hand; every trap in it cost real time to find. Run
`--help` for the phase list. It was written against SGX nodes, so on debug expect phase 1's
measurement check to need adjusting (measurements are empty/wildcard).

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
`delayed_init_enclave.sh`'s stall watchdog tolerates ~10 minutes for exactly this reason.

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

- **The §0 answer** — does debug-to-debug attestation work? Everything else is downstream of it.
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
- `testscripts/two_node_bringup.sh` — the harness, and its header comment listing the traps.
