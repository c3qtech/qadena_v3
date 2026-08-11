# Testing backlog: enclave rollback / two-phase commit

Deferred from the `enclave-rollback` branch, deliberately.  What shipped with the branch: ten Go
unit tests in `cmd/qadenad_enclave/enclave_height_test.go` (the state machine, refusals, outbox
rollback, secrets survival), and one manual single-node end-to-end on the Mac (2026-08-11:
genesis start -> watermarks tracking -> one-block rollback 0.7s -> 74-block one-shot 1.8s ->
restart reconciled case A with zero store mismatches).

**The consequence of what is missing must be stated plainly: this work has no automated fork
detection.**  `test_peer_agreement.sh` is the only detector and it exits 0 with "NOTHING
COMPARED" on a single node, so single-node CI reports success while testing nothing.  A rollback
bug *is* a fork bug.  The P0 items are not optional before this is relied on in anger.

Existing gaps this backlog also closes: keeper tests still dodge the enclave via
`WithIsCheckTx(true)` (`x/qadena/keeper/testctx_test.go`); nothing automated asserts
enclave/chain height agreement; the reconciliation branches A-E have no fake-client unit tests
(the fake is straightforward -- `types.QadenaEnclaveClient` is an interface; embed it nil and
override the three height RPCs).

## P0 -- before this is trusted

1. **`testscripts/test_enclave_rollback.sh`**, added to `testscripts/regression.sh`.  Record
   height H and `GetStoreHash`; run N blocks of real transfers and credential issuance; stop
   chain and enclave; `qadenad rollback --height H`; restart; assert store hashes match the
   recorded ones, `prepared == confirmed == H`, and the chain progresses past H with identical
   results.  (The manual Mac run proved the shape; this automates it with real transactions.)
2. **Two-node fixture.**  The only real fork detection.  Until it exists, make the rollback
   suite FAIL rather than skip when it finds no peers, so the gap is loud.
3. **Fault injection reproducing the 2026-08-09 incident.**  `kill -9` the enclave mid-block,
   and `kill -STOP` to simulate the OOM stall.  Assert the node halts via `haltOnEnclaveFailure`
   rather than committing; restart; assert reconciliation classifies correctly (case D halts and
   prints the remedy); run the remedy; assert convergence.  The only test that exercises the
   path this whole branch exists for.

## P1 -- correctness depth

4. Rollback **across an SS key rotation boundary** (`keyUpdateFrequency = 555`) -- the exact
   incident shape.  Assert the secrets DB is byte-identical afterwards and no key is lost.
5. Rollback across a **credential create and remove** -- assert the uniqueness slot in
   `EnclaveCredentialHash` is released, so the identity is not bricked.
6. Rollback across an **AML scan window** (`EnclaveScanTransferHistory`) -- assert the rolling
   window unwinds with the transfer that created it.
7. **Deep rollback** (thousands of blocks): timing, and `LoadVersionForOverwriting`'s fast-node
   index rebuild.  Confirms the 30-minute RPC timeout is adequate.  (Mac data point: 74 blocks
   in 1.8s including app construction; depth scaling unmeasured.)
8. **Boundary cases**: rollback exactly at `earliestHeight`; one below it (must refuse by
   name); at `prepared` (idempotent no-op); above `prepared` (must refuse).  Unit-covered;
   repeat against a real chain with pruning enabled, where `earliestHeight` actually moves.
9. **Concurrency**: rollback RPC issued while a block is in flight must be refused, not
   serviced.  Today this is guaranteed only by caller discipline (CLI requires qadenad stopped;
   reconciliation runs pre-transaction) -- add an in-flight-block guard and test it.

## P2 -- crash matrix

10. Inject a crash at each of the four windows in the two-phase table, especially **between
    `BaseApp.Commit` and `ConfirmHeight`** -- the formerly silent, permanent divergence.
    Assert case B confirms on restart.
11. Crash during `saveEnclaveParams`; assert the temp-file + rename leaves a readable file and
    `SealedTableSharedSecret` survives.
12. Crash *during* `RollbackToVersion`; assert restart is recoverable, not a half-rolled tree.
13. Enclave restart between a store write and the next `EndBlock` -- the loss the versioned
    outbox fixes; assert the outbox entry survives the restart and drains at re-execution.

## P3 -- soak and property

14. **Soak with periodic rollbacks** on two nodes, asserting peer agreement throughout.
15. **Property test**: random sequences of commit/confirm/rollback converge to the same state
    as the equivalent linear history.
16. **Memory**: `GetStoreHash` plus deep rollback under the 1 GB heap with heap sampling -- the
    original OOM was `GetStoreHash` colliding with a key rotation.
17. **Reproducible SGX build + `test_enclave_upgrade.sh`** across the new store layout
    (enclave_secrets, qmeta/, outbox).  Budget ~24 min per build.  The upgrade scripts carry
    `enclave_data` in place; verify `enclave_secrets` crosses the E1 upgrade correctly.

## P4 -- regression cover for the latent-bug fixes

18. `saveEnclaveParams` atomicity (see 11).
19. `LoadLatestVersion` failure is fatal -- assert the enclave refuses to start rather than
    serving an empty tree.
20. SS keygen no longer races the tx cache: generate a key concurrently with a failing
    transaction, assert the key survives.  (The unit test covers the sequential shape; this one
    needs real concurrency.)
21. `GetStoreHash` no longer mutates -- unit-covered (`TestGetStoreHashDoesNotMutate`); repeat
    under concurrent tx execution.
