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

## Open questions -- pioneer addressing (investigation, not tests)

Raised 2026-08-14, while tracing how an enclave finds its secret-share owners. Recorded as
questions because they are **unverified**; the leads below are starting points from code read in
passing, not answers, and should be confirmed before anything is built on them.

22. **Are pioneer/validator IP addresses written to the chain, tied to the pioneer name?**
    Lead: the enclave resolves owners with `s.getPioneerIPAddress(owner)`
    (`cmd/qadenad_enclave/enclave.go:626`) and builds `tcp://<ip>:26657` from it, so an address
    clearly reaches the enclave from somewhere. The `IntervalPublicKeyID` push is the suspected
    carrier. Confirm what is actually stored on chain, in which message and field, and whether the
    key is the pioneer name/ID or something else.

23. **Can multiple pioneers share one IP address?** Working guess when raised: no. Worth settling
    explicitly -- it decides whether co-locating two pioneers on one host is a supported test
    topology or an accident waiting to happen, which matters directly for a single-host two-node
    fixture (item 2).

24. **Does anything look a pioneer up BY IP, or is it always by pioneer name?** Lead pointing to
    "always by name": the one resolution path seen so far goes name -> IP, never the reverse. If
    that holds everywhere, an IP change is a data update rather than an identity change, which is
    the good case. Verify there is no reverse lookup, no IP-keyed map, and no IP used as an
    identity or authorization check anywhere.

25. **Is there an update procedure when an IP address or DNS name changes?** If a pioneer moves
    host or its DNS name changes, what re-registers it, who may sign that update, and how do other
    enclaves learn about it? If no procedure exists, note the consequence: peers keep dialling a
    stale address, every call fails, and `getSSPrivK` degrades exactly as an unreachable peer does
    (`cmd/qadenad_enclave/enclave.go:663` -> `continue` -> `return ""` at `:707`) -- a silent,
    latent divergence rather than an error. That failure mode is why these questions were raised.

26. **Reachability must be proven when a node joins -- probably at the point it asks to become a
    validator.** Today nothing verifies that a newly added node can actually be reached by its
    peers. Working hypothesis when raised: full nodes' IP addresses are *not* recorded on chain,
    so the meaningful checkpoint is the promotion to validator/pioneer -- the moment an address
    first gets published and other enclaves start dialling it. Verify that hypothesis first (it is
    the same question as item 22), then decide where the gate belongs.

    Why this is not merely hygiene: an unreachable pioneer is not an error anyone sees. Its peers
    take the `continue` at `cmd/qadenad_enclave/enclave.go:663`, fall through to `return ""` at
    `:707`, and carry on with a missing key -- so the cost of admitting an unreachable node is
    paid later, by *other* nodes, as a silent divergence. A join-time probe (dial the published
    address, require an attested round trip to succeed before the registration is accepted) turns
    that into a loud, local, immediate failure for the operator who can actually fix it.

    Note the ordering trap: at `getThreshold` = 1 (0-3 owners, `enclave.go:484`) there is no
    redundancy, so the first unreachable owner is already fatal to reconstruction. Small networks
    -- including the two-node test rig -- need this gate more than large ones, not less.

27. **If rollback requires the enclave to be running, ship a script that does both -- with an
    approval step that states exactly what it will do.** The reconciliation advice printed today is
    a bare `qadenad rollback --height <prepared>`, which describes only the chain half. The enclave
    half (`RollbackToHeight`, `cmd/qadenad_enclave/enclave_height.go`) is an RPC, so it needs a
    live enclave to receive it.

    First verify the premise: does the enclave have to be up for its rollback to take effect, and
    is the chain-side `rollback` command able to drive it? If yes, the current advice is a trap --
    an operator who has stopped everything (the natural instinct after a halt) rolls back the chain
    while the enclave keeps its state, converting a diagnosed halt into the exact chain/enclave
    height mismatch the halt existed to prevent.

    What the script should do: start the enclave if needed, show the operator the current chain
    height, enclave `prepared`/`confirmed` heights, and the target -- then require an explicit
    confirmation before touching anything, print what changed afterwards, and re-run reconciliation
    to prove convergence. Rollback destroys state that cannot be recovered except by re-syncing, so
    a dry-run/`--yes` split is the minimum; no silent path.

    Related: item 3 exercises the case-D remedy in a test. This item is about the operator-facing
    tool that remedy tells people to run.

28. **Audit the failure modes of every outward enclave call -- and decide per call whether a halt
    is actually warranted.** The enclave talks outward to other nodes' enclaves (secret shares,
    recover-key shares, identity validation, sync-enclave, private-state transfer) and potentially
    to other chains. Each of those calls needs its failure mode named deliberately rather than
    inherited from whatever `continue` happens to be in the loop today.

    The key distinction, and the reason "halt on peer failure" is too blunt a rule: **some of these
    operations only need a SUBSET of peers, not all of them.** Key recovery is the clear case --
    Shamir needs `threshold` shares, not every owner, so a node that reaches enough owners is fully
    correct even though several peers were unreachable. Treating any unreachable peer as fatal
    would halt a chain that is working exactly as designed.

    So the audit should ask, per call:
    - How many peers must answer for the result to be *correct*? (`getThreshold`,
      `cmd/qadenad_enclave/enclave.go:484` -- note it returns 1 for 0-3 owners, so small networks
      have no redundancy at all.)
    - Is there a real fallback -- retry, another owner, a later block -- or is the first failure
      the final answer?
    - **Does the result feed deterministic execution?** If yes, an under-threshold outcome must not
      silently become a state transition; that is the `return ""` problem at `enclave.go:707`. If
      no, failing softly is correct.
    - If it does feed execution, is a halt genuinely required -- or can this node simply run slower
      than its peers, finish the work, and catch up? A node that lags and converges is far cheaper
      than one that stops. Halt should be reserved for the cases where continuing would commit a
      *different* state, not merely a later one.

    The output should be a table: call -> peers required -> fallback -> consensus-relevant? ->
    chosen failure mode (halt / retry / degrade-and-catch-up). Today that table does not exist and
    the behaviour is accidental.

29. **`sync-enclave`'s reply grows with chain age and is not paged.** `QueryEnclaveSyncEnclave`
    (`cmd/qadenad_enclave/enclave.go:2201`) packs `tmpEnclaveParams.SSIntervalOwners =
    s.getAllOwners()`, and `getAllOwners` (`:4275`) walks every key under
    `EnclaveSSIntervalOwnersKeyPrefix`, doing a separate `getOwners()` lookup per key. A new
    interval key is minted every `keyUpdateFrequency = 555` blocks (`:1880`), so the entry count is
    about `chainHeight / 555`: ~166 at today's 92k, ~1,800 at 1M, ~18,000 at 10M. It is assembled
    into a SINGLE unpaged message, so it faces both a latency ceiling and the 4 MiB gRPC message
    ceiling.

    The failure mode is misleading because of where the deadline sits. The joining enclave calls out
    with `context.Background()` (`:2787`) -- no deadline of its own -- so the binding deadline is the
    SEED's, which after the height-34025 retiering is `c.DebugTimeout` (2s). On an older chain,
    `add_full_node.sh` will start failing at the `sync-enclave` step against a seed that is perfectly
    healthy, and nothing in either log will say "too much data".

    **PAGED as of 2026-08-14** -- `EncryptableSyncEnclavePage` (cursor + `maxBytes`, 1 MiB target /
    3 MiB cap), with `nextCursor`/`done` inside the encrypted, attested payload so the handshake
    cannot be truncated by flipping a cleartext flag, and a legacy unpaged reply when `maxBytes ==
    0` so a new joiner still works against an old seed. Unit-tested with 1-byte budgets, because at
    166 entries against a 1 MiB budget the multi-page path would otherwise first execute years from
    now on a chain old enough to need it.

    STILL OPEN: the sizing was never measured. Time `getAllOwners()` and a full paged handshake at
    interval counts of 166 / 1,800 / 18,000 and confirm where 2s and 4 MiB are actually crossed. Two
    known gaps: the `sort.Strings` in `getOwnersPage` is not covered by the tests (both memdb and
    leveldb already iterate in key order, so removing it does not fail anything), and the paged path
    has never run against a real enclave over gRPC -- only in-process.

    Related: item 28 (per-call failure-mode audit) and the unprofiled 60s peer timeout in
    `x/qadena/keeper/enclave_call_context.go`, which has the same "round number, never measured"
    problem.

## Raised by the first two-node state-sync run (2026-08-14, ARM/non-SGX)

Context: the private-state transfer executed end to end for the first time -- a joiner
state-synced at height 2800, imported 79 rows in the first `BeginBlock`, reached
`earliestHeight == H+1`, and agrees with the primary on every app hash. Getting there
took three fixes (iavl v1.2.8, the store-push reorder in `b60c6316`, and the peer's
`31b86eeb`). What follows is what that run left open.

30. **DSVS `AuthorizedSignatory` never seeds on a state-synced joiner, and nothing halts.**
    Measured: the joiner holds 0 rows against the primary's 11, having failed 252 times --
    once per block, indefinitely -- with

        ERR DSVS: EnclaveSynchronizeStores error returned by ValidateAuthorizedSignatory
            ... codespace qadena code 1141: Unauthorized
        ERR [enclave - E]: bindData does not contain the current or previous ssIntervalPubKID

    NOTHING IS MISSING. The joiner's CHAIN store holds all 11 rows (`query dsvs
    list-authorized-signatory` reports Count: 11 on both nodes); the interval public key
    ids are chain state and compare identical between the two enclaves; and
    `resolveSSIntervalPubKIDForBind`'s own comment states that "getSSPrivK is keyed by
    pubKID and interval private keys are never discarded, so the old key is still usable
    for decryption". The key is available. The row is available.

    The refusal is POSITIONAL. `resolveSSIntervalPubKIDForBind` accepts a bind naming the
    CURRENT interval, or the PREVIOUS one as a rotation grace window, and rejects anything
    older -- whether or not the key can be had. That is correct for the LIVE path, where a
    bind naming a long-dead interval is suspicious. It is wrong for SEEDING, where rows are
    old by construction: these were written during setup around height 300-500, and with
    `keyUpdateFrequency = 555` against a chain at ~3000 they are four or five rotations
    behind. Every row written before the last two rotations is refused on a node that is
    legitimately replaying chain history.

    THE MECHANISM FOR FIXING IT IS ALREADY THERE. `decryptSignatory(in, trusted bool)`
    takes the unrestricted path when `trusted` -- `FindB64AddressAndBech32AddressByNodeIDAndType`,
    no window. `ValidateAuthorizedSignatory` calls `decryptAuthorizedSignatory(in.Signatory,
    false)`. Seeding replays rows that are already on chain and consensus-validated, which
    is what `trusted` is for. Worth checking whether every other seeding-path decrypt makes
    the same choice.

    SEPARATELY: the DSVS path LOGS AND CONTINUES where the qadena path halts (`aa9cdbe8`).
    The node runs permanently short of rows while every hash anyone checks agrees, which is
    the silent divergence this branch exists to prevent, one module over.

31. **`CredentialPCXYMap` is 72 on the joiner against 360 on the primary.** Same run, same
    settled height (3000, both nodes at 3046). Plausibly the same expired-interval
    mechanism as item 30, but that is a guess -- nothing has been traced. Worth settling
    before assuming the transfer covers every table that matters.

32. **The seeding halt's diagnosis is misleading.** Its text attributes rejected rows to a
    historical SS interval key needing reconstruction "from its owners over the network"
    and tells the operator to check peer reachability and restart. For `ProtectKey` that
    was wrong on both counts: the cause was seeding ORDER (`b60c6316`), the peer was
    reachable -- `SyncEnclave SUCCEEDED` against it minutes earlier -- and restarting
    re-ran the identical fixed order and failed identically. The same text happens to
    describe item 30 correctly. Rewrite it to name what was actually observed, or to
    distinguish the two causes; a halt that names the wrong remedy costs more than one
    that names none.

33. **Neither paging path has been exercised over gRPC with more than one page.** The
    joins ran `sync-enclave` over real gRPC (which item 29 wanted), but at ~8 interval key
    ids they fit one page even with `syncEnclavePageTargetBytes` forced to 256 -- and the
    page count only logs at `LoggerDebug`, while `add_full_node.sh`'s start-from-scratch
    branch rewrites `config.toml` and reverts `log_level` before the enclave starts. The
    private-state transfer reported `79 rows over 1 pages` for the same reason. To get
    positive evidence: raise the log line to info, or make the page counts observable
    somewhere that survives a join.

34. **`add_full_node.sh` silently degrades to block-sync below `TRUSTHEIGHT > 1500`.** A
    join given both genesis-pioneer IPs at height 1481 printed "Trust height is too low,
    we won't use state sync", configured nothing, and completed successfully. The node
    joined, peered, synced and passed peer agreement -- by block-sync. Nothing in the
    join's outcome distinguishes that from a state-sync join; it is only visible by
    reading `config.toml` afterwards. Either fail the join when state-sync was explicitly
    requested and cannot be provided, or say so loudly at the end.

35. **The transfer's table list was never audited against the full enclave-private surface,
    and the one omission we tested forked a node.** Three categories exist and only two are
    covered:

        TRANSFERRED (privateStateTables, 5)   ScanTransferHistory, CredentialHash,
                                              CredentialHashesByCredentialID,
                                              ProtectSubWalletIDByOriginalWalletID,
                                              RecoverOriginalWalletIDByNewWalletID
        CHAIN-MIRRORED (GetStoreHash, 9)      Wallet, Credential, JarRegulator, PublicKey,
                                              IntervalPublicKeyID, ProtectKey, RecoverKey,
                                              EnclaveIdentity, AuthorizedSignatory
        NEITHER                               CredentialPCXY, PioneerJars

    Measured on the 2026-08-14 joiner at a settled height: all five transferred tables
    byte-identical; eight of nine mirrored stores identical; `AuthorizedSignatory` 0 against
    11 (item 30, and it forked the node); `CredentialPCXY` 72 against 360; `PioneerJars` 0
    against 1.

    The third category has NO MECHANISM to reach a state-synced node. It is not failing --
    nothing is even attempted. Those rows are built by executing blocks, which is precisely
    what state-sync skips. `EnclaveCredentialPCXYKeyPrefix` has four read/write sites in
    the enclave and appears nowhere in `privateStateTables` or `GetStoreHash`'s key list.

    THE WORK: enumerate every `Enclave*KeyPrefix`, classify each as transferred,
    chain-mirrored, legitimately node-local, or MISSING, and justify each classification in
    the table's own comment. A table whose absence changes a validation verdict is a fork,
    and `AuthorizedSignatory` demonstrated that is not hypothetical -- a table nobody had
    audited took a node out of consensus 250 blocks after it joined, with nothing on the
    node reporting a problem. Also settle the node-local set by evidence rather than
    assumption: SSIntervalShares, SSIntervalPrivK, PrivateEnclaveParams, PrivKCache and
    PreparedHeight are currently believed per-node because their differences look
    plausible, which is the same standard that let AuthorizedSignatory through.

36. **A state-synced joiner forked, and only an external test noticed.** Full chain, every
    step evidenced: DSVS seeding refused 11 AuthorizedSignatory rows (item 30) -> the
    enclave held none -> a transaction requiring signer authorization arrived ->
    `ValidateAuthorizedSigner` returned code 1137 "Unauthorized signer" ONCE, seven log
    lines before the failure -> the same transaction carries `code: 0` in the primary's
    `block_results` -> divergent app hash -> `CONSENSUS FAILURE!!! Expected 7CBD399E...,
    got EA3A099...` at height 3053, 252 blocks after joining at 2800.

    The node then sat at 3052 reporting `catching_up=false` and answering RPC normally.
    Nothing on it complained. It was `test_peer_agreement.sh`, running inside the
    regression loop from the OTHER node, that caught it -- and the failing suite's log
    survived only because failed logs are now preserved (`1d9fd033`); the next run would
    have overwritten it.

    Two things to take from this. A joiner cannot detect this class of divergence about
    itself, so peer agreement has to run from outside and has to keep running -- a single
    pass proves the peers agreed at that height and nothing more. And the halt that
    protects the qadena-side push (`aa9cdbe8`) has no counterpart on the DSVS side, which
    is exactly why this one got as far as consensus.
