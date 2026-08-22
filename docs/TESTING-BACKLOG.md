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
        NEITHER                               PioneerJars (CredentialPCXY: see correction)

    Measured on the 2026-08-14 joiner at a settled height: all five transferred tables
    byte-identical; eight of nine mirrored stores identical; `AuthorizedSignatory` 0 against
    11 (item 30, and it forked the node); `CredentialPCXY` 72 against 360; `PioneerJars` 0
    against 1.

    CORRECTION, recorded rather than quietly edited away: this item first claimed BOTH had
    no mechanism. That is true of PioneerJar and NOT true of CredentialPCXY.
    `SetCredential` calls `setCredentialByPCXY` when `WalletID == ""`, and the mirror push
    goes through `SetCredential` -- so the index IS derived during seeding. The 72-vs-360
    count gap is most likely the lazy-pruning asymmetry the HOWTO already documents for the
    AML window ("a from-genesis node's may still hold dead entries... compare the live
    entries, not the raw table"): the chain holds 100 credentials, not 360. Treat
    CredentialPCXY as UNSETTLED, not as a known gap, until someone compares live entries.

    PioneerJar is the real one. It is chain state -- `PioneerJarKeyPrefix`,
    `GetAllPioneerJar`, and `EnclaveClientSetPioneerJar` all exist, and the record is
    present in the joiner's own chain store -- but there is no `case
    types.PioneerJarKeyPrefix` in `enclaveSynchronizeStores` and the prefix is absent from
    `GetStoreHash`'s key list. Every piece needed is already written; the store was simply
    never added to the mirror set. The fix has the same three-line shape as every other
    case in that switch, and needs no peer, because the data is already local.

    NEITHER IS LEGITIMATELY NODE-LOCAL, which was checked rather than assumed. PioneerJar
    is shared chain state: `query qadena list-pioneer-jar` returns the SAME record
    (pioneerID pioneer1) on both nodes, and `SetPioneerJar` forwards it to the enclave via
    `EnclaveClientSetPioneerJar` -- so the joiner's chain holds the row, the enclave has a
    setter for it, and no path connects the two on a node that did not execute the
    originating message. That is the AuthorizedSignatory shape exactly, minus the attempt:
    that one tries and is refused, this one is never tried.

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

37. **Building on a machine with a running node CRASHES the node, and the build reports
    success.** Observed 2026-08-14 21:18: the chain segfaulted (`run.sh: Process qadenad
    ... exited with RC 139`) twice, ~9,639 blocks in, with no Go stack trace and no core
    dump.

    The chain, in order:

        build.sh:130 calls install.sh --chain -- BUILDING IMPLIES INSTALLING
        install.sh copies with plain `cp` into $qadenabin
        the running EXECUTABLES are protected by ETXTBSY, so those copies fail:
            cp: cannot create regular file '.../qadenad': Text file busy
            cp: cannot create regular file '.../qadenad_enclave': Text file busy
            cp: cannot create regular file '.../signer_enclave': Text file busy
        libwasmvm*.so has NO such protection and was overwritten IN PLACE at 21:18
        the node had it mmap'd; the kernel pages it in lazily; the bytes changed
        underneath a live process -> SIGSEGV
        run.sh respawned into the same corrupted mapping -> a second RC 139

    Timestamps at the moment of the crash, captured before they were overwritten:
    libwasmvm*.so and the versioned copies at 21:18-21:19, while qadenad,
    qadenad_enclave and signer_enclave stayed at 18:23 -- the ETXTBSY split is the whole
    story in one listing.

    NO GO STACK TRACE is diagnostic rather than unhelpful: the fault is in mapped C code,
    not Go, which is what sends you looking at cgo and libwasmvm instead of the chain.

    AND THE BUILD EXITED 0.  The three cp failures are printed and never checked, so
    build.sh announced success at the moment it crashed the running chain, and the only
    evidence was three lines in a log nobody reads on a green build.

    THE FIX: copy to a temporary name and `mv` over the target.  mv is an atomic rename,
    so a process still mapping the old inode keeps a coherent library and only new
    processes see the new one.  Failing that, install.sh should refuse when
    is_qadena_running, or build.sh should not install at all -- but the rename is the one
    that makes the operation safe rather than merely forbidden.

    Also check the cp exit status while you are in there.  A build that cannot install
    what it built has not succeeded.

38. **Nothing here has been tried at a million wallets and credentials, and several
    things are O(state) per block.** The two-node testnet runs ~100 wallets and ~100
    credentials. Every number below is fine at that size and none of them have a
    ceiling in the code.

    What is already known to grow without bound:

        export-private-state    ONE JSON document for the whole enclave.  Passed gRPC's
                                4 MiB default receive cap at ~10k blocks and 100 wallets
                                (8,328,613 bytes).  --digest-only and --section exist
                                now; the full dump does not scale and is not meant to.
        GetStoreHash            "scans the whole tree on most blocks" (enclave.go:227),
                                iterating nine prefixes with no cache -- per block.
        enclaveSynchronizeStores  seeds a fresh enclave by pushing EVERY row of every
                                mirrored store, one-shot at first BeginBlock.  At a
                                million wallets this is the join, and it holds a block.
        private-state transfer  paged, but the page size is tuned against 269 rows.
        assertStoresAreReadable one iterator seek per store -- O(1), fine.

    The questions worth answering before anyone claims a size:

    - What is the largest chain a joiner can state-sync in a bounded time?  Seeding and
      the private-state import both run inside ONE BeginBlock, and a block that takes
      minutes is a liveness failure even though nothing is wrong.
    - Does GetStoreHash's per-block full scan become the block time?  It is the obvious
      first thing to cache or make incremental, and it is on the consensus path.
    - Where does enclave memory actually run out?  The EPC budget is tens to a couple of
      hundred MB (enclave_private_state_sync.go), the import was deliberately paged to
      bound live memory to one page -- and then the EXPORT builds everything at once.
      The digest path fixes that for diagnostics; the getAll* helpers still materialize
      whole tables into slices and maps.
    - Do the AML scan-history windows grow per wallet without bound, and is the pruning
      the transfer relies on actually pruning?

    THIS IS A SIZING EXERCISE, NOT A BUG REPORT.  The right output is a table of
    measured block time, join time and peak enclave RSS against 1e3 / 1e4 / 1e5 / 1e6
    wallets, and the first structure that falls over.  Guessing which one it will be is
    less useful than running it -- though GetStoreHash's per-block full scan is the
    standing favourite.


39. **State-sync's rebuild indexes only the IDP credentials that are still UNCLAIMED, so
    a joiner's CredentialPCXY index is permanently short by every credential claimed
    before it joined.** Found 2026-08-14 with the new `export-private-state
    --digest-only` / `--section`, which is the only reason it was visible at all.

    THE INVARIANT, which M1 satisfies exactly and M2 does not:

        |CredentialPCXY|  ==  |credentials with a findCredentialPedersenCommit|

        M1   1608 == 1608     complete
        M2    636 != 1608     short by 972

    An IDP-issued credential is exactly one that HAS a findCredentialPedersenCommit; the
    user credential minted during a claim is created with that field nil
    (enclave.go:3683, and update does the same), so it can never be indexed -- the guard
    at enclave.go:5129 returns early on a nil commitment.  At height 13000 that splits
    2832 credential rows into 1608 IDP-issued and 1224 user-owned, and M1's index is
    1608 rows.  One per IDP credential, nothing stale, nothing missing.

    THE MECHANISM.  SetCredential is doing double duty as the live-issue path AND the
    rebuild path, and the two need different tests:

        enclave.go:4259    if in.WalletID == "" { s.setCredentialByPCXY(in) }

    On the live path that gate is right and always true -- a credential is ownerless at
    the moment an IDP issues it.  On the REBUILD path it is wrong, because
    enclaveSynchronizeStores replays CURRENT state: a credential claimed before the join
    arrives reading walletID "CLAIMED", the gate is false, and it is silently skipped.
    The mirror pushes every row and indexes a subset.

    CONFIRMED BY PREDICTION.  If that is the mechanism, the deficit must equal the number
    of IDP credentials already CLAIMED at the seeding height.  M1 keeps history to height
    1, so it can be read directly at M2's seeding height 9800:

        idp_credentials 1272   =   ownerless 300  +  CLAIMED 972
        M2's measured deficit at 13000:                        972

    Predicted 972, measured 972.

    AND IT IS PERMANENT.  Nothing re-indexes an already-claimed credential, so the hole
    never closes by continued operation.  M2 indexed 300 at seeding, has added 336 live
    since, and is still exactly 972 short.  The node carries it for life.

    WHAT BREAKS.  Both consumers of the index diverge between the two nodes, and both are
    consensus-visible because CometBFT's deterministicExecTxResult (types/results.go)
    commits Code, Data, GasWanted and GasUsed to LastResultsHash:

      read side   claim (enclave.go:3536) and update (enclave_update_credential.go:445)
                  do  if !found -> ErrCredentialNotExists ; if WalletID != "" ->
                  ErrCredentialClaimed.  Same transaction, two different codes.

      write side  credentialByPCXYExists (enclave.go:4252) returns BEFORE storing, so a
                  credential whose commitment matches a row M1 has and M2 lacks is
                  REJECTED ON M1 AND STORED ON M2 -- divergent enclave state, not just a
                  divergent code.  This is the worse of the two.

    Reachable because the commitment is deterministic: findCredentialPC =
    NewPedersenCommit(hash(lastName+phoneNumber), hash(providerPrivK)), and
    NewPedersenCommit only randomizes the blinding when it is nil (ecpedersen.go:317).
    Same person, same issuer, same commitment, forever.

    NOT the identity-uniqueness guard.  That is the credential-HASH table, written at
    claim time, and it is byte-identical on both nodes (CredentialHashMap, 264 rows).
    Uniqueness enforcement is intact on the joiner; what is short is the lookup index.

    TWO EARLIER READINGS OF THIS WERE WRONG and are recorded because both were plausible
    and both would have caused damage:

      "M2 is right, M1 leaks"      -- claimed the gate encodes "index holds only
                                     ownerless credentials" and the claim path should
                                     remove the row.  Refuted by M2's own 252 CLAIMED
                                     rows, which that invariant makes impossible, and by
                                     1608 == 1608.  Acting on it would have deleted rows
                                     the reader depends on.
      "the retained row is the duplicate-issue guard" -- over-reached in the other
                                     direction.  The guard is the hash table; this is a
                                     lookup index.

    THE FIX is to make the rebuild test what the invariant states --
    findCredentialPedersenCommit != nil -- rather than the current walletID, which is
    irrelevant history by rebuild time.  Transferring the table in privateStateTables
    would also work and is a bigger hammer; the comment there calling it "pure waste" to
    ship is wrong either way, since the local rebuild is demonstrably lossy.

    NOT YET DONE: fire the trigger.  Everything above is measurement plus code reading;
    no live divergence has been provoked.  Doing so deliberately halts the chain, since a
    consensus failure is the success condition.  Note also that
    test_credential_uniqueness.sh cannot catch this -- every identity it issues carries a
    per-run id, so no two issues ever share a commitment and credentialByPCXYExists never
    fires.  Its header line `create   no check at all` is inaccurate: there IS a check at
    create, just not the hash-uniqueness one it is describing.

40. **The suites that cannot repeat are the ones that create unreconstructable history,
    so the continuous loop structurally cannot find rebuild bugs.** Noticed while
    chasing item 39, which 672 consecutive regression runs did not surface.

    Three flows stamp a sentinel into Credential.walletID, and each one consumes an
    IDP-issued row permanently:

        CLAIMED      enclave.go:3743                       claim
        UPDATED      enclave_update_credential.go:279,289,345   update
        RECOVERKEY   enclave.go:4487                       key recovery

    Coverage in the continuous loop:

        CLAIMED      every cycle
        UPDATED      only under --with-credentials, which the loop never passes
        RECOVERKEY   only under --with-credentials as well -- update_credentials.sh
                     carries its own recovery flow (recover-jill / recover-jill2, claimed
                     with --recover-key).  The standalone test_key_recovery.sh is wired
                     into no harness at all, but the sentinel itself is not uncovered.

    update_credentials.sh is excluded for a STATED and good reason (regression.sh:59):
    single-use claim codes and consumed rate-limit windows mean it cannot run twice
    against one chain.  test_key_recovery.sh is excluded for NO stated reason anywhere;
    its absence is merely observed in passing at regression.sh:571, where it is relied on
    to justify reusing al-eph1.  It has the same single-shot property (fixed recover-al /
    recover-ann wallet names, fixed claim codes) so it would qualify for the same
    justification -- but nobody wrote one, so it reads as an omission rather than a
    decision, and nothing flags it.

    THE STRUCTURAL POINT.  Non-repeatable is not an incidental property here: a suite
    cannot repeat precisely BECAUSE it consumes something irreversibly, and consuming
    something irreversibly is what creates state that a from-current-state rebuild cannot
    reconstruct.  So the tests most able to expose a rebuild-vs-history divergence are
    exactly the ones a continuous loop must skip.  Item 39 is one instance; there is no
    reason to think it is the only one.

    WHAT WOULD ACTUALLY HELP, in rough order of value:

    - Run the excluded suites ONCE against a chain that a joiner then state-syncs from,
      and diff the enclaves with `export-private-state --digest-only`.  That is the shape
      of test that finds this class, and it does not need to be repeatable to be run --
      it needs to be run on a chain that is then joined.
    - Make the single-shot suites parameterised by a per-run id, the way
      test_credential_uniqueness.sh already is, so they become repeatable.  That is a
      real piece of work for update_credentials.sh (its claim codes are baked in at the
      top) but it converts an opt-in into a default.
    - Failing both, assert the invariant directly and cheaply on every joiner:
      |CredentialPCXY| == |credentials with a findCredentialPedersenCommit|.  It is one
      comparison, it holds on a correct node regardless of history, and it would have
      caught item 39 the first time any node state-synced.

    The third is worth doing even if the first two happen, because it is the only one
    that keeps working on a chain whose history nobody replayed.

    PARTLY RESOLVED 2026-08-17 -- the second bullet, for update_credentials.sh.  It now
    provisions its own four identities per run (setup.sh --prefix) AND its key-recovery
    cases run against the per-run jill with per-run recovery wallets, mnemonics and claim
    codes.  Nothing is consumed irreversibly, so the whole suite repeats, and the
    --with-credentials opt-in that gated it has been REMOVED from regression.sh: both the
    UPDATED and RECOVERKEY sentinels above now execute on every cycle of the continuous
    loop, which is what the coverage table said they never did.  --skip recovery drops
    just the recovery cases, for a chain that cannot spare the traffic.

    STILL OPEN: test_key_recovery.sh remains wired into no harness (fixed recover-al /
    recover-ann wallet names, fixed claim codes -- genuinely single-shot), and the first
    and third bullets are untouched.  The structural point above stands: this closed one
    instance, not the class.

41. **setup.sh --prefix silently produces unclaimable credentials unless the prefix is
    NUMERIC, because the CLI throws away a parse error.**  Found 2026-08-15 while making
    update_credentials.sh repeatable.

    --prefix suffixes the blinding factor along with the names (bf "5678" -> "5678ZZTEST"),
    and the CLI parses it as a base-10 integer with the error DISCARDED:

        x/qadena/client/cli/tx_create_credential.go:111
            findCredentialA,  _ := big.NewInt(0).SetString(argFindCredentialA, 10)
            findCredentialBF, _ := big.NewInt(0).SetString(argFindCredentialBF, 10)
            findCredentialPC = c.NewPedersenCommit(findCredentialA, findCredentialBF)

    SetString on a non-numeric string returns nil, and NewPedersenCommit treats a nil
    blinding factor as "generate a random one" (ecpedersen.go:317).  So the credential is
    created against a RANDOM commitment; the later claim-credential recomputes another
    random one, does not find the row, and fails with ErrCredentialNotExists -- an error
    that names neither the blinding factor nor the prefix.

    A numeric prefix works, which is why test_credential_uniqueness.sh is fine: it uses
    run_id=$(date +%s), suffix="${run_id: -6}", and builds claim codes as "${suffix}13".
    That constraint is load-bearing and written down nowhere.

    THREE FIXES, and they are not alternatives:

    - Check the SetString errors and fail with "blinding factor must be numeric, got X".
      Discarding them is what turns a typo into a random commitment.
    - Reconsider nil-means-random in NewPedersenCommit for the CLI path.  It is
      reasonable for a caller that wants a fresh commitment and dangerous for one that
      just failed to parse; the two are indistinguishable at the call site.
    - Say so in setup.sh --help, which currently documents --prefix as "Add a prefix to
      the test users" with no hint that the value must be a number.

    NOT a hypothetical: --prefix is the mechanism for giving a suite per-run identities,
    which is exactly what item 40 asks for.  Anyone reaching for it with a word-shaped
    prefix gets a setup that fails at the claim step for reasons that point elsewhere.

42. **test_key_recovery.sh asserts nothing, so wiring it into regression would add a
    suite that cannot fail.**  Nearly done on 2026-08-15, then reverted.

        script                    set -e   expect_*   fail()   exit 1
        test_key_recovery.sh         0         0         0        0
        request_key_recovery.sh      0         0         0        2
        sign_key_recovery.sh         0         0         0        0
        show_key_recovery.sh         0         0         0        0

    show_key_recovery.sh is four `query show-recover-key` calls that PRINT their output.
    Nothing compares it to anything.  So the suite would report PASS with every recovery
    request rejected, no partner signature registered, and every query returning an
    error -- the same shape as "the bring-up harness reported success while testing
    nothing" (commit 31616f51), which this repo has already been bitten by once.

    IT IS ALSO REDUNDANT.  update_credentials.sh cases 6/6a/6b cover the same flow and
    actually check it: the seed is withheld at 2-of-3 signatories and released at 3, the
    released phrase equals jill's real mnemonic, a second recovery returns the same
    phrase, and -- the part nothing else covers -- recovery still works when the user
    presents their PRE-MARRIAGE surname, which is the hash-aliasing guarantee.

    What test_key_recovery.sh has that the credentials suite does not is breadth: four
    users at three different signatory thresholds (al 2, ann 1, jill 3).  That is worth
    having, but only once it checks outcomes.  As written it exercises code without
    observing it, which is worse than not running it, because the green light is
    evidence to whoever reads the summary.

    SO: add assertions to it FIRST, then wire it in.  Until then the recovery coverage
    that means anything is the one inside update_credentials.sh.

43. **SetCredential refuses to re-store a credential it has already indexed, so a partial
    re-sync loses every row it has already seen.**  Found 2026-08-15 while costing the
    fixes for item 39, and it is independent of which of those is chosen.

        enclave.go:4252
            if s.credentialByPCXYExists(in) {
                return &types.SetCredentialReply{Status: false}, types.ErrCredentialExists
            }
            s.setCredentialNoNotify(in.CredentialID, in.CredentialType, *in)   // NOT REACHED

    The existence check runs BEFORE the store, so a re-push is not a no-op -- it is a
    failure that also skips the write.  For a live IDP issuing a genuine duplicate that is
    correct.  For enclaveSynchronizeStores it is not: that pushes EVERY credential
    whenever the Credential store hash differs, which is precisely the case where the
    enclave already holds some of them.

    So a node re-synced with a partially-populated enclave fails on each row already in
    the index, increments pushFailures, and leaves those credentials unstored -- while the
    rows it has NOT seen go in fine.  The result is a half-seeded enclave whose failures
    are counted but whose store is silently short.

    THE BLAST RADIUS GROWS WITH ANY ITEM 39 FIX.  Today the rebuild only indexes the
    still-ownerless credentials, so only those can collide: 504 of 3589 rows on this chain.
    Every candidate fix for item 39 indexes all IDP-issued credentials instead -- 2054 --
    so the number of rows a re-push would refuse goes up roughly FOURFOLD.  Fixing item 39
    without this makes this one worse.

    THE FIX is to make the re-push idempotent rather than to weaken the duplicate check:
    if the existing PCXY row already maps to the SAME credentialID, this is a replay of a
    row the enclave already has, and the correct response is to store it and return
    success.  Only a DIFFERENT credentialID behind the same commitment is a real duplicate
    and deserves ErrCredentialExists.  That distinction is available at the call site --
    getCredentialByPCXY returns the credentialID -- and it is the difference between "this
    identity is already issued" and "I have seen this exact row before".

    Not yet observed in the wild: the two-node chain has never re-synced an enclave that
    already held credentials, because the joiner was always wiped first.  That is also why
    it has not bitten -- and why it would, the first time anyone re-syncs rather than
    rebuilds.

30. **Does an SGX node actually need root? Evidence says no, and nobody has tested it.**
    `needs_root_if_real_enclave` (`scripts/setup_env.sh`) exits demanding sudo whenever the enclave
    is a real one, and every runtime script gates on it -- so every SGX node anyone has run has been
    started as root, and the assumption has never been re-examined.

    It looks wrong. `ubuntu/setup_qadena_build.sh` adds the login user to the `sgx` and `sgx_prv`
    groups, which own `/dev/sgx_enclave` and `/dev/sgx_provision` (`crw-rw---- root sgx` and
    `crw-rw---- root sgx_prv`). Measured on .120: the login user is in both groups (108, 1001) and
    `os.open()` succeeds on both devices. If `ego run` needs nothing else privileged, the node
    should come up unprivileged.

    The test: stop the node, `chown -R` $QADENAHOME to the login user, start WITHOUT sudo, and
    confirm the enclave attests, the chain produces blocks, and `qadenad enclave store-hash` works
    as the login user. If it does, `needs_root_if_real_enclave` should become a check that the user
    can open the devices rather than a check that the user is root.

    Why it is worth doing rather than leaving alone: running as root is the root cause of a
    surprising amount of friction. It produced root-owned logs that `init.sh` then could not delete
    without sudo, a root-owned `$QADENAHOME`, a root-owned `/tmp/start120.log` whose failed redirect
    silently ate a run and served STALE output as if current, and the EPERM that made
    enclave-rollback and enclave-crash look like a broken enclave (item fixed in 7688e6b5, but the
    fix would be unnecessary). It also means every test that touches the enclave needs an elevation
    path it should not need.

    Note the fix in 7688e6b5 is deliberately ownership-based rather than SGX-based, so it keeps
    working either way and does not have to be reverted if this test succeeds.

## Raised by the accumulator/watchdog/paging work (2026-08-16, Mac + M1/M2)

44. **Accumulator phase 2: compare chain-acc to enclave-acc DIRECTLY, then every block.**
    Both sides now maintain per-store accumulators (chain side activated in EnclaveEndBlock /
    dsvs BeginBlock), but they are only compared TRANSITIVELY: each side shadow-verifies its own
    value against its own scan, and the scans are compared across the boundary by GetStoreHash.
    The direct compare is an `acc` field beside `hash` in GetStoreHash's per-store reply -- and
    the elegant cadence is piggybacking the enclave's ten values on the EndBlockReply it already
    sends every block, giving full content-agreement checking per block for ~330 bytes in an RPC
    that already happens.  A mismatch halts THIS node with a named cause (node-local, halt-or-
    proceed, cannot fork).  Proto + enclave handler change, so MRENCLAVE moves: bundle with 45.

    DESIGN (settled 2026-08-16, and it supersedes an earlier fallback note): the vehicle is a
    PAIRED ESTABLISH-AND-RETURN RPC -- GetStoreAccumulators, the accumulator equivalent of
    GetStoreHash.  The read-only constraint that forced the enclave's flag/drain/EndBlock
    establishment dance belongs to GetStoreHash specifically (its commitCache history), not to
    the seam: a NEW rpc may write, exactly as SeedStorePage does.  So the handler ensures-if-
    missing (scan once, save) and then returns all values -- after this call "absent" is
    impossible by construction, the chain ensures its own side at the call site (its sync-loop
    compare already establishes on first touch), and the exchange compares acc-to-acc directly.
    One RPC is then establishment + comparison + the CLI access command: this item and 45 are the
    same change.  The per-block maintain sweeps on both sides remain, demoted from primary
    establishment to repair-and-insurance (one Get per store per block); the scan-moment shadow
    compares remain for phase-1 verification.  No absent-marker wire fallback is needed once the
    seam RPC exists -- establishment happens at the moment of first need, which is the seam.

45. **Accumulator access commands: `enclave store-accumulators --height` and
    `compare-accumulators --height`.**  Answering "are the accumulators the same across?" took
    debug-log archaeology plus a three-step syllogism; it should be one command.  The enclave
    side resolves height->version through the same index export-private-state and rollback use.
    Accumulators are digests -- same disclosure class as GetStoreHash -- so serve them from real
    SGX enclaves too, not just debug.  The chain side is a standard module query (--height comes
    free from the SDK query context) once activation has shipped.  This is also the binary-search
    tool for WHEN a store diverged, which nothing else in the system can answer.

46. **Accumulator phase 3: swap the hot paths, demote the scans -- but never delete them.**
    Once the shadow has been quiet across full regressions on both platforms (already true for
    the enclave half) plus real soak, startup sync and displayStoresSync should compare 33-byte
    rows instead of scanning ~16k rows per side.  Keep a LOW-FREQUENCY scan audit forever (the
    existing debug Height%25 cadence is the right shape): the accumulator is a maintained
    invariant, and only a scan catches a write path added later that forgets to hook it -- the
    exact rot that emptied the iavl fast index and shorted CredentialPCXY.  Note phase 1 as
    shipped INCREASES total scanning (value + verification on top of existing scans); the net
    saving only arrives with this item.

47. **Chain-side accumulator activation is consensus-visible: nodes must cross it together.**
    maintainStoreAccumulators writes ten rows into the qadena store (dsvs one more), which feeds
    the app hash.  Deterministic, so upgraded nodes agree with each other -- and disagree with
    un-upgraded ones from the first post-swap block.  Single-node chains swap freely; the M1+M2
    pair must swap binaries at the same halt or the full node forks off with an apphash mismatch.
    Any future chain with independent validators needs a coordinated upgrade height.

48. **CredentialHashMap and the other enclave-private derived indexes have NO comparison of any
    kind.**  Not mirrored, not hashed by GetStoreHash, not accumulated: corruption is invisible
    to everything except update_credentials case 6b, which only exists because the suite happens
    to recover through the primary hash.  This is the third member of the CredentialPCXY bug
    class (derived index, conditionally maintained, no ground-truth check).  Enclave-private
    accumulators would cost nothing consensus-wise -- enclave state never touches the app hash --
    and the machinery is already there; it is a prefix list away.

49. **displayStoresSync still ignores PioneerJar in its scan display.**  The store that produced
    a day of DIVERGED false alarms is compared at startup only; a mid-run divergence stays
    invisible until the next restart.  (The new accumulator shadow DOES cover it per checkSync
    block, but the enclave-vs-chain scan comparison -- the authoritative one until item 46 --
    does not.)  Add the case to the switch; it is one fallthrough.

50. **Codegen toolchain skew: M1's ignite regenerates 9 pb.go files without
    `var Msg_serviceDesc = _Msg_serviceDesc`.**  ignite chain init on a machine with a different
    protoc-gen version dirties the tree (one dead alias line per service file), which correctly
    trips package_release.sh's clean-tree guard and blocks phase 7 of 1st_node_bringup.  Worked
    around by `git checkout -- .` before packaging; the fix is pinning the codegen toolchain
    version across machines, or teaching the build to refuse mismatched generator versions with
    a message that names them.

51. **Real-loop-against-real-handler multi-page paging has still never run over actual gRPC.**
    Unit tests force it on each side separately (real keeper loop vs fake enclave; real enclave
    handler vs test-local loop); live tables are ~1000x under the 1 MiB budget.  QADENA_PAGE_BUDGET
    now exists (chain-side only, shrink-only, announced at ERROR when active): add an opt-in
    forced-paging regression cycle that starts the node with a few-KiB budget and asserts
    `outbox drain ... consumed X of Y` with X<Y appears -- evidence of a mid-queue page boundary
    crossing the real wire.

52. **Four pre-existing x/qadena/keeper test failures predate everything above.**
    TestGetParams/TestParamsQuery fail on a cosmetic big.Int nil-vs-zero mismatch after a marshal
    round trip; TestRecoverKeyQuerySingle/Paginated expect pagination from a query that is a
    committed `Unimplemented` stub ("intentionally mnot implemented", typo included).  Either fix
    the comparisons/stub or delete the tests; today they train people to ignore red.

53. **1st_node_bringup phase 8 decides "same enclave already installed" BY NAME.**  Debug
    placeholder ids never change with code, so a stale pre-fix enclave was kept while the check
    reported it current; only the qadenad content mismatch exposed it.  Compare binary content
    (hash), not the unique-id string, before skipping an install.

54. **M2 is joined but not finished: phases 6-7 never ran.**  Validator conversion and
    test_peer_agreement -- the first SCRIPTED cross-node comparison -- are the natural completion
    of the two-node bring-up, and peer-agreement would exercise the accumulator comparison from
    item 44 the moment it exists.

55. **Watchdog numbers are judgement, not measurement -- and the crash suite leaks its short
    grace.**  5s/3s/2m are unprofiled (zero false misses across full regressions on two
    platforms so far -- keep watching that stat); and the suite's QADENA_ENCLAVE_HEALTH_GRACE=15s
    export persists on the node it restarts.  The NON-DEFAULT announcement now makes that leak
    loud, but the suite could also re-export the default on its final restart at the cost of the
    next cycle's fast halt.

## Raised by the enclave trust split (2026-08-18, Mac + M1/M2 non-SGX + .120/.140 SGX)

Context: an enclave upgrade made a chain permanently unjoinable -- genesis names the LAUNCH
measurement `active`, the new enclave refused a foreign active identity, and the keeper panics on
refusal, so every joiner died at `InitChain` with `code 1146`.  Reproduced on SGX (.140 -> .120) and
non-SGX (M2 -> M1), fixed across 5f9b7dda..94650e9f by separating the mirrored EnclaveIdentity store
(the CHAIN's opinion, accumulated) from the trusted set (who may receive secrets, sealed params).
Verified: full regression 23/23 including `enclave-upgrade`, plus BOTH join paths onto an upgraded
chain -- block-sync (caught up 936, validator, peer agreement PASSED) and state-sync (caught up
2238, from snapshot 2001).

56. **P0 SECURITY, INTRODUCED BY 2a9acceb AND LIVE IN PUSHED CODE: `isLive` is node-supplied, and
    a false value skips the attestation age gate entirely.**  `UpdateEnclaveIdentity` reads
    `if knownPos && isLive && !attestationWithinAgeLimit(...)`, and `isLive` arrives from the
    keeper (`time.Since(header.Time)`), i.e. from the host.  The enclave cannot distinguish a
    replayed block message from a direct RPC call by its sole client, and that client IS the
    adversary in this threat model.  So a host can call the enclave's `UpdateEnclaveIdentity` over
    the socket with a GENUINE historical promotion of a since-RETIRED build, declare `isLive=false`,
    gain trust for it, run that build and pull the jar and regulator keys.  Before 2a9acceb a
    non-live attestation was ignored outright, so this is a regression, not an inherited flaw.  The
    justification given in the commit ("during replay the stream is consensus-ordered, so nothing
    chooses what we see") asserts a property the transport does not have.
    FIX: stop deriving age from `isLive`.  Keep a SEALED MONOTONIC HEIGHT HIGH-WATER-MARK and refuse
    trust-GAIN when `in.Height < HWM - attestationMaxAgeBlocks`.  A genuine joiner replaying history
    has a low HWM that climbs with the messages, so in-sequence grants still apply; an established
    node at height 5000 fed a promotion from height 1000 refuses it however `isLive` is set.  Add
    "replay may REVOKE, never GRANT" alongside (asymmetric in the safe direction, and the
    sync-enclave bootstrap plus reconcile/quorum already make declining safe), a future bound
    preserving the old `age < -1` symmetry, and seed a joiner's HWM from the seed's attested height
    so a fresh join is not permissive until it climbs.

57. **P1 pre-existing: `verifyRemoteReportMeasurement` reads `remoteReport.Data` AFTER a failed
    verification.**  The RealEnclave branch returns early only for `Revoked`/`OutOfDate`; every
    other error logs "neither revoked nor completely out-of-date" and falls through to
    `bytes.Equal(remoteReport.Data[:len(hash)], hash[:])`.  Two consequences: ego returns a ZERO
    report for any error that is not `OE_TCB_LEVEL_INVALID`, so `Data` is nil and the slice panics
    (recovered by the gRPC interceptor -- fragile, not exploitable); and `OutOfDateConfigurationNeeded`
    (4) != `OutOfDate` (1), so a genuinely out-of-date platform is ACCEPTED.  Last touched by
    a9998a69, so it predates the trust work.  FIX: reject explicitly when
    `err != nil && !errors.Is(err, attestation.ErrTCBLevelInvalid)`, before any `Data` read; then an
    explicit TCB ALLOW-list (UpToDate, ConfigurationNeeded, SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded); plus a `len(Data) < len(hash)` guard so the function is
    panic-free regardless.  Found by static analysis in a parallel session; never executed.

58. **DECISION, not a patch: rollback-freeze is the irreducible floor of the enclave-vs-host model,
    and should be an explicit accepted residual or an explicit project.**  Sealing gives
    confidentiality and tamper-detection, NOT freshness.  `enclave_config/enclave_params_<uid>.json`
    is an ordinary host file (with a `_backup.json` beside it), so the host can restore an older
    AUTHENTIC sealed state in which a since-retired build was genuinely trusted, spoof `isLive=true`,
    and have the enclave serve it from its own frozen past.  Verified that nothing detects this: no
    monotonic counter, no peer-anchored height, and `preparedHeight` is crash-consistency with its
    own node.  Note the ordering honestly -- this PREDATES the trust split and the split RAISED the
    bar: before it, trust was read off the mirrored row's Status, so minting trust in a build that
    was NEVER legitimate took a single mirror push; after it, all four trust-gain routes (self,
    bootstrap, attested, quorum) require the build to have been genuinely active at some real point.
    The only real close is a VICTIM-NONCE-BOUND, FAIL-CLOSED peer freshness challenge: the releasing
    enclave generates a nonce, the answering peer binds (nonce | its height) inside its remote
    report, and release is refused without threshold fresh answers.  The naive version ("ask a
    quorum their attested height") is replayable by the very host it defends against.  Building
    block exists: `QueryEnclaveValidateEnclaveIdentity` is already an attested peer round-trip.

59. **`build_enclave.sh` rewrites a LIVE node's `genesis.json`, and .120 is in that state right
    now.**  It rewrites `.app_state.qadena.enclaveIdentityList[].uniqueID/signerID` in
    `$QADENAHOME/config/genesis.json` on every build, so an upgrade on a running node leaves the
    file disagreeing with the genesis its own CometBFT serves: .120's file records `b43e245d...`
    while its RPC serves `bcbea7c9...`.  CometBFT validates genesis against what it stored, so
    **.120 may fail to restart** -- the divergence is established, the restart is UNTESTED.  This
    also cost a wrong diagnosis: the file was read as authoritative while the RPC held the truth.
    FIX: refuse to rewrite when the home already has chain data, or write to a template rather than
    the live config.

60. **`package_release.sh` can never run after a build in the same bringup.**  The build regenerates
    `.pb.go` (dropping `var X_serviceDesc = _X_serviceDesc` alias lines under a different
    protoc-gen-gogo), the tree is dirty, and packaging refuses artifacts that "correspond to no
    commit".  Phase 7 of `1st_node_bringup.sh` failed on EVERY run today; the workaround was
    stashing the generated files around the package step.  FIX: treat regenerated protobuf output as
    derived rather than authored for the dirty check, or regenerate deterministically.

61. **`increment_id` collides when the enclave-upgrade suite runs twice against the same chain.**
    The suite bumps `test_unique_id.txt`, registers the result, then REVERTS the file, so a second
    run computes the same next id and tries to register a measurement the chain already has.  Every
    run so far was preceded by a chain wipe, which is why it has not bitten -- but
    `run_regression_continually.sh` on .120 is exactly the shape that would.

62. **`nth_node_bringup.sh` reports PASS while 1,806 `ERR` lines scroll past.**  Its success criteria
    never grep the joiner's log for errors, so both joins were reported green while the accumulator
    divergence below was being written every block.  Same shape as the fork that was reported as
    "16 of 16 SUITES PASSED".  FIX: fail, or at least report, on unexpected `ERR` in the joiner's
    log during a bring-up.

63. **The `preInitEnclave` write-ahead may be unnecessary on the JOINER path, and it is the sole
    cause of every accumulator divergence measured.**  `preInitEnclave` writes the node's own rows
    locally -- `setIntervalPublicKeyIdNoNotify` once, `setPublicKeyNoNotify` twice -- and only then
    broadcasts them, so the enclave holds rows the chain lacks until its own registration is
    included: 1,806 ERR lines over heights 1-903 on a block-sync join, 410 over 2001-2205 on a
    state-sync one, each ending exactly at the block carrying its own `MsgPioneerAddPublicKey`.
    `PioneerJar` is the control that proves the mechanism: same registration transaction, no
    write-ahead, no divergence.  On the FIRST node the write-ahead is load-bearing -- `InitEnclave`
    calls `GenerateSecretShare` eight lines later, which reads `getAllPioneers()` and
    `getEnclavePubK()` for every pioneer INCLUDING self and bails out if the pubkey is missing.  On
    a JOINER, `SyncEnclave` never calls `GenerateSecretShare`, and `updateSSIntervalKey` is
    proposer-gated, so no reader was found.  "No reader found" is a search result, not a proof, and
    the failure mode of getting it wrong is a silently missing secret share surfacing later as an
    undecryptable VShare.  INVESTIGATE by instrumenting a joiner to log every
    `getAllPioneers`/`getEnclavePubK` call between `SyncEnclave` and its registration block.

64. **Do not cite the accumulator as a backstop against a doctored mirror -- it does not halt.**  The
    per-block CHAIN-vs-ENCLAVE check (`comparePerBlockAccumulators`) logs at ERROR and continues,
    deliberately, pending item 46's evidence gate.  The check that DOES panic
    (`auditStoreAccumulators`) compares the chain's maintained value against a scan of the chain's
    OWN rows -- self-consistency, blind to the enclave.  Confirmed at runtime: a joiner logged ~900
    blocks of cross-party divergence and went on to become a healthy validator that passed peer
    agreement.  A parallel session's security argument rested on the opposite assumption, so this is
    worth stating where it cannot be missed.

65. **Tests written but never run, and paths still untested.**  Written this session, not executed:
    `testscripts/test_add_full_node_mismatch.sh` (a joiner whose enclave differs from the seed must
    be refused BEFORE minting, funding or wiping anything, naming both builds) and
    `testscripts/test_enclave_identity_catchup.sh` (a node down while identities change: abstain
    rather than condemn, replay moves no trust, the gap is detected and QUEUED not trusted, and the
    "queued" line precedes the "trusting" line -- ordering, because an end-state assertion would
    pass just as happily if the node had believed the mirrored row).  Still untested entirely: the
    attestation age limit (needs ~1110 blocks or a test-only knob), non-proposer local decide, and
    the consensus-decoupling change in `PioneerUpdateEnclaveIdentity` under two-node peer agreement
    -- that last one is the highest severity, since being wrong there is a fork.

66. **Node logs rotate by DATE with no size cap and no retention, and a debug node writes ~100 MB an
    hour.**  `restart_qadena.sh:54` pipes the node through
    `rotatelogs -l -D -L $QADENAHOME/logs/qadena.log $QADENAHOME/logs/qadena-%Y-%m-%d.log 86400` --
    one file per day, nothing pruned, no ceiling.  Measured 2026-08-18: M1 reached **573 MB in about
    six hours** at `log_level=debug` (M2, quieter, 11 MB).  A long-lived node fills its disk, and a
    multi-gigabyte log is slow enough to grep that people stop looking -- which is the same failure
    as item 62, arrived at from the other direction: the evidence exists and nobody reads it.  Wants
    rotation by SIZE with a retention count (`rotatelogs -n`), or logrotate with compression, plus a
    decision about whether debug is the right default level for a node expected to stay up.
    Note the two files are HARDLINKS (`qadena.log` and today's dated file share an inode), so any
    pruning must account for that rather than assume two copies.

    NOT a bring-up concern, and deliberately not solved there: `1st_node_bringup` already starts
    clean (`init.sh` does `rm -rf $QADENAHOME`, logs included), and `nth_node_bringup` must NOT
    delete the joiner's log -- `add_full_node.sh` leaves `logs/` in place, and the previous attempt's
    log is usually the reason someone is re-joining.  Item 62 reads it from a byte offset taken
    before the node starts, which gives this run's boundary without destroying the last one's record.

67. **Codegen skew was ignite's CACHE, not the plugin and not the binary version -- three diagnoses,
    two of them committed before the third was found.**  Recorded so nobody repeats the sequence.
    `ignite generate proto-go` and `ignite chain init` regenerate with tooling ignite keeps under
    `~/.ignite` (93 MB on M1), and swapping the ignite BINARY does not touch it.  Established by
    experiment, in this order:

      1. *the PATH plugin* (b6af80cb) -- DISPROVED: hiding protoc-gen-gocosmos entirely and running
         `ignite generate proto-go` still succeeds, so ignite supplies its own.
      2. *the ignite module version* (a0368d23) -- INSUFFICIENT: M1 aligned to the Mac's v29.7.0 and
         still rewrote nine .pb.go files.
      3. *the cache* -- CONFIRMED: clearing `~/.ignite/cache` made M1 regenerate byte-identical to
         the committed tree, with no other change.

    Both earlier commits kept their pins, which fix real defects (`@latest` behind an `[ ! -f ]`
    existence test; a version comparison against a display string that reads `v29.10.1-dev` on
    machines running v29.7.0 and v29.8.0) -- but their stated reasoning was wrong and is corrected
    in place.  setup_qadena_build.sh now clears the cache whenever it installs a different ignite.

    A cache-staleness preflight was written and REJECTED: "cache older than the binary" fires on a
    machine that generates correctly (the Mac), and a check that cries wolf on a healthy machine
    trains people to ignore the checks that matter.  Invalidating at install time is the fix;
    detecting staleness after the fact would need to verify by OUTCOME (regenerate into a temp tree
    and diff), which is worth doing if this recurs.

68. **Nothing records which openapi generation path is canonical, and the three that exist disagree
    on CONTENT.**  `docs/static/openapi.yml` is generated, but by whom is unclear: `buf.gen.sta.yaml`
    uses `openapi_naming_strategy=simple` and `buf.gen.swagger.yaml` uses `fqn`, and
    `ignite generate openapi` and the generation inside `ignite chain init` do not produce the same
    file.  Measured 2026-08-18 with every plugin pinned and identical: committed 208 KB, an aligned
    Mac regenerated 894 KB (it pulls in the cosmos/evm surface), and M1 produced a third result
    **missing the `qadena.dsvs.Msg` endpoints** -- so adopting whichever machine ran last would
    silently drop documented endpoints.

    It dirtied the tree on every bring-up and blocked `package_release.sh` for artifacts it is not
    part of (`docs/` is in no packaged component), so it is now excluded from that dirty check --
    binaries still must correspond to a commit.  What remains is the decision: pick the intended
    config, regenerate once deliberately, and commit that.  Until then the committed file stands
    because it is what the API console serves today and nothing is visibly wrong with it.

69. **The state-sync join has no NEGATIVE CONTROL, so its pass proves less than it looks.**
    `nth_node_bringup.sh --state-sync` is now green on real SGX (.140 state-synced onto upgraded
    .120: snapshot restored at 2000, 61 private rows imported from the seed, app hashes MATCH at
    3523).  That shows the peers AGREE while the private-state import works.  It does NOT show the
    test would CATCH a broken import -- if the enclave-private tables were never transferred, or
    were transferred empty, nothing in the run asserts that the app hashes would then DIVERGE.
    A test that cannot fail is not evidence.

    Add a control: repeat with the import suppressed (a flag on the joiner, or a seed that refuses
    to serve `SeedStorePage`) and assert the peers **do** diverge.  Until that exists, cite the
    state-sync result as "the path completes and agrees", never as "the private-state transfer is
    verified".  The script's own closing note has said this since it was written; it was printing
    it against the wrong branch (it announced the block-sync caveat after a state-sync run), which
    is now fixed -- so the caveat is finally visible to whoever runs it.

70. **Three messages in this session described hardware or state they had not measured.**  All the
    same shape: report a PROXY instead of the observation, and be confidently wrong in one branch.
    - `add_full_node.sh` compared the enclave id EMBEDDED in the binary (`unique047` on every SGX
      build) instead of the MRENCLAVE `ego uniqueid` computes, and refused a perfectly matched pair.
    - `nth_node_bringup.sh` inferred SGX presence from whether `sudo_for` returned a string -- empty
      means BOTH "devices usable" and "no SGX at all" -- and printed "primary has no SGX device"
      during a real-SGX run.  `1st_node_bringup.sh` had already fixed this exact line and left a
      comment saying so; the fix did not propagate.
    - the same script's completion banner announced "this proves a BLOCK-SYNC joiner agrees" at the
      end of a `--state-sync` run.
    All three are fixed.  The pattern is worth a standing rule: **a script may only state what it
    probed**, and where two conditions produce the same proxy value, it must probe again rather than
    pick the friendlier branch.  Grep for other messages inferred from `$SUDO`, `$BUILD_SGX` or a
    flag rather than from the machine.

71. **`install_release.sh` told every operator to run it with `sudo`, and four places repeated it.**
    Nothing in the install needs root: it writes only into the invoking user's `~/qadena`, and the
    one root-sensitive step (`start_qadena.sh`) gates itself.  Following that advice leaves the whole
    node home root-owned, after which the operator's own `qadenad q ...` cannot read its 0600
    `config/client.toml` -- which is exactly how a healthy SGX joiner was stopped: the pre-check's
    remote query failed on a LOCAL permission fault, and, because the query ran under `2>/dev/null`,
    the refusal blamed the seed for being too old.
    `setup_env.sh`'s `needs_root_if_real_enclave` has argued the opposite case in detail for a long
    time ("ROOT IS NOT A QADENA REQUIREMENT") and `init.sh` refuses to run as root outright, carrying
    a `sudo rm -rf` workaround that exists only because homes end up root-owned.  The install docs
    were never reconciled with any of it.  Fixed in `install_release.sh` (header + a note, no
    automatic `chown`: recursively re-owning a live home would hand `priv_validator_key.json`,
    `data/` and `keyring-*` to the login account on the very machines where the node is meant to run
    as root), `package_release.sh` (x2), `1st_node_bringup.sh` phase 7, and `HOWTO-SGX-BRINGUP.md`.
    Remaining: nothing enforces it -- a future doc can reintroduce `sudo ./install.sh` and no test
    would notice.

72. **dsvs seeds AuthorizedSignatory into the enclave and never checks that it landed -- on the one
    path that has already caused a fork.**  `EnclaveSynchronizeStores`
    (`x/dsvs/keeper/enclave_gprc_client.go`) compares the enclave's accumulator against the chain's,
    pushes every row with `SetAuthorizedSignatory` when they differ, sets `checkSync = true` to mark
    that a re-check is owed -- and then discards it: `_ = checkSync`.  The re-compare the flag was
    written for does not exist.  A push that returns no error but seeds nothing is indistinguishable
    from a correct seed, in the code AND in the logs.

    That matters more here than elsewhere for two reasons.  First, the comment directly above the
    push records that this exact path already forked a chain: on a state-synced joiner every row was
    refused (`code 1141: Unauthorized`) because the live-path freshness rule was applied to rows that
    are old by construction, "the node then ran with no authorized signatories at all and forked 252
    blocks later".  The refusal was fixed (SET, not VALIDATE); the absence of verification was not.
    Second, the compare is not a per-block safety net -- `EnclaveBeginBlock` guards it with a
    package-level `synchronizedWithEnclave` bool, so it runs ONCE PER PROCESS.  There is exactly one
    observation per boot, and nothing looks again.

    (I asserted the opposite while reviewing the SGX state-sync join -- "it appears once and never
    recurs, and the compare runs every block, so a persistent divergence could not hide".  The
    second clause is false, which makes the first clause meaningless as evidence.  It never recurs
    because it never runs again.)

    Do the re-check: after seeding, call `GetStoreAccumulators` again and compare.  Log at Error and
    fail closed if it still differs -- a joiner that silently lacks authorized signatories is a node
    that will fork at the first dsvs transaction, hundreds of blocks after the cause.

    Note for whoever picks this up: the SEEDING/OUT-OF-SYNC distinction added this session makes the
    empty-enclave case log at Info.  That is right (an empty store is not a divergence) but it means
    the ONE per-boot observation of a genuinely wrong state is the Error branch alone -- all the more
    reason the post-seed verification has to exist.

    **Verified BEHAVIOURALLY on M1/M2 (2026-08-19), which is not the same as fixed.**  A debug
    state-sync join reproduced the SGX conditions exactly (seed on unique048, genesis naming
    unique047, 26 signatory rows on chain, snapshot at 2000) and the seeding works:
      - first boot logged `SEEDING ... AuthorizedSignatory (enclave holds no rows)`, chain-acc
        779484a1...;
      - two later boots did NOT re-seed, so the rows persisted;
      - at debug level the compare stated its own verdict -- `in-sync store:
        key=AuthorizedSignatory/value/ acc=49b434da...` -- which is direct evidence rather than
        inference from a missing error line;
      - 894 blocks of live dsvs traffic after the join: 0 refusals, 0 consensus failures, 0
        divergence, and peer agreement MATCHED at 2680 and again at 3335.
    So the push lands.  What is still missing is what this item is about: the CODE cannot tell.  A
    seed that silently failed would produce identical logs and identical silence, and the node would
    fork hundreds of blocks later.  Verification belongs in the code, not in a session transcript.

73. **The joiner's log is the evidence for a join test, and the NEXT join deletes it.**
    `add_full_node.sh` starts the node from scratch, which takes `~/qadena/logs` with it.  M2 ran a
    state-sync join and then a block-sync join; when the SGX run raised a question about what the
    state-sync join had logged, the answer was unrecoverable -- the only retained log was the later
    block-sync run.  Two joins in sequence means the first one's evidence is gone by the time anyone
    asks about it, which is exactly when it is wanted.
    Cheap fix: `nth_node_bringup.sh` copies the joiner's log window off the joiner when the run
    finishes (it already computes the byte offset for the error check), or `add_full_node.sh` moves
    `logs/` aside instead of removing it.

74. **Coverage note: what M1/M2 CANNOT establish, learned by finding four things only on SGX.**
    Debug builds prove logic, and they did -- but three of the four issues the SGX round surfaced
    were invisible there by construction, and the fourth was missed by test ordering:
    - **measurement identity**: with no `ego` on the box, every probe falls back to the id EMBEDDED
      in the binary (`unique048`), which on a debug build genuinely IS the chain's identity.  Code
      that confuses embedded-id with MRENCLAVE is CORRECT on debug and wrong only on SGX.
    - **privilege**: no SGX devices means `sudo_for` is always empty, so no scripted path there ever
      installs or runs as root; ownership faults cannot appear.
    - **messages conditioned on SGX state**: "primary has no SGX device" is TRUE on M1/M2.  A
      message is only wrong on the machines it is wrong about.
    - **dsvs seeding (item 72)**: the conditions DID exist on M1/M2 -- M1's chain held 15
      authorized-signatory rows at height 2001, the snapshot M2 state-synced from -- but that join
      predates item 62's joiner-log check, and the most recent M2 round was block-sync only, where
      the joiner replays from height 1 with both sides empty and the seeding path never runs.  The
      SGX run was the FIRST state-sync join ever executed with the check active.
    Implication for how to read a green M1/M2 run: it is evidence about logic, not about
    attestation, identity, privilege, or anything conditioned on real hardware.  And when a fleet
    round exercises only one join path, say which one -- "joiner verified" without naming the path
    reads as both.

75. **`--with-enclave-upgrade` reports "could not build the enclave" when the real cause is that
    `go` is not on PATH, and leaves the chain stopped.**  The suite stops the node by design, builds
    the new measurement, and restarts on it.  When the build fails the node stays down, and the
    summary line names the measurement rather than the fault -- the actual error,
    `build_enclave.sh:126: command not found: go`, is only in
    `/tmp/enclave_upgrade_build.$USER.log`.

    Hit this session by launching `regression.sh` over ssh WITHOUT a login shell: a non-interactive
    ssh command does not source the profile that adds `/usr/local/go/bin`, so `go` is missing even
    though it is installed and on PATH for any normal login.  `nth_node_bringup.sh`'s header already
    documents this trap ("`bash -lc` is the fix for ... a non-login shell missing /usr/local/go/bin
    during builds"); the regression has no such guard.

    Two cheap fixes: preflight for `go` (and the other build tools) BEFORE the suite stops the node,
    so an environment fault costs nothing and reports itself; and surface the last line of the build
    log in the failure message.  Restarting the chain on failure would be better still -- an
    environmental error should not leave a stopped node behind.

76. **RETRACTED -- the credential-update cool-down was never shown to be broken.**  This item
    originally claimed that a second hash-changing update was committed three blocks after the first
    against `update_credential_min_blocks_between_updates = 10000`, citing two transactions at
    h=11713 and h=11716 both carrying `code=0`.

    That conclusion was wrong, and the way it was wrong is worth keeping.  The claim rested on
    transaction CODES alone.  The credential's own counter says otherwise:

        Update Generation:  1     (al102847, and again al111633 on a later run)

    One update ever applied -- case 1's correction.  The policy held; nothing was substituted.  A
    code is not evidence that state changed, and for a store the enclave owns, the state is the only
    thing that can settle it.

    Two mistakes fed it.  First, the failing case was misidentified: the command that failed uses
    `${suffix}03` = `$reject_a`, which is CASE 3 ("rejected substitution: first + last + birthdate
    all change at once"), not case 9's rate limit.  The suite aborts at case 3, so the cool-down
    case never runs at all and remains UNTESTED to this day.  Second, `tx_reject_code` returned
    EMPTY when a transaction was refused before broadcast -- which callers reported as "the chain
    ACCEPTED it" -- and it took the FIRST txhash in the output, which belonged to the preceding
    create-credential and resolved to an unrelated transaction.  Both are fixed.

    What remains genuinely open, and should be re-run once the helper is trusted:
      - does case 3's refusal report a usable qadena code, or only a simulation failure?
      - does case 9 (the cool-down) pass when the suite is allowed to reach it?
      - is `expect_reject` strong enough?  A transaction that lands with code 0 and changes nothing
        would still pass a code-based check; asserting Update Generation is what actually proves a
        refusal.

77. **A trailing newline in test_unique_id.txt silently creates a DIFFERENT enclave, and forks the
    chain.**  The three identity files are `//go:embed`-ed verbatim, so `echo "unique048" > ...`
    (which appends "\n") produces an enclave whose id is `unique048\n`.  That id names the sealed
    state file, so the enclave does not find its own state, starts with EMPTY private tables, and
    then executes real blocks against a chain that expects the populated ones.  Observed directly:

        -rw-r--r-- 2154 09:18  enclave_params_unique048.json     <- the real sealed state
        -rw-r--r--  333 09:42  enclave_params_unique048\n.json   <- a fresh, empty one

    The node logged `Enclave starting 1.1.5 signer051 unique048` (the newline is invisible), no
    watermark line, and `reconciled at height 11848` -- i.e. it adopted the chain's height while
    holding none of its state.  It ran ~15 blocks that way.  The app hashes still agreed, because
    the accumulators it owned had not yet changed; the fork surfaced one block later and the chain
    halted with M1 at 66.4% -- just under the 2/3 it needed to proceed alone.

    Fixed at the source: the embedded values are now `strings.TrimSpace`d, so the failure is
    impossible rather than merely unlikely.  Still worth doing: refuse to start when the sealed
    state for this id is absent BUT another `enclave_params_*` file exists whose name differs only
    by whitespace -- that is never a legitimate new identity, and starting empty is the worst
    possible response to it.

78. **A rebuild after an enclave upgrade silently reverts the node to the PRE-UPGRADE identity.**
    `build_enclave.sh` takes the measurement AND the version from tracked files
    (`cmd/qadenad_enclave/test_unique_id.txt`, `version.txt`), and `test_enclave_upgrade.sh` bumps
    them, builds, and then RESTORES them (`restore_version_files`).  So after an upgrade the repo no
    longer describes what the node is running, and any later `build_enclave.sh` on that machine
    produces the old identity again -- here it rebuilt `unique047` on a chain running `unique048`,
    and on the retry it produced `1.1.4/unique048` against a chain expecting `1.1.5/unique048`,
    which failed provisioning with `1108: Invalid destination EWalletID`.

    Nothing warns.  The build should compare what it is about to produce against what the node's
    home currently holds (`enclave_config/enclave_params_*.json`, or the installed binary's own
    answer) and refuse -- or at least say loudly -- when a rebuild would move the node's identity
    backwards while chain data exists.  This is the same shape as item 59 (rewriting a live node's
    genesis): a build step that is safe on a fresh machine and destructive on a running one.

79. **The enclave's private tables are NOT keyed by enclave identity, so a "different" enclave
    silently inherits and writes another one's store.**  Sealed params are per-identity
    (`enclave_config/enclave_params_<uid>.json`), but the tables are a fixed path:

        db,        _ = tmdb.NewGoLevelDBWithOpts("enclave", *homePath+"/enclave_data",    &opts)
        secretsDB, _ = tmdb.NewGoLevelDBWithOpts("secrets", *homePath+"/enclave_secrets", &sopts)

    So an enclave that cannot find its sealed state -- new identity, corrupted file, or item 77's
    trailing newline -- starts with NO KEYS AND NO TRUST but with the PREVIOUS enclave's tables
    open for writing.  It then executes blocks, cannot decrypt what it reads, and writes what it can.
    That is how a two-node chain forked here: 16 blocks executed that way left `enclave_data` on the
    proposer permanently inconsistent with its peer, and no restart could undo it, because the
    divergence was in the tables rather than in the params or the binary.

    The pairing should be explicit: either put the tables under the identity too
    (`enclave_data_<uid>/`), or refuse to open an existing store when no sealed state matches this
    identity.  A fresh identity meeting a populated store is either a mistake or an attack; it is
    never routine.  Note this ALSO means a genuine enclave upgrade shares tables across
    measurements, which is presumably intended -- so the guard has to be "no params but a populated
    store", not "identity changed".

    Related: item 77 (the newline that created the identity), 78 (the rebuild that produced the
    wrong one), and the accepted rollback-freeze residual in ENCLAVE-THREAT-MODEL.md, which assumes
    an enclave's own sealed state is the thing an attacker would swap -- this is the same class,
    reached by accident.

80. **A node should HALT rather than execute blocks with an enclave that cannot use its own state.**
    The whole cost of items 77-79 was that a keyless enclave kept going: it executed sixteen blocks,
    wrote into the previous enclave's tables, and left a store that no restart, binary revert or
    params swap could reconcile.  Had the node simply stopped, the fix would have been "correct the
    id and restart" -- seconds, not a chain rollback.

    THE EXISTING CHECKS DID NOT SEE IT, and it is worth being exact about why:

    - `verdictHaltNoHistory` halts a fresh enclave facing a chain with history -- but this enclave
      did not look fresh.  Its TABLES were there (enclave_data is not keyed by identity, item 79);
      only its KEYS were missing.  It reported `reconciled at height 11848` and carried on.
    - the per-block accumulator compare logged NOTHING (0 divergences all day).  It hashes the ROWS,
      and the rows were the same rows -- the enclave simply could not decrypt them.  So "the
      accumulators agree" is not evidence that the enclave can use what it holds.

    The missing signal is decryptability, not presence.  A cheap detector: on startup, decrypt one
    known row (any store the enclave must be able to read -- an IntervalPublicKeyID entry, say) and
    refuse to serve if it fails.  A blind enclave fails that on the first attempt, before it can
    execute anything.  The narrower version of the same idea is item 79's guard: no sealed params
    for this identity BUT a populated store is never legitimate.

    Prefer HALT to degraded operation here.  Halting is node-local and fork-safe -- the chain pauses
    if the node holds enough stake, which is loud, recoverable and exactly what happened anyway,
    except that the pause came 16 blocks too late and after the damage.  Note the same argument the
    per-block compare's comment makes for staying at Error ("halting graduates through item 46's
    evidence gate") does NOT apply to this check: a node that cannot decrypt its own state has no
    correct work to do, so there is no false-positive cost to weigh.

    Today's evidence for the gate: TWO occurrences, and the second is worse than the first.

    The first cost 16 blocks of bad execution, a halted two-node chain, and a recovery that needed
    `qadenad rollback --height`.

    The second (2026-08-20, ARM fleet, height 30755) cost a FORK. Three joiner enclaves held a
    Shamir SHARE where a private key belonged -- `SetPublicKey` cached `myShare` into the private
    key cache unconditionally, which is correct below four owners (nothing is split) and fatal at
    or above it. A share is one byte longer than the secret, so `getSSPrivK` returned 65 bytes,
    `MultBytes` fed that to `ScalarMult`, which panics above 32, and the recovered panic came back
    as a zero-value reply the keeper read as a VERDICT. All three convicted a well-formed credential
    with 1153. They held 71.5% of stake, committed the block, and EJECTED THE ONE NODE THAT HELD THE
    REAL KEY. That node was correct; it hit CONSENSUS FAILURE and never moved again, while the other
    three ran on for 650+ blocks with nothing reporting a problem.

    THIS IS THE DIAGNOSIS IN THIS ITEM, DEMONSTRATED. The enclave state store reported 193 rows on
    every node and full agreement -- every presence check and every row-count check passed. Only the
    VALUE LENGTHS differed: `{64:193}` on the healthy node against `{0:61, 64:127, 130:5}` on each
    joiner. Presence was never the missing signal; usability was.

    It also supplies the blinding mechanism this item's negative control needs, which was not
    available when it was written: make a node an owner of a genuinely split SS key (four or more
    addressable pioneers) and let it receive the broadcast. One forced rotation reproduces it on
    demand -- verified 2026-08-21, both non-minting pioneers cached 130 hex chars where the minter
    cached 64.

    **THE DETECTOR NEEDS A NEGATIVE CONTROL, or it joins the class of checks it exists to replace.**
    Both checks that failed here were checks that could not fail: `verdictHaltNoHistory` saw tables
    and concluded "not fresh", and the accumulator compare hashed rows that were byte-identical and
    reported zero divergences all day.  A decryptability check added without a test that
    DELIBERATELY BLINDS AN ENCLAVE AND ASSERTS THE NODE HALTS is the same kind of artifact: green
    from the day it ships, with nothing establishing it would go red.  The test is cheap now that
    item 77 is understood -- write an id file with a trailing newline, or point the enclave at a
    populated store with no matching sealed params, and require a halt rather than a height.  This
    is item 69's complaint about the state-sync join, in a place where the cost of being wrong has
    already been measured at 16 blocks and a rollback.

81. **update_credentials.sh case 3 passes without proving what its own comment claims.**  The case is
    the right idea -- the identity provider mints a credential for a DIFFERENT person (Ferdinand /
    Romualdez / Marcos, 1957-Sep-13) and al, who is Rodolfo Alberto / Asuncion / Villarica,
    1970-Feb-02, tries to update onto it.  First, middle, last and birthdate all move at once, which
    `update_credential_max_changed_identity_fields = 1` must refuse.  It IS refused: the run reports
    "rejected as expected", and independently the credential's own counter stays at
    `Update Generation: 1` across runs, so nothing was substituted.

    But the assertion is weaker than the case reads:

    - **The "rollback proof" is not a test.**  The case prints al's credential under the heading
      "must be byte-identical to case 1", and nothing compares them.  No variable holds case 1's
      dump, no diff runs, and no assertion can fail.  The strongest claim in the case is a comment
      over an echo.
    - **The rejection code is not pinned.**  Any failure passes: wrong blinding factor, insufficient
      fees, rate limit, a typo in the credential id.  `test_credential_uniqueness.sh` pins its codes
      for exactly this reason ("both cases would still pass while testing nothing about
      uniqueness"); this suite does not.  Today the case passes on `rejected-before-broadcast` --
      a refusal at simulation, which proves the chain said no but not WHICH rule said it.
    - The policy's own error exists and is specific: **1154 ErrCredentialUpdateRejected**
      ("Credential update rejected by change policy").  Case 3 should require it.

    Two changes make it a real regression guard: capture case 1's credential dump into a variable
    and diff it after case 3, and assert code 1154.  The same applies to case 4 (birthdate
    substitution), which passes on the same unpinned signal.

82. **A release package is architecture-locked, and nothing in it says so.**  `package_release.sh`
    ships BOTH `libwasmvm.aarch64.so` and `libwasmvm.x86_64.so`, which makes a package look portable,
    but there is exactly one `qadenad` and one `qadenad_enclave` and they are the BUILDER's
    architecture.  Measured on the ARM primary:

        includes: qadenad qadenad_enclave signer_enclave libwasmvm.aarch64.so libwasmvm.x86_64.so ...
        qadenad -> ARM aarch64,  qadenad_enclave -> ARM aarch64

    The manifest records version, commit and measurements -- not arch.  `install.sh` does not check
    it either, so installing an ARM package on an x86 node (or the reverse) succeeds and fails later
    as a loader or exec error, at a point that looks nothing like its cause.  This matters as soon
    as a fleet is mixed: the ARM boxes are where the debug sequence gets rehearsed and the SGX boxes
    are x86, so the two groups can never share a package.

    Cheap and worth doing: record `uname -m` in the manifest at package time, and have install.sh
    refuse a package whose arch does not match the host, naming both.  The check belongs in the
    package, not in whatever script happens to be driving -- a preflight refusal instead of a late
    loader error.

    Found while advising a parallel session that was about to distribute an ARM-built package to an
    SGX pair; they now probe `uname -m` before building, but the guard should not depend on the
    caller.

83. **`1st_node_bringup.sh --ref <branch>` builds a STALE LOCAL branch, and reports it as success.**
    Phase 3 resolves the ref by preferring an exact local match and only falling back to
    `origin/<ref>`:

        if git rev-parse --verify --quiet "$REF^{commit}";       then resolved="$REF"
        elif git rev-parse --verify --quiet "origin/$REF^{commit}"; then resolved="origin/$REF"

    That is right for a TAG or a SHA and backwards for a BRANCH.  `main` always resolves locally, so
    the fetch immediately above it is discarded and `reset --hard main` is a no-op against whatever
    the target last had.  Measured 2026-08-19 on two freshly cloned ARM boxes: `--ref main` fetched,
    then reported

        building commit 907103f5

    while `origin/main` was two commits ahead at `9befbcfe`.  Nothing warned, because "the ref I
    asked for" and "the commit it built" are each self-consistent -- the run simply tested older code
    than the operator asked for, and every later artifact (package, measurement, manifest) correctly
    describes the wrong commit.

    It survived review because it needs a STALE LOCAL COPY of the branch to bite: on a machine that
    has never checked that branch out, only the `origin/` fallback exists and the behaviour is
    correct.  A cloned box is exactly the case that has one.

    Fix: when the ref names a remote-tracking branch, prefer `origin/<ref>`; keep the local-exact
    path for tags and SHAs, which have no remote-tracking form and must not be rewritten.  Note that
    a plain `git pull` is NOT the fix and should not be adopted: the no-`--ref` mode deliberately
    leaves the checkout alone so a local, unpushed, or bisected commit can be tested, and
    `--ref` already implies `reset --hard` + `clean -fd`, which is why phase 3 refuses a dirty tree.
    The property that protects both modes is the one already present -- REPORT the commit actually
    built -- so that should also be recorded into the run directory rather than only printed.

    Fix this WITH item 85: both are about what `1st_node_bringup.sh` phase 3 does and what phase 1
    should have done first.  Resolving the ref correctly and hoisting the cheap checks touch the same
    two phases, and doing them separately means reading the same ordering twice.

84. **A fleet bringup should be able to BLOCK-SYNC the joiner instead of waiting for state-sync to
    become eligible.**  State-sync cannot start until the primary is past the snapshot interval AND
    has actually written a snapshot -- 2000 blocks at this chain's 1.5s `timeout_commit`, so roughly
    50 minutes of waiting during which nothing is being tested.  `full_fleet_bringup.sh` spends that
    time in its snapshot-wait stage, and it is by far the longest stage in the sequence on ARM, where
    the build itself is about three minutes.

    Block-sync has no such precondition: `nth_node_bringup.sh` already block-syncs whenever
    `--state-sync` is absent, so the joiner can be brought up as soon as the continuous regression is
    running and the chain is producing blocks.  The option is therefore nearly free to add -- skip
    the snapshot wait, and drop `--state-sync` from the join -- and it turns a ~50-minute idle wait
    into a join that can start immediately.

    KEEP STATE-SYNC THE DEFAULT, because the two are not interchangeable as tests:

    - State-sync is the path that seeds a joiner's ENCLAVE STORE from a snapshot rather than by
      replaying history, which is the mechanism items 69 and 72 are about.  A block-synced joiner
      never exercises it, so a fleet brought up this way proves nothing about snapshot import.
    - Block-sync replays every block from genesis, so it gets slower as the chain grows.  It is
      fastest early and eventually becomes the slower option -- the opposite of the intuition that
      makes it attractive.

    So: `--block-sync` for the case where the point is to HAVE a second node quickly (peer agreement,
    two-validator consensus, anything needing traffic from two sources), and the default state-sync
    path when the point is to TEST how a node joins.  Whichever runs should be recorded in the run
    directory, since "the joiner caught up" means something different in each case.

85. **The cheapest preconditions are checked LAST, after the destructive ones have run.**  A
    toolchain fault that is knowable before anything is touched currently costs the node, the
    checkout and the chain data first.  Measured 2026-08-19 bringing up two fresh ARM clones:

        INIT CHAIN FROM SCRATCH AND ERASE ALL DATA
        Removing /home/alvillarica/qadena          <- chain data destroyed
        Copying config/config.yml -> config.yml
        protoc-gen-openapiv2 is the WRONG VERSION  <- then it fails

    `check_codegen_plugins.sh` is called from `init.sh:129`, which is AFTER `rm -rf $QADENAHOME` in
    the same script.  The plugin versions do not depend on anything the removal does, so the order is
    pure accident.  `1st_node_bringup.sh` compounds it: init.sh runs in its PHASE 4, so phase 2 has
    already stopped the node and phase 3 has already `reset --hard`ed the checkout.  Its own phase 1
    preflight checks `go` and `git` exist but never checks that they are the RIGHT VERSIONS, which is
    the failure that actually happens on a machine provisioned before the current pins.

    The dirty-tree guard has the same shape: it is in phase 3, so a run on a checkout with
    uncommitted work stops the node in phase 2 before discovering in phase 3 that it will not
    proceed.  Both were hit on consecutive runs on the same pair of boxes.

    Fixes, cheapest first:

    - `init.sh`: call `check_codegen_plugins.sh` BEFORE `rm -rf $QADENAHOME`, not after.  One line
      moved, and it stops the script destroying a chain it was never going to rebuild.
    - `1st_node_bringup.sh` phase 1: run `check_codegen_plugins.sh` and the dirty-tree check there,
      alongside the existing `go`/`git`/`ego`/`docker` probes.  Phase 1 is the designated home for
      "can this machine do the job at all", and it currently answers a weaker question than its name
      claims.  It also benefits everyone running the script directly, which is the common case.
    - `full_fleet_bringup.sh`: run the per-node preflight (`--only 1`) for every host BEFORE its own
      stage A, which archives each joiner's `~/qadena`.  Today it does that destructive move first
      and discovers an unbuildable primary afterwards -- on the first of these runs it archived a
      1.2G tree for a run that then failed at stage B.

    The split worth keeping: NODE-level checks (toolchain currency, tree cleanliness, disk) belong in
    `1st_node_bringup` phase 1 where any caller gets them; FLEET-level checks that a single-node
    script cannot know about -- architecture agreement across primary and joiners, reachability of
    every host, SGX consistency -- stay in `full_fleet_bringup`.  The rule in both: NOTHING
    destructive until every cheap check has passed on every host.

    Fix this WITH item 83, which is the other half of the same phase 3: 83 is the ref it resolves
    wrongly, this is the checks that should have run before it resolved anything.  Both edit the same
    two phases, and the dirty-tree guard moving out of phase 3 is a precondition for 83's fix being
    legible -- otherwise phase 3 keeps two unrelated responsibilities.

    Same family as items 81, 82 and 83, and worth reading together: each is a check or a report that
    cannot fail -- an assertion with nothing to compare, a package that does not declare what it is,
    a ref that resolves to the wrong commit self-consistently, and here a preflight whose name
    promises more than it verifies.  The recurring lesson is that a green signal is only worth what
    the thing producing it could have said instead.

86. **`nth_node_bringup.sh` passes `user@host` straight into `--advertise-ip-address`, and the node
    refuses to start.**  `1st_node_bringup.sh` ALREADY FIXED THIS FOR ITSELF and documents it at the
    top of the file; `nth_node_bringup.sh` has the same defect, untouched, at lines 543 and 626:

        --advertise-ip-address $JOINER \
        --genesis-pioneer-first-ip-address $PRIMARY$SECOND_IP_ARG \

    `$JOINER` and `$PRIMARY` are ssh targets and legitimately accept `user@host`.  These two flags
    are not ssh targets -- they become CometBFT addresses.  Measured 2026-08-19 joining an ARM node
    driven as `alvillarica@192.168.86.136`:

        external_address = 'alvillarica@192.168.86.136:26656'      <- written into config.toml
        ERR failed init node error="address (85cd3d22...@alvillarica@192.168.86.136:26656)
            does not contain ID"

    Two `@` in one address, so CometBFT cannot split `<nodeid>@<host>:<port>` and the node exits 1 at
    startup, taking the enclave and signer down with it.  The failure appears at PHASE 5 (start),
    several minutes after phase 4 has already minted the pioneer key, funded it, fetched genesis and
    run sync-enclave -- all of which SUCCEEDED, so the run looks like a start problem rather than an
    argument that was wrong from the first phase.  Recovery is to edit `external_address` by hand and
    re-run `--only 5`; nothing else has to be redone.

    Fix: strip the prefix once, exactly as `1st_node_bringup.sh` does --

        ADVERTISE_J="${JOINER##*@}" ; ADVERTISE_P="${PRIMARY##*@}"

    -- and use those for the two address flags while `$JOINER`/`$PRIMARY` stay whole for ssh.  Note
    the third site: `SECOND_IP_ARG` defaults to `${SEED2:-$PRIMARY}`, so the state-sync trust seed
    carries the same prefix whenever `--seed2` is omitted.

    **IT CONTAMINATES THREE CONFIG FIELDS, NOT ONE, AND THEY FAIL ONE AT A TIME.**  Fixing
    `external_address` alone gets the node one step further and it dies again on the next field.
    Measured, in the order they surfaced:

        external_address = 'alvillarica@192.168.86.136:26656'
        persistent_peers = '<nodeid>@alvillarica@192.168.86.52:26656,<nodeid>@alvillarica@...'
        rpc_servers      = 'alvillarica@192.168.86.52:26657,alvillarica@192.168.86.52:26657'

    Each produces a DIFFERENT error at a different startup stage -- `failed init node`, then `could
    not add peers from persistent_peers field`, and `rpc_servers` would have followed -- so an
    operator fixing them reactively pays three restart cycles to learn one fact.  Anyone repairing a
    node by hand should `grep -c '<user>@' config.toml` and expect ZERO before restarting, rather
    than fixing the field the current error names.

    (The doubled entries are not a second bug: `SECOND_IP_ARG` defaults to the primary, so a
    two-node chain legitimately lists it twice -- self-corroborating, as `--seed2`'s help says.)

87. **A build DIRTIES ITS OWN CHECKOUT via a tracked generated file, so the next run refuses to
    start.**  `config/config.yml` points ignite at a generated OpenAPI spec:

        client:
          openapi:
            path: docs/static/openapi.yml

    `ignite chain init` regenerates that file, and it is TRACKED, so every successful bringup leaves

        M docs/static/openapi.yml

    behind.  The next run with `--ref` then hits the dirty-tree guard and stops, because
    `git clean -fd`/`reset --hard` would discard it.  The guard is right -- it cannot tell generated
    output from a person's uncommitted work -- so the result is a machine that can be brought up
    exactly once and then blocks itself.  Measured 2026-08-19 on M1 and .52, both of which had built
    successfully and were refused on the next run for nothing but this file.

    It is invisible until the guard runs early: previously the check lived in phase 3, AFTER the node
    had been stopped, so the usual experience was a run that killed the chain and then refused.

    The file is a single line of ~213KB of JSON, so it also diffs as "1 insertion, 1 deletion" and
    tells a reader nothing.

    Options, best first:

    - Do not track it.  It is build output; `.gitignore` it and drop it from the index.  Anything
      that needs to serve the spec generates it, which `ignite chain init` already does on every run.
    - If it must stay tracked (a published artifact), regenerate it deliberately -- a make target or
      a commit hook -- rather than as a side effect of every chain init, and have the bringup restore
      it (`git checkout -- docs/static/openapi.yml`) before the dirty check.
    - Do NOT "fix" this by passing `--force` from the fleet script.  That disables the guard for
      genuine uncommitted work too, which is exactly the loss the guard exists to prevent -- and on
      2026-08-19 that guard is what saved two Go test files (`dumpcommit/`) on three separate boxes.

    Related: item 85 (the guard moving earlier is what made this visible at all).

    Worth noting WHY it survived: driving with a bare IP works, and that is what every previous run
    did.  The `user@` form is documented and supported for driving a node as a specific account, and
    it is the form a fleet script naturally passes through -- so the option that exists for the
    harder case is the one that is broken.  A run that never needs it never sees this.

88. **FIXED 2026-08-19.  test_bank_restriction.sh waits 120s for a proposal that can legitimately
    take 300s, so it fails spuriously.**  `submit_whitelist_proposal()` now sizes its wait from
    `query gov params`.`voting_period` plus 90s of margin, and says why when it does run out.
    One trap found while fixing it, worth keeping in mind for any other duration read from the
    chain: **the query answers in GO DURATION FORMAT, not seconds.**  `config.yml` says `"300s"`
    but the chain renders it `5m0s`, so the obvious `${vp%s}` yields `5m0` -- not a number, so a
    naive parse silently takes its fallback every single time and only looks correct while the
    fallback happens to match. The fix parses h/m/s properly (verified against `5m0s`, `300s`,
    `1h0m0s`, `2m30s`, `504h0m0s`).  `submit_whitelist_proposal()` submits with `expedited: true` and then polls
    `60` times at `2s` -- 120 seconds.  That covers the 30s `expedited_voting_period` comfortably and
    is LESS THAN HALF the 300s regular `voting_period`.

    An expedited proposal whose threshold is not met inside its window is CONVERTED to a regular one
    by the SDK -- normal behaviour, not an anomaly -- and it then needs the full 300s.  When that
    happens the poll gives up, returns `PROPOSAL_STATUS_VOTING_PERIOD`, and case 7 fails.

    Measured 2026-08-19 on .120, where the same suite passed 22 of 23 and this was the only failure.
    The voting windows show it exactly -- same helper, same JSON, one proposal converted:

        prop 4: expedited=true    30s window   passed
        prop 5: expedited=true    30s window   passed
        prop 6: expedited=null   300s window   FAILED THE TEST
        prop 7: expedited=true    30s window   passed

    THE CHAIN WAS RIGHT AND THE TEST WAS WRONG.  Proposal 6 finished as
    `PROPOSAL_STATUS_FAILED` -- precisely what case 7 asserts -- roughly three minutes after the
    poll had already given up.  Nothing about the whitelist logic misbehaved; the suite simply
    stopped watching too early, and reported a chain defect that did not exist.

    Fix: size the wait for the REGULAR voting period plus margin (300s here, so ~180 polls at 2s),
    because conversion is expected behaviour rather than a fault.  Better still, assert on the
    proposal's own `voting_end_time` instead of a fixed poll count, so the wait follows the chain's
    configured periods rather than a constant that silently rots when `voting_period` changes.

    Note the shape: items 81-85 are checks that CANNOT FAIL; this is the mirror image, a check that
    fails when nothing is wrong.  Both make a green suite mean less than it appears -- one by never
    objecting, the other by objecting to noise -- and a flaky red is the more expensive of the two
    here, because it stops a fleet bringup that had nothing wrong with it.

89. **FIXED 2026-08-19.  A fleet bringup cannot RESUME, so a late flake costs the whole build.**
    `full_fleet_bringup.sh` now takes `--from <stage>` (A0 A B C D E F G H), validated against the
    stage list and recorded in the run directory.  `--from D` or later prints a NOTE that it is
    stepping over the regression, because skipping the red-run guard should never be quiet.
    `PRIM_UID` is resolved lazily from the primary's binary when stage D is skipped, so a resume
    still verifies each joiner against what the primary is ACTUALLY running rather than against an
    unset variable.  Verified by resuming at F on a live node: A0-E were skipped entirely and
    nothing on the host was touched.  `full_fleet_bringup.sh`
    correctly refuses to package, install or join off a failed regression (that guard is right and
    should stay), but it has no `--from`, so recovering means re-running from stage A -- including a
    ~24-minute reproducible SGX build that had already succeeded and whose artifacts were still
    installed and healthy.

    On 2026-08-19 the SGX pair hit item 88 at stage C with a live, correct chain on .120 and a
    perfectly good enclave already built.  Continuing by hand (`--only 7`, `--only 8`, loop, join)
    took about three minutes; a clean re-run would have cost half an hour to rebuild something that
    was never broken.

    The sub-scripts are already phase-addressable, so this is sequencing, not new machinery: give
    the fleet script the same `--from <stage>` its own children have, and make the run directory
    record which stage it reached so a resume knows where to start.  Keep the red-run guard --
    resuming past a real failure must stay a deliberate act, not the default.

90. **A NODE-LOCAL ENCLAVE FAILURE BECOMES A CONSENSUS-VISIBLE TRANSACTION RESULT, WHICH IS A
    FORK.** `EnclaveValidatePersonalInfo` runs inside a message handler -- in DeliverTx -- and
    returns whatever THIS NODE'S enclave answers over a local gRPC socket. Whether the call
    succeeded, failed in transport, timed out, or crashed becomes the transaction's result, and a
    result that differs per node is a different app hash.

    Measured, height 30755, 2026-08-20: three joiner enclaves panicked and the recovered panic was
    read as "invalid credential" (1153) while the fourth node validated the same credential
    successfully. The three held 71.5% of stake, committed the block, and ejected the one node that
    was CORRECT. Fixing the panic and the malformed reply (both done) makes the failure honest; it
    does NOT stop the fork. The tx still fails on the failing nodes and succeeds on the healthy one.

    THE RULE IS DETERMINISTIC VS NODE-LOCAL, not panic vs recover. A failure that is a pure function
    of the transaction is safe to become a tx result -- every validator computes it identically. A
    failure that depends on node-local state (enclave keys, OOM, a socket) must HALT, because
    recovering it manufactures a per-node answer. This is item 80's argument, one layer down: item
    80 halts when an enclave cannot use its own state at startup; this halts when an enclave call
    fails DURING BLOCK EXECUTION.

    A PLAIN `panic()` IN THE HANDLER DOES NOT WORK, and this is the part that makes it non-trivial.
    baseapp's `newDefaultRecoveryMiddleware` wraps EVERY panic raised inside `runTx` into `ErrPanic`
    and returns it as an ordinary tx result -- so panicking forks exactly as before. `haltOnEnclaveFailure`
    works only because EndBlock is outside `runTx`; all 12 of its uses are EndBlock or height
    reconciliation. 47 call sites in `enclave_grpc_client.go` do `return err` on an enclave error
    inside a message handler and are outside its reach.

    Two viable constructions:
      - TYPED PANIC + `AddRunTxRecoveryHandler`. The client panics with a typed `enclaveUnavailable{}`;
        a registered handler re-panics for that type only, escaping runTx's recovery and halting,
        while every other panic keeps today's treatment. PREFERRED: it cannot be forgotten at a call
        site the way an explicit call can.
      - POISON FLAG + halt in EndBlock. Record the failure in PROCESS MEMORY (not the KVStore --
        that would make it part of the app hash, which is the divergence being avoided), scoped to
        the block height, gated on `ExecMode() == ExecModeFinalize`, and call `haltOnEnclaveFailure`
        at the top of `EnclaveInvokeEndBlock`. More predictable; halts at a defined point.

    THE COST IS REAL AND SHOULD BE STATED BEFORE ANYONE IMPLEMENTS THIS. With it in place on
    2026-08-20, M2/M3/M4 would ALL have halted at 30755 and the chain would have STOPPED rather than
    forking. That is the correct outcome -- a halted chain with an obvious cause beats 650 blocks
    built on a wrong verdict -- but it converts this class of defect from a silent fork into a fleet
    outage. Deferred deliberately on 2026-08-21 so the cause fix could be validated first.

    WORTH WEIGHING FIRST, because it may remove the class instead of converting it: guard
    `ValidatePersonalInfo` with `IsCheckTx` the way `EnclaveValidateTransferPrime` already does, so
    a bad credential is refused at admission and never becomes a consensus question at all.

91. **The enclave panics on inputs it could reject, and the one safe fix changes a signature.**
    `ECPoint.Mult` reduces its scalar mod N before calling `ScalarMult`; `ECPoint.MultBytes` does
    not, so any caller handing it more than 32 bytes panics in vendored C-backed secp256k1
    (`scalar_mult_cgo.go`). That is how a corrupt cache entry became a crash at height 30755.

    DO NOT "FIX" IT BY REDUCING MOD N TO MATCH `Mult`. That silences the panic and silently computes
    a WRONG CURVE POINT instead, which is worse: a loud crash beats a quiet wrong answer, and every
    caller here is decrypting or verifying something. The safe fix is to REJECT an oversized scalar,
    which `MultBytes` cannot do -- it returns `*ECPoint` with no error, so this means changing the
    signature and its 11 callers in `x/qadena/common/vshare.go`.

    NOTE THIS IS HYGIENE, NOT A CONSENSUS FIX. Turning a panic into a returned error leaves the
    error node-local, so the results still diverge and item 90 still applies. It is worth doing
    anyway because under SGX a crashed enclave loses its working state and needs restart and
    re-attestation. It also cannot be made complete: OOM is not defensible by any input check, and
    item 80's incident was an enclave OOM death.

92. **A new enclave measurement can never be promoted while any other pioneer is addressable, so
    the enclave upgrade path deadlocks on a multi-pioneer fleet.**
    Hit on 2026-08-21 rolling `unique049` onto the 4-validator ARM fleet. The upgrade failed with

        [enclave-old-unique048 - E]: But couldn't find an active enclave identity for uniqueID: unique049

    and by then `unique049` was already `inactive` on chain -- not merely `unvalidated`.

    THE CYCLE. `validateEnclaveIdentities` asks every addressable pioneer, and each peer answers from
    `QueryEnclaveValidateEnclaveIdentity` -> `getEnclaveIdentity` -> `trusts()`, which reads the
    TRUSTED SET, not the chain's mirrored `EnclaveIdentity` row. Trust is granted by exactly five
    routes -- `isSelf`, bootstrap (`enclave.go:3527`), attested-by-a-trusted-enclave (`:3891`), own
    quorum (`:6208`), and upgrade handover. A measurement NO ENCLAVE IS RUNNING YET satisfies none of
    them, so every peer truthfully answers `InactiveStatus`. Note `randomizePioneerIDs` removes SELF
    before the threshold is computed, so on the 4-validator fleet it is `getThreshold(3)` = 1, not 2:
    `answered=3`, `activeCount=0`, `threshold=1` -- enough answers to clear the abstain guard
    (`answered < threshold` is false), so it CONDEMNS. Only ONE peer ever needed to vouch, and none
    could.

    THE ONE NON-CIRCULAR BRANCH IS UNREACHABLE ONCE A SECOND NODE HAS EVER PROPOSED. Promotion can
    also happen via `len(pioneers) == 0` ("no pioneers (except self), will mark it as valid"), which
    skips the poll. `getAddressablePioneers` keys off a published `ExternalIPAddress`, written by
    `updateIsValidator` on a node's first proposed block -- and NEVER cleared: no code path sets a
    pioneer's address back to `""` (only service providers get that, on deactivate), and
    `updateIsValidator` is guarded by `!PioneerIsValidator`, which is sealed true permanently. So the
    branch closes for good the moment a second node proposes, and stopping peers does not reopen it:
    unreachable peers abstain, they do not become un-addressable. A full fleet rebuild therefore buys
    exactly ONE promotion -- the window before any second node has ever proposed.

    IT IS NOT RECOVERABLE BY RE-REGISTERING. A mirror push may remove trust but never add it
    (`enclave_trusted_identities.go`, "HOW TRUST IS LOST"), so a fresh governance proposal setting the
    identity back to `unvalidated` -- or even to `active` -- restores nothing. `reconcileTrustOnGoingLive`
    only re-QUEUES such a row for validation, which condemns it again. The measurement is burned.

    WHY IT WAS NEVER SEEN. It has only ever worked through the `len(pioneers)==0` self-promotion
    branch ("no pioneers (except self), will mark it as valid"). M1's log shows exactly that for both
    live identities, at 1:00 and 1:01 AM, when M1 was the only addressable pioneer; M2/M3/M4 then
    inherited that trust by bootstrap. Making M3/M4 validators turned a latent gap into a hard block.
    `testscripts/test_enclave_upgrade.sh` cannot catch it: it restarts the chain to make promotion
    reachable in bounded time, and that chain has one addressable pioneer.

    ANY FIX IS A TRUST-MODEL CHANGE AND MUST BE DESIGNED, NOT PATCHED. The honest framing is that
    quorum cannot answer "should we trust code nobody is running" -- attestation of a measurement is
    not the same question as whether peers have seen it. Options, none free:
      - Let governance be a trust anchor: a passed proposal is a human decision with a quorum behind
        it. Weakens "a mirror push never adds trust", which exists because mirrored rows arrive from
        an untrusted node -- so it would have to bind to the gov result, not the row.
      - Let a peer vouch for a measurement it can ATTEST rather than one it already trusts, i.e. have
        the upgrading node present a remote report from the new enclave. Closest to the SGX model,
        and useless on debug builds where reports are forgeable.
      - Accept it and document that upgrades roll from a single addressable pioneer.

    OBSERVABILITY WAS THE REAL FAILURE and is fixed (2026-08-21): the answering side logged NOTHING
    about its decision, so a condemnation left no record of who voted what. Both sides now log under
    `enclave-identity: ` -- `ANSWER active/inactive` with its reason on the responder, `VOTE <pioneer>
    answered <status>` on the asker, the pioneer count and threshold before the decision, and a loud
    `CONDEMNING` / `NOBODY VOUCHED FOR` naming this exact case. `trusts()` is pinned by
    characterization tests in `cmd/qadenad_enclave/enclave_trust_promotion_test.go`.

93. **`test_update_enclave_identity.sh` votes only `--from pioneer1` and reports success regardless.**
    The proposal expires unpassed while all three transactions (submit, deposit, vote) succeed and
    the script exits 0. Observed twice on 2026-08-21; both times a manual treasury vote was needed.

    THE SHORTFALL DEPENDS ON WHO ELSE VOTES, which is why it is so easy to get wrong -- this item
    has now been wrong in BOTH directions. Measured on 2026-08-21:

      - pioneer1 voting ALONE on a proposal the treasury ignored: **25.0000%** of bonded stake. An
        operator's vote carries its validator's entire delegated stake.
      - pioneer1 + pioneer2, treasury still silent: **50.0000%** -- past the 33.4% quorum. Two
        operators are enough.
      - on a proposal the treasury DID vote on, the same accounts carried only their
        self-delegations (0.2475% and 0.2722%), because a delegator's vote overrides its validator
        for that portion, and the treasury has delegated 98.94% of all stake across all four.

    So `--from pioneer1` alone reaches 25%, short of quorum but not by the two orders of magnitude
    an earlier draft of this item claimed. `gov_can_reach_quorum` now reports both bounds.

    Also worth recording: the treasury holds ~48x the entire bonded supply in LIQUID aqdn, which
    carries zero voting power. Its 98.94% comes entirely from having delegated.

    The script should assert the proposal PASSED, not that its transactions landed.

94. **DONE 2026-08-21 -- there were no node-operator scripts for governance.**
    Built: `scripts/gov_lib.sh` (shared helpers), `gov_register_enclave_identity.sh` (submit,
    deposit, vote, wait for PASSED, then wait for the peer quorum to promote it, with `--dry-run`
    and a refusal to submit when the named voters cannot reach quorum), `gov_vote.sh` (vote from
    several accounts, report the resulting tally), and `gov_proposal_status.sh` (status, tally, and
    distance from quorum; exits non-zero unless PASSED so it can gate a deploy).

    Two arithmetic traps were found while building them, both of which produce WRONG NUMBERS RATHER
    THAN ERRORS: zsh's `$(( ))` is 64-bit and silently truncates ~1e25 stake values, and jq's
    `tonumber` converts them to IEEE doubles and prints `1.01e+25`, which `bc` cannot parse. All
    stake arithmetic in these scripts sums decimal strings through `bc`.

    Original item, kept for the rationale:
    Registering an enclave identity, the one routine operation that REQUIRES governance, has no
    operator-facing tooling. The only script that submits a proposal is
    `testscripts/test_update_enclave_identity.sh`, which is a test fixture: it hardcodes the message
    type, votes only `--from pioneer1`, and asserts nothing about the outcome (item 93).

    WHAT THIS COST ON 2026-08-21. Registering `unique049` needed three transactions plus a second
    vote from the treasury account to clear the 33.4% quorum, none of which is scripted. Every step
    was assembled by hand against `qadenad tx gov`, and each hand-assembly is a chance to get the
    deposit, the voting period, or the voter set wrong -- all of which fail by TIMING OUT rather
    than erroring, so the failure arrives minutes later as "the proposal is still in voting period"
    with no indication of which step was wrong.

    Wanted, as `scripts/` (operator) rather than `testscripts/` (fixtures):
      - submit a proposal from a template, print the proposal id, and WAIT for it to leave the
        deposit period -- the id is only discoverable by parsing tx events today
      - vote from a named set of accounts, and report the running tally against quorum and threshold
        rather than just that the vote transaction landed
      - poll a proposal to a terminal state and exit non-zero on REJECTED or FAILED, so it can gate
        a deployment script instead of being watched by a human
      - a `--dry-run` that reports whether the named voters can actually reach quorum BEFORE
        submitting, since on a balanced 4-validator fleet no single pioneer can

    Note the enclave-identity case specifically: the status a proposal may set is constrained
    (`msg_server_update_enclave_identity.go` allows a NEW identity only as `unvalidated` and an
    EXISTING one only to `inactive`), so a wrapper should refuse an impossible transition up front
    instead of letting it pass, spend a voting period, and fail at execution.

95. **Enclave identity registration passes on the same bar as a text proposal.**
    Since the promotion fix (item 92), a passed governance proposal is what makes a measurement
    `active` -- and an active measurement is one every node will hand its sealed jar and regulator
    private keys to, as soon as someone runs code with that MRENCLAVE. Governance is now the trust
    anchor for the enclave, so `MsgUpdateEnclaveIdentity` decides KEY CUSTODY, not spending.

    It carries no more weight than a proposal to change a text field. gov v1 has exactly two tiers,
    regular and expedited, and no per-message-type thresholds, so chain-wide params cannot express
    "this one needs more". Raising `quorum` for everything to protect this one message is the wrong
    instrument -- it was raised 0.334 -> 0.40 on 2026-08-21 for ordinary prudence, not as a fix here.

    The bar belongs in the handler (`msg_server_update_enclave_identity.go`), which already refuses
    illegal transitions and is the natural place for a stricter rule. Options, in rough order of
    cost:
      - require a supermajority of the CURRENT enclave operators, not of stake. The set of nodes
        running an active measurement is knowable on chain, and it is the set with something to lose.
      - require the proposal to carry a remote report from the candidate build, verified in the
        ENCLAVE (never in the handler -- see the DCAP-replay hazard recorded at
        `msg_server_pioneer_update_enclave_identity.go:31`, where verification in a consensus path
        halts a replaying node).
      - a longer mandatory voting period for this message type specifically, so a registration
        cannot be pushed through in a quiet window.

    NOTE THE ORDERING CONSTRAINT any fix must respect: the measurement has to reach `active` BEFORE
    the binary goes live, because the outgoing enclave refuses to hand its keys to an inactive
    identity. A stricter bar therefore lengthens every legitimate upgrade too, which is the real
    cost to weigh.

96. **`qadenad_enclave -unique-id` reports the DEBUG LABEL on an SGX build, not MRENCLAVE.**
    Observed on SGX1 2026-08-21: the flag answered `unique047` while `ego uniqueid` on the same
    binary answered `cc3518658aa8bf13de1b37533b8742a18c2685042a66aac20ed86657073b49e9` -- and the
    hash is what everything else on that machine is keyed by:

        qadenad_enclave.ab35560151defd04...        (staged binaries)
        enclave_params_cc3518658aa8bf13...json     (sealed params)

    The label is `//go:embed`-ed from `cmd/qadenad_enclave/test_unique_id.txt` and is compiled in
    whether or not the binary is ego-signed, so the flag cannot distinguish the two builds. Any tool
    trusting it on SGX compares a debug label against a chain full of hashes, finds no match, and
    reports a healthy node as running an unregistered measurement.

    `scripts/enclave_lib.sh` now centralises the rule -- ego present means ego is authoritative, ego
    absent means the build is debug and the embedded label IS the identity -- and
    `enclave_identities.sh`, `activate_enclave.sh` and `check_upgrade_enclave.sh` use it. Verified
    against both a debug node and SGX1.

    THE FLAG ITSELF IS STILL MISLEADING and is what should really be fixed: on a real enclave it
    could report the measurement the runtime knows about instead of the compile-time label, or refuse
    to answer. Until then, every new caller has to remember this, which is the kind of thing nobody
    remembers.

97. **A build stopped a running node on another machine's chain.**
    Introduced and hit the same day, 2026-08-21. `install.sh` was changed to stop the node before
    installing binaries (item: a plain `cp` silently fails with "Text file busy" against a running
    node, so builds reported success while deploying nothing). That change is right on a normal
    host and wrong inside a build container.

    `build.sh` re-invokes itself with `DOCKER_BUILD=1` for the SGX reproducible build, and the inner
    invocation does not carry `--hold`. So the in-container `install.sh` called `stop_qadena.sh
    --all`. A build container has no node to stop -- except the SGX builder is privileged and
    bind-mounts `$QADENAHOME` because it needs `/dev/sgx`, so the stop reached OUT of the container
    and halted the host's chain at height 98145, during a `--hold` build whose entire purpose was to
    touch nothing. The host's own log recorded the `stop_qadena.sh` lines, which is what made it
    attributable.

    Fixed by guarding on `DOCKER_BUILD` rather than on `--hold`: a flag has to be threaded correctly
    to help, and this has to hold even when it is not. Stopping a node is never right from inside a
    build.

    STILL WORTH DOING, because the guard only covers the case we know about:
      - `--hold` is not threaded into the Docker invocation at all. It should be, so the two agree.
      - the SGX builder having host reach is the underlying hazard, and it is not specific to this
        script. Anything that shells out during a reproducible build can do this. Worth checking
        whether the builder needs to be privileged, or whether `/dev/sgx` alone is enough.
      - `stop_qadena.sh` could refuse to run when it detects it is inside a container.

98. **`install_release.sh` promised not to touch a running node, then touched it.**
    When the enclave identity is not yet active it deliberately declines the cutover and prints

        === 4. leaving the node running ===
          the cutover cannot happen yet, so nothing that is in use will be written.
          Only the new enclave is staged alongside; the running node is untouched.

    and then step 5 installed everything anyway, dying on

        cp: cannot create regular file '/home/alvillarica/qadena/bin/qadenad': Text file busy

    Observed on SGX2 2026-08-21. The ETXTBSY arrives several screens after a message promising the
    opposite, so it reads as a mysterious permissions problem rather than the script contradicting
    itself. Fixed with a `stage_only` flag honoured by the binary, library and scripts installs: the
    measurement- and version-named copies are still written (a new filename is never busy), the live
    names and `scripts/` are not.

    WHY IT WENT UNNOTICED: the branch only runs when a node is ALREADY installed, RUNNING, and the
    packaged identity is not yet active on the chain that node can see. On a fresh install or a
    stopped node it never fires.

    THE UNDERLYING CONDITION IS WORTH KNOWING, because it is not an error: SGX2's local state was at
    height 71208 while the identity had been registered at ~99781, so the identity genuinely did not
    exist in the state it could see. A catching-up node cannot verify a recent registration, and at
    ~93 blocks/minute it needed ~5 hours before it could. `install_release.sh` has `--wait-active`,
    which waits for the identity but not for the node to be able to SEE it; a sync-aware wait, or at
    least reporting `catching_up=true` as the reason rather than "not registered, or the chain is not
    reachable", would have made this self-explanatory.

99. **A node that is behind when a measurement is promoted can never trust it, and if every peer
    upgrades it is stranded permanently.**
    Hit on SGX2 2026-08-21. Two-node chain; SGX1 upgraded cc3518658a -> 22f4780f while SGX2 was
    ~28,000 blocks behind. SGX2 can no longer use any peer enclave:

        [SGX1] ss-reconstruct: SERVE OK ... to=A/iVV4U1v9Z/     (467 of them, zero refusals)
        [SGX2] remote report unverified
        [SGX2] not enough shares to reconstruct privk

    SGX1 served every share it was asked for. SGX2 DISCARDED all 467, because it verifies the
    responder's report against its own trusted set and 22f4780f is not in it.

    WHY IT CANNOT RECOVER. Trust in a new measurement normally arrives by executing the promotion
    block while LIVE (the attested route). A node that is replaying defers trust changes; on going
    live `reconcileTrustOnGoingLive` only QUEUES the identity for validation; and validation polls
    peers, where counting an answer requires verifying that peer's report -- which requires already
    trusting its measurement. With every peer upgraded there is no trusted enclave left to learn
    from. The circle closes.

    Note the item-92 fix does NOT help here. That changed the RESPONDER (a node now vouches for a
    measurement governance registered). This is the REQUESTER side, which still authenticates
    answers against its own trusted set.

    WHY IT USUALLY STAYS HIDDEN: a lagging node replays on its CACHED SS interval keys and never
    asks a peer for anything -- SGX2 did that for hours at 64 blocks/min. The trap springs only when
    the cache is gone (here: enclave_secrets wiped in lockstep with enclave_data, as required) or
    when a key minted after the upgrade is needed.

    OPERATIONAL RULE UNTIL FIXED: every node must be live and caught up when a measurement is
    promoted. Check `catching_up` on every node before registering; if one is behind, wait for it or
    deliberately hold one peer on the old measurement until it lands. This is what made the M1-M4
    rolling upgrade uneventful -- all four were in sync at height 19756 when unique050 was promoted,
    so all four trusted it before any binary was swapped.

    POSSIBLE FIXES, all trust-model changes and none obviously right:
      - let a stranded node accept the on-chain attested claim's own report when the chain row is
        active AND the claim verifies against a measurement named in a governance proposal
      - allow sync-enclave bootstrap from a peer running a DIFFERENT but chain-active measurement,
        which today is refused (the seed must run OUR build)
      - keep the previous measurement trusted for a grace period after an upgrade, so a straggler
        has a trusted peer to learn from

100. **State-sync needs enclave keys the snapshot does not carry, so it works for a joiner or a node
     with a trusted peer -- and for nothing else.**
     Measured on SGX2 2026-08-21, three runs.

     THE CHAIN HALF IS FINE. Discovery, App.OfferSnapshot's enclave-aware accept, chunk transfer,
     app-hash verification and restore at height 102000 all worked, every time. Nothing below is a
     criticism of state-sync itself.

     WHAT A SNAPSHOT DOES NOT CARRY. The enclave holds private tables nothing on chain encodes, and
     rebuilding them is not a copy: SeedStorePage calls the real SetProtectKey/SetRecoverKey, which
     DECRYPT a VShare using the SS interval private key that was current WHEN THAT ROW WAS CREATED.
     So seeding needs historical interval keys, one per row's era.

     WHY A NODE'S CACHE IS THE WRONG SHAPE. Replay walks forward and needs only the key current at
     each block. Seeding applies EVERY row at once, each bound to its own era's key. A node's cache
     therefore covers the blocks it WALKED, not the rows the snapshot HOLDS. The two coincide only
     for a node that was present for all of history.

     MEASURED, with everything else held constant:
       enclave_secrets wiped  -> 467 rows rejected
       enclave_secrets kept   ->  77 rows rejected (62 ProtectKey + 15 RecoverKey)
     i.e. the cache covered 83%, and the residue was exactly the rows created during the ~29,000
     blocks the node was behind. A third run with every config value read back and verified before
     start produced 77 again, so configuration was never a factor.

     For the residue it must fetch shares from a peer, which requires TRUSTING that peer's enclave.
     SGX1 served every request (467 "ss-reconstruct: SERVE OK", zero refusals); SGX2 discarded all of
     them because SGX1 had upgraded to a measurement absent from SGX2's sealed trusted set (item 99).

     SO STATE-SYNC HAS THREE SHAPES AND ONLY TWO EXIST:
       fresh joiner            no cache, no trust -- but sync-enclave bootstraps trust from a seed
                               running its OWN measurement.  This is why add_full_node.sh works: it
                               wipes enclave_config, so the enclave is a fresh build matching the seed.
       trusted peer available  fetches whatever the cache lacks.  The normal case.
       stale identity, no      neither route.  Created here by upgrading the node's only peer.
       trusted peer

     WHAT TO BUILD, in increasing order of ambition:
       - PRE-FLIGHT CHECK, cheap and worth doing regardless: before enabling state-sync, verify the
         node can authenticate at least one peer's enclave measurement. If it cannot, seeding WILL
         fail -- say so before downloading and restoring a snapshot, not after. The failure currently
         arrives as "Encryption generic error" on a ProtectKey row, which names neither cause.
       - PREFER THE NEAREST SNAPSHOT, not the highest. CometBFT offers the newest first; the smaller
         the gap between the node's current height and the snapshot, the more of the seeding its
         existing cache covers. A node a few thousand blocks behind would likely seed cleanly.
       - LET SEEDING DEFER WHAT IT CANNOT DECRYPT. Today one undecryptable row halts the node. If
         ProtectKey/RecoverKey rows whose era-key is unavailable could be recorded as pending and
         resolved once trust or the key arrives, a node could state-sync now and complete later --
         PROVIDED the pending set is genuinely inert, which needs care: half-seeded private tables
         are exactly the silent-fork hazard OfferSnapshot exists to prevent.
       - FIX THE STRANDING (item 99), which removes the trust half of the problem entirely.

101. **`test_enclave_rollback.sh`'s networked branch asserts against a variable that is never set.**
     Line 239 compares `"$bal_now" = "$bal_after"`, and `bal_after` is assigned NOWHERE in the
     script -- only `bal_before` (129) and `bal_now` (215) exist. So the branch can only ever fail:

         FAIL(test_enclave_rollback): re-sync did not restore the transaction: expected , got 899999997352269658972280

     Note the empty "expected". Observed on the 4-validator ARM fleet 2026-08-21.

     WHY IT SURVIVED: the branch runs only when the node HAS PEERS. On a solo chain the other branch
     runs, and that one is complete and correct -- it checks the enclave store hashes reverted, which
     is the assertion the whole test exists for. So the suite passes everywhere it is usually run and
     fails only on a fleet, where the failure reads as a product bug rather than a test bug.

     THE FIX IS NOT JUST ADDING THE ASSIGNMENT. The intent (from the comment at 238: "the peers still
     hold the block, so we must have re-synced INTO it") is that after re-sync the balance equals its
     post-transaction value. That snapshot has to be taken between the transaction landing and the
     rollback, and getting the point wrong turns a never-passing assertion into a wrongly-passing
     one, which is worse. Whoever fixes it should also assert the enclave side on this branch --
     re-syncing the CHAIN back into the block says nothing about whether the ENCLAVE followed.

     `run_regression_continually.sh` now auto-skips this test when the node has peers. That is a
     STOPGAP so the loop stops reporting a red suite, not a fix: while it is skipped, the networked
     rollback path is untested on the only topology it exists for.

102. test_enclave_crash_recovery's PROMPTNESS bound asserts more than the system guarantees

     `[ "$advanced" -le 5 ]` (testscripts/test_enclave_crash_recovery.sh:104) fails intermittently on
     the 4-validator ARM fleet. Observed over 119 archived runs on M1:

         run  64  advanced=6   FAIL
         run  66  advanced=10  FAIL
         run  67  advanced=6   FAIL
         (2026-08-21, last recorded pass)  advanced=5  PASS -- exactly at the ceiling

     THE SAFETY PROPERTY NEVER FAILED. Line 100 -- "chain is STILL ADVANCING against a stalled
     enclave ... the fork-instead-of-halt bug is back" -- passed in every one of these runs. The
     chain froze rather than committing enclave-less blocks each time; only the bound on HOW SOON
     it froze was exceeded. Reading these as a halt regression would be wrong.

     TWO EXPLANATIONS CHECKED AND DISPROVEN, so whoever picks this up does not repeat them:
     - NOT faster blocks shortening the fixed detection window. The detection loop sleeps 2s and
       needs two consecutive equal heights, so its slop is fixed in WALL CLOCK and converts to more
       blocks if blocks speed up. Measured: 2.12s/block at the passing run (h~35150) versus
       2.28s/block at the failures (h~67900). Essentially unchanged, and slightly SLOWER.
     - NOT the `header.Height%11` UpdateHeight cadence gating when a call first blocks. Distance
       from the stall height to the next multiple of 11 was 8, 1, 4, 9 for advanced = 5, 6, 10, 6.
       No correlation.

     So the source of the variance is not yet established, and four samples is not enough to find
     it. WHAT IS NEEDED FIRST IS DATA: the per-suite logs are only archived for FAILING runs, so
     the distribution of `advanced` across passing runs does not exist and could not be recovered
     when this was investigated. Retain that number per run -- then the ceiling can be set from a
     real distribution instead of a guess.

     DO NOT simply raise the constant to make the red go away. The bound exists to distinguish
     "halted promptly, as designed" from "wandered on for dozens of blocks and stopped for some
     unrelated reason", and a ceiling loosened to fit unexplained variance stops making that
     distinction. Either explain the variance and set the bound from it, or split the assertion so
     the safety property (froze, did not fork) reports separately from the promptness bound -- the
     first is the one that must stay loud.
