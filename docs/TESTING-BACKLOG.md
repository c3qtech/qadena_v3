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

76. **The credential-update cool-down is not reliably enforced -- and the broken test assertion was
    hiding it.**  `update_credential_min_blocks_between_updates = 10000` on the chain, yet al's
    SECOND hash-changing update was committed three blocks after the first:

        h=11713  code=0  MsgUpdateCredential     (case 1, correction -- expected)
        h=11716  code=0  MsgUpdateCredential     (case 9, rate limit -- MUST have been refused)

    `code=0` is the delivered result, so the enclave accepted it and the state changed; this is not
    a reporting artefact.  `checkUpdateLimits` (cmd/qadenad_enclave/enclave_update_credential.go:541)
    reads correctly, `BlockHeight` is populated by the keeper (`sdkctx.BlockHeight()`), and the
    history is keyed by `msg.CredentialID`, which line 139 pins to the wallet's own credential -- so
    the key is stable across both updates and the lookup SHOULD have found LastUpdateHeight=11713.
    Prime suspect is the `!found` path at line 198-201 ("seeded identity history for ..."), which
    starts a fresh record with LastUpdateHeight=0 and therefore disables the cool-down entirely.
    That line is Debug, so confirming it needs a run at debug level.

    NOT ALWAYS: two historical cycles reached case 14 with no credentials failure, so the limit did
    fire in those runs.  Intermittent enforcement of a rate limit is worse than none, because a
    passing test proves nothing.  Note the enclave is not consulted during CheckTx
    (`EnclaveClientUpdateCredential` returns early on `IsCheckTx`), so an update rejection can only
    ever surface in execution or in `--gas auto` SIMULATION -- which is the likely source of the
    variance, and is worth confirming.

    WHY THIS WAS INVISIBLE: the suite aborted at case 7 (anti-squat) in 10 of the 12 most recent
    failed cycles, on the exit-code bug fixed in e487b05c, so cases 8-14 never ran.  Fixing the
    assertion did not create this failure -- it revealed it.  A test that fails for a bogus reason
    does not merely waste time; it stops before the assertions that would have caught something real.

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
