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
