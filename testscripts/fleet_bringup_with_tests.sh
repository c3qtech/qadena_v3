#!/bin/zsh
# Bring up a fleet and run WHAT YOU ASK FOR, WHERE YOU ASK FOR IT.  Nothing is tested by default.
#
# THE ONLY FLEET BRINGUP.  It replaced full_fleet_bringup.sh, which ran a fixed order -- build,
# regression, package, install, soak, join -- and could express none of what is scheduled here.
# Everything that script did is a schedule this one accepts: its regression is a --test before the
# first --joiner, its soak is a --test last.  Its two behaviours that are NOT reproducible here were
# the reasons it went:
#   - it started the soak BEFORE the joins, and the soak and the joins both spend from the treasury.
#     That is an account-sequence collision, and it failed a real run mid-join ("expected 143, got
#     142") after surviving the two joins before it.  The soak may only be scheduled LAST here.
#   - it joined --until 5, leaving joiners unbonded.  An unbonded node never proposes, so it never
#     publishes an external address, is never addressable, never becomes an SS key owner, and is
#     invisible to the re-share audit -- and phase 7's peer agreement never ran at all.
#
# The question it answers: "what happens to the chain AS THE FLEET GROWS?"  That needs tests
# interleaved between joins rather than bracketing them, and it needs the operator to choose which.
#
#   ./fleet_bringup_with_tests.sh --primary m1 --joiner m2 --joiner m3 --joiner m4 \
#       --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
#       --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
#       --test "./testscripts/run_regression_continually.sh --skip enclave-crash"
#
# runs as:  primary up -> test -> package -> install -> m2 -> test -> m3 -> test -> m4 -> test -> soak
#
# ---------------------------------------------------------------------------------------------
# WHY THIS SHAPE: THE CLEAN-CHAIN GROWTH TEST (TESTING-BACKLOG item 107).
#
# The re-share audit heals SS interval keys that were minted when the fleet was SMALLER than it is
# now.  A fleet that arrives all at once never produces that case: on M1-M4 every node joined inside
# the first rotation interval, so almost every key was minted with all four pioneers already
# addressable, and the audit had nothing real to heal.  A fleet already at its target teaches
# nothing about growth.
#
# Forcing rotations BETWEEN joins is what manufactures the interesting state -- keys minted at 1
# owner, then 2, then 3 -- so the audit has genuine work and the threshold crossing (1 -> 2, where
# shamir.Split runs for the first time) actually happens.
#
# "WAIT UNTIL ADDRESSABLE" IS LOAD-BEARING, and is why a joiner's --test does not simply run when the
# join returns.  A joined node is INVISIBLE to the audit until updateIsValidator publishes its
# external address, and that happens on its FIRST PROPOSED BLOCK AFTER BONDING -- not when it joins.
# Rotating before then mints a key that silently excludes the node you just added, and the test then
# measures the wrong thing while looking like it worked.
#
# ---------------------------------------------------------------------------------------------
# NOTHING RUNS BY DEFAULT, and that is deliberate -- the bringup it replaced always ran a fixed
# regression and always left a soak.  No regression, no soak, no enclave upgrade unless a --test
# asks for it.  A bringup that quietly
# tested nothing is worse than one that tested nothing loudly, so the summary names what ran.
#
# WHERE THEY RUN: on the PRIMARY, always.  The scheduled commands are chain-level tests; the primary
# is the node with the keyring, the treasury and the enclave that can force a rotation.
#
# A FAILED SCHEDULED COMMAND HALTS THE RUN: nothing is packaged, installed or joined off a failure.
#
# ORDER GUARDS.  Two commands cannot go just anywhere, and the script refuses rather than letting a
# run produce a misleading result:
#   - run_regression_continually.sh only as the LAST --test.  It never exits, so anywhere else it would
#     either block the run forever or share the chain with the next suite -- they contend for ann,
#     pioneer1 and the treasury, and the collisions read as chain bugs.
#   - --test-fleet-upgrade only AFTER the last --joiner.  It rolls a new measurement to the nodes
#     that exist when it runs, so a joiner added afterwards would be installed from the stage-D
#     package -- which measures the OLD enclave -- and the chain would refuse it.
#
# Everything else -- the ordering traps, the login-shell build path, ssh -f, the height-advancing
# health gate -- lives in fleet_lib.sh and is documented there.  Read it before changing anything
# here.

set -u

SCRIPT_DIR="${0:A:h}"
# Captured before the parser consumes them, so the run directory records what was actually asked
# for.  Reconstructing it afterwards from the variables loses every default that was not overridden.
INVOCATION="$0 $*"

PRIMARY=""
JOINERS=()
REF="main"
BUILD_SGX="auto"           # auto | yes | no
PIONEER_PREFIX="pioneer"
SNAP_INTERVAL=2000
SNAP_WAIT_MIN=120
RUN_DIR=""
# THE SCHEDULE IS THE COMMAND LINE, IN ORDER.  --test attaches to whatever node preceded it, so
# what you type is what runs:  --primary m1 --test A --joiner m2 --test B  ==  m1, A, m2, B.
# Entries are tagged strings because zsh has no nested arrays; the tag is everything before the
# first colon.  Kept as ONE list rather than per-node lists so the order can never be reconstructed
# wrongly -- there is nothing to reconstruct.
SCHEDULE=()
ADDRESSABLE_WAIT_MIN=20
BLOCK_SYNC=0
# TOLL-FREE JOINS.  With --foundation-sponsored no joiner is ever sent coins: each one gets a
# bounded, recurring fee grant instead, and joins with no balance and no treasury of its own.
# Passed straight through to nth_node_bringup.sh, which does the work in its phases 3 and 4.
SPONSORED=0
SPONSOR_GRANTER="treasury"
# UNSPONSORED funder, passed through to nth_node_bringup.sh.  `treasury` is the devnet's
# do-everything key and does not exist on a launch-config chain -- name a key the PRIMARY holds.
FUNDER="treasury"
# WHICH CHAIN THE FLEET RUNS.  Empty = the DEVNET (config/config.yml), which every SS and
# regression suite here is written against.  --mainnet-source builds a LAUNCH-shaped chain from a
# rendered instance instead; see the note above the joiner loop for what that costs.
MAINNET_SRC=""
MNEMONIC_FILE=""
# Passed through to nth_node_bringup.sh.  Empty means "use its defaults", which are DEVNET-sized.
FUND_QDN_ARG=""
STAKE_ARG=""
# --from <stage>.  The sub-scripts have been phase-addressable all along; the fleet script was not,
# so a failure at stage C meant redoing a ~24-minute SGX build that had already succeeded and whose
# artifacts were still installed and healthy.  See TESTING-BACKLOG.md item 89.
FROM_STAGE="A0"
# Set in stage D, but read in E and in the summary -- so a resume that skips D must still be able
# to answer "what is the primary running?".  Resolved lazily from the binary rather than carried.
PRIM_UID=""
STAGE_ORDER=(A0 A B C D E F G)

# Helpers, and the traps they encode, live in ONE place -- fleet_bringup_with_tests.sh drives the
# same machines the same way and must not carry a second copy that can drift.  See fleet_lib.sh.
FLEET_NAME="${0:t:r}"
source "$SCRIPT_DIR/fleet_lib.sh"

# SYNCHRONOUS, because the exit status IS the verdict.  rsh_build_detached exists for things that
# outlive the run (the soak); a scheduled test has to be waited on, and ssh -f throws the status
# away.  Trap 4 still applies: login bash with the toolchain path, or a build failure reports
# itself as an enclave error.
rsh_build() {   # host, command...
    local host="$1"; shift
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" \
        "cd \$HOME/qv3 && bash -lc $(printf '%q' "$BUILD_PATH $*")"
}

# A joined node is INVISIBLE to the re-share audit until updateIsValidator publishes its external
# address, and that happens on its FIRST PROPOSED BLOCK AFTER BONDING -- not when the join returns.
# Rotating before then mints a key that silently excludes the node just added, and the growth test
# then measures the wrong fleet size while looking like it worked.  TESTING-BACKLOG item 107.
wait_addressable() {   # host, expected-count
    local host="$1" want="$2" i=0 n="" blind=0
    while (( i < ADDRESSABLE_WAIT_MIN )); do
        # FULL PATH, NOT A BARE `qadenad`.  rsh_user runs `zsh -lc`, and on these boxes the node's
        # bin is not on a zsh login PATH -- `which qadenad` says NOT-ON-PATH.  A bare name therefore
        # produced EMPTY output, which this loop read as "not addressable yet" and sat on for the
        # full twenty minutes before failing, on a fleet where the count was already 2.  Same trap
        # as the login-shell build path in fleet_lib.sh, one layer down.
        n=$(rsh_user "$host" '$HOME/qadena/bin/qadenad --home $HOME/qadena q qadena list-interval-public-key-id --limit 5000 -o json 2>/dev/null | jq "[.intervalPublicKeyID[]? | select(.nodeType==\"pioneer\" and .externalIPAddress!=\"\")] | length"' 2>/dev/null | tr -d "[:space:]")
        if [[ "$n" == <-> ]]; then
            blind=0
            (( n >= want )) && { info "addressable pioneers: $n (>= $want)"; return 0 }
            (( i % 2 == 0 )) && info "addressable pioneers: $n, want $want -- waiting"
        else
            # A QUERY THAT WILL NOT ANSWER IS NOT A NODE THAT IS NOT READY.  Three unreadable polls
            # in a row means the command is wrong or the RPC is down, and waiting out the remaining
            # nineteen minutes teaches nothing -- which is exactly what happened when the path was
            # wrong.  Fail on the real reason instead.
            (( blind++ ))
            (( blind >= 3 )) && fail "could not read the addressable-pioneer count on $host three times running (got \"${n}\"). The query is broken or the RPC is down -- this is not a node that is merely slow to bond."
        fi
        sleep 60; (( i++ ))
    done
    fail "only ${n:-?} addressable pioneers after ${ADDRESSABLE_WAIT_MIN}m, expected $want. The audit cannot see a node that has not proposed a block since bonding, so a rotation now would mint a key that excludes it."
}

# Every scheduled command runs HERE: on the primary, synchronously, output mirrored into the run
# directory, and a non-zero status halts the run.  Nothing is packaged, installed or joined off a
# failed test.
run_scheduled() {   # slot-label, log-tag, command
    local slot="$1" tag="$2" cmd="$3" log="$RUN_DIR/$tag.log"
    info ""
    info "[$slot] $cmd"
    note "$slot: $cmd"
    # ${pipestatus[1]}, NOT the pipeline's status.  A pipeline exits with its LAST command's status,
    # which here is tee -- and tee always succeeds.  So `if cmd | tee log; then` reported EVERY
    # scheduled test as passed, including one that printed FAILED and exited 1, and the halt-on-
    # failure guarantee this whole script advertises never once held.  Observed on the growth run:
    # the audit failed with 3 keys short and the driver logged "[after pioneer3 #1] passed" and
    # carried on joining nodes off a red test.
    rsh_build "$PRIMARY" "$cmd" 2>&1 | tee "$log"
    if (( ${pipestatus[1]} == 0 )); then
        info "[$slot] passed"
        note "$slot: passed"
    else
        tail -30 "$log" | while read -r l; do info "$l"; done
        fail "[$slot] FAILED (exit ${pipestatus[1]}): $cmd -- see $log"
    fi
    assert_advancing "$PRIMARY" "[$slot] after $cmd"
}

# ONE ENTRY POINT for every scheduled --test, so the sync/detached decision is made in exactly one
# place.  The soak is the only thing that runs detached, because it is the only thing that never
# exits -- and the guard above has already proved it is last, so nothing follows it to contend with.
run_test_entry() {   # slot-label, log-tag, command
    local slot="$1" tag="$2" cmd="$3" rlog
    if [[ "$cmd" == *run_regression_continually* ]]; then
        rlog="\$HOME/${tag}.log"
        info ""
        info "[$slot] $cmd   (detached -- it never exits)"
        note "$slot: $cmd (detached)"
        rsh_build_detached "$PRIMARY" "$rlog" "$cmd" || fail "[$slot] could not launch: $cmd"
        sleep 10
        n=$(rsh_user "$PRIMARY" 'pgrep -f "run_regression_continuall[y]" | wc -l' | tr -d "[:space:]")
        [[ "$n" != "0" ]] || fail "[$slot] the soak did not start; see $rlog on $PRIMARY"
        sync_log "$PRIMARY" "$rlog" "$tag.log"
        info "[$slot] running; mirrored to $RUN_DIR/$tag.log"
        assert_advancing "$PRIMARY" "[$slot] after launch"
    else
        run_scheduled "$slot" "$tag" "$cmd"
    fi
}


# EVERY DRIVER-SIDE ENTRY GOES THROUGH HERE, so --test-local and --test-fleet-upgrade cannot drift
# apart in how they are run, logged or judged.  $1 slot label, $2 log tag, rest the command.
run_local_entry() {   # slot, tag, command...
    local slot="$1" tag="$2"; shift 2
    local log="$RUN_DIR/$tag.log"
    info ""
    info "[$slot] (here, not on the primary) $*"
    note "$slot: $*"
    "$@" 2>&1 | tee "$log"
    if (( ${pipestatus[1]} == 0 )); then
        info "[$slot] passed"
        note "$slot: passed"
    else
        tail -30 "$log" | while read -r l; do info "$l"; done
        fail "[$slot] FAILED -- see $log"
    fi
    assert_advancing "$PRIMARY" "[$slot] after it"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary)       PRIMARY="$2"; shift 2 ;;
        --joiner)        JOINERS+=("$2"); SCHEDULE+=("joiner:$2"); shift 2 ;;
        --test)          SCHEDULE+=("test:$2"); shift 2 ;;
        # RUNS HERE, NOT ON THE PRIMARY.  --test is defined as "on the primary" (run_scheduled ->
        # rsh_build "$PRIMARY"), which is right for chain-level tests and wrong for anything that
        # has to reach the whole fleet: the primary cannot ssh to the joiners.
        --test-local)    SCHEDULE+=("local:$2"); shift 2 ;;
        # Sugar for --test-local of test_fleet_upgrade.sh.  It stays a flag of its own because the
        # upgrade needs the FLEET MEMBERSHIP, which this script already knows -- spelled as a
        # --test-local string you would retype --primary/--joiner and the two lists could drift,
        # silently upgrading a different set of nodes than the run built.
        --test-fleet-upgrade) SCHEDULE+=("upgrade:"); shift ;;
        --ref)           REF="$2"; shift 2 ;;
        --build-sgx)     BUILD_SGX="yes"; shift ;;
        --no-build-sgx)  BUILD_SGX="no"; shift ;;
        --pioneer-prefix) PIONEER_PREFIX="$2"; shift 2 ;;
        --snapshot-interval) SNAP_INTERVAL="$2"; shift 2 ;;
        --addressable-wait) ADDRESSABLE_WAIT_MIN="$2"; shift 2 ;;
        --skip-regression|--no-loop|--after-primary|--after-join|--at-end)
            print -u2 "FAIL: $1 does not exist here -- nothing runs by default, and tests are"
            print -u2 "      scheduled positionally with --test:"
            print -u2 "        --primary m1 --test \"./testscripts/regression.sh\" \\"
            print -u2 "        --joiner m2 --test \"./testscripts/test_ss_key_rotation.sh --key-added-only\" \\"
            print -u2 "        --joiner m3 --test \"./testscripts/run_regression_continually.sh\""
            exit 1 ;;
        --block-sync)    BLOCK_SYNC=1; shift ;;
        --funder)        FUNDER="$2"; shift 2 ;;
        --mainnet-source) MAINNET_SRC="$2"; shift 2 ;;
        --fund-qdn)      FUND_QDN_ARG="$2"; shift 2 ;;
        --stake)         STAKE_ARG="$2"; shift 2 ;;
        --pioneer-mnemonic-file) MNEMONIC_FILE="$2"; shift 2 ;;
        --foundation-sponsored)
            SPONSORED=1
            if [[ -n "$2" && "$2" != --* ]]; then SPONSOR_GRANTER="$2"; shift 2; else shift; fi ;;
        --cosmovisor)    shift ;;   # accepted and ignored: every node is cosmovisor-managed now
        --from)          FROM_STAGE="${2:u}"; shift 2 ;;
        --run-dir)       RUN_DIR="$2"; shift 2 ;;
        --help)
            print "Usage: fleet_bringup_with_tests.sh --primary <[user@]host> [--joiner <[user@]host>]..."
            print "                             [--run-dir <dir>] [--ref <git-ref>]"
            print "                             [--build-sgx | --no-build-sgx] [--pioneer-prefix <n>]"
            print "                             [--snapshot-interval N] [--addressable-wait MIN]"
            print "                             [--test <cmd>]... [--test-local <cmd>]... [--test-fleet-upgrade]"
            print "                             [--block-sync] [--from <stage>]"
            print ""
            print "  --joiner            REPEATABLE.  Joiners are installed and joined serially."
            print "                      With none given, the primary is built and tested alone."
            print "  --run-dir           where every log for this run is collected on THIS machine."
            print "                      Default ~/qadena-fleet-runs/<timestamp>, plus a 'latest'"
            print "                      symlink.  Remote logs are pulled in as the run proceeds."
            print "  --build-sgx         force a reproducible SGX build (refused without devices)."
            print "  --no-build-sgx      force a DEBUG enclave even on SGX hardware -- skips the"
            print "                      ~24-minute docker build when only logic is being tested."
            print "                      NEITHER IS NORMALLY NEEDED: hosts are probed, and the same"
            print "                      command line works on an SGX fleet and an ARM/debug one."
            print "  --test <cmd>        REPEATABLE, POSITIONAL.  Runs <cmd> ON THE PRIMARY after"
            print "                      whichever node preceded it on the command line.  The"
            print "                      schedule IS the command line:"
            print ""
            print "                        --primary m1 --test A --joiner m2 --test B --joiner m3 --test C"
            print ""
            print "                      runs  m1, A, m2, B, m3, C.  A failure halts the run."
            print "                      After a --joiner, the test waits until that node is"
            print "                      ADDRESSABLE -- not merely joined.  A node is invisible to"
            print "                      the re-share audit until it proposes a block after"
            print "                      bonding, and rotating before then mints a key that"
            print "                      silently excludes it (TESTING-BACKLOG 107)."
            print "                      run_regression_continually.sh must be the LAST --test; it"
            print "                      never exits, so it runs detached and nothing may follow."
            print "  --test-local <cmd>  REPEATABLE, POSITIONAL.  Like --test, but runs the command"
            print "                      HERE (this workstation) instead of on the primary.  For"
            print "                      anything that must reach the whole fleet: --test commands"
            print "                      run on the primary, and the primary cannot ssh to the"
            print "                      joiners.  Same ordering rules and same halt-on-failure."
            print "  --test-fleet-upgrade  POSITIONAL.  Bumps the enclave identity and both versions"
            print "                      on the primary and rolls the release to EVERY node by"
            print "                      governance, then asserts each one swapped and that the"
            print "                      sealed keys survived.  Must come after every --joiner: a"
            print "                      node joining afterwards would be installed from a package"
            print "                      measuring the OLD enclave and the chain would refuse it."
            print "                      Runs from HERE, not on the primary -- it has to reach"
            print "                      every node, and the primary cannot ssh to them."
            print "  --addressable-wait  minutes to wait for a joiner to become addressable (20)."
            print "  --from <stage>      resume at a stage (A0 A B C D E F G H) instead of the top."
            print "                      For recovering from a late failure without repeating work"
            print "                      that already succeeded -- an SGX build is ~24 minutes, and"
            print "                      a flake at stage C should not cost it.  --from D or later"
            print "                      SKIPS THE REGRESSION and says so; stepping over that guard"
            print "                      should be a deliberate act, never a quiet one."
            print "  --mainnet-source <file> / --pioneer-mnemonic-file <file>"
            print "                      build a LAUNCH chain instead of the devnet.  The joins"
            print "                      then need --funder naming a key the PRIMARY holds (a"
            print "                      launch chain has no 'treasury'), and a SPONSORED join"
            print "                      from a bucket multisig cannot run unattended at all --"
            print "                      see docs/HOWTO-TEST-FLEET-BRINGUP.md."
            print "  --fund-qdn <qdn> / --stake <qdn>"
            print "                      passed to nth_node_bringup.  Its defaults (200000 fund,"
            print "                      110000 stake) are DEVNET figures and exceed what a launch"
            print "                      chain's funder holds -- set both there."
            print "  --funder <key>      UNSPONSORED joins: the key on the primary that sends"
            print "                      joiners their coins (default: treasury, which a"
            print "                      launch-config chain does NOT have)."
            print "  --foundation-sponsored [<granter-key>]"
            print "                      TOLL-FREE JOINS.  No joiner is sent coins and none holds a"
            print "                      treasury of its own: each gets a bounded, recurring FEE GRANT"
            print "                      from <granter-key> (default: treasury, the key the primary"
            print "                      already holds).  The grant covers the five messages a node"
            print "                      broadcasts for life -- join, SS rotation and SS re-share --"
            print "                      so a sponsored node keeps working, not just joining."
            print "                      Validator self-bonds are NOT sponsored; --stake is unaffected."
            print ""
            print "  --block-sync        join by BLOCK-SYNC, skipping the wait for state-sync to"
            print "                      become eligible (~50 min for 2000 blocks at 1.5s).  Use it"
            print "                      when the point is to HAVE a second node quickly.  It is NOT"
            print "                      the same test: state-sync seeds the joiner's enclave store"
            print "                      from a snapshot, and a block-synced joiner never exercises"
            print "                      that path -- so the default stays state-sync."
            print ""
            print "  A0 preflight EVERY host -- nothing is stopped or moved until all of them pass"
            print "  A  stop any suite on the primary; archive each joiner's old ~/qadena"
            print "  B  1st_node_bringup phases 1-6: build, init, start the primary"
            print "  C  --test commands scheduled before the first --joiner"
            print "  D  1st_node_bringup phase 7: package what is actually running"
            print "  E  1st_node_bringup phase 8 per joiner: install that package"
            print "  F  wait for height past the snapshot interval and a snapshot on disk"
            print "  G  join each joiner in turn; after each, wait until it is addressable,"
            print "     then run the --test commands that follow it on the command line"
            print ""
            print "  Nothing is tested unless a --test asks for it.  For the"
            print "  clean-chain growth test that exercises the re-share audit, see item 107 in"
            print "  docs/TESTING-BACKLOG.md and the header of this script."
            exit 0 ;;
        *) print -u2 "unknown option $1"; exit 1 ;;
    esac
done

[[ -n "$PRIMARY" ]] || { print -u2 "FAIL: --primary is required"; exit 1 }

# THE ORDER IS THE POINT here too -- see the header.  Refusing beats producing a result that looks
# fine and measured the wrong thing.  Both guards are expressible directly on the schedule now,
# because the schedule IS the order.
_n=${#SCHEDULE[@]}
_i=0
_seen_joiner=0
for e in "${SCHEDULE[@]}"; do
    (( _i++ ))
    case "$e" in
        joiner:*) _seen_joiner=1 ;;
        upgrade:*)
            # AFTER EVERY JOINER.  The upgrade rolls the release to the nodes that exist WHEN IT
            # RUNS; a joiner added afterwards would be installed from the stage-D package, which
            # measures the OLD enclave, and its join would be refused against the upgraded chain.
            _rest=0
            for _f in "${SCHEDULE[@]:$_i}"; do [[ "$_f" == joiner:* ]] && (( _rest++ )); done
            (( _rest == 0 )) || {
                print -u2 "FAIL: --test-fleet-upgrade must come after every --joiner: $_rest joiner(s)"
                print -u2 "      still follow it.  Rolling before they join would install them from a"
                print -u2 "      package that measures the OLD enclave, and the chain would refuse them."
                exit 1 }
            ;;
        test:*|local:*)
            _cmd="${e#*:}"
            # A driver-side entry that IS the fleet upgrade obeys the upgrade rule above.
            [[ "$e" == local:* && "$_cmd" == *test_fleet_upgrade* ]] && {
                _rest=0
                for _f in "${SCHEDULE[@]:$_i}"; do [[ "$_f" == joiner:* ]] && (( _rest++ )); done
                (( _rest == 0 )) || {
                    print -u2 "FAIL: test_fleet_upgrade.sh must come after every --joiner: $_rest joiner(s)"
                    print -u2 "      still follow it.  Rolling before they join would install them from a"
                    print -u2 "      package that measures the OLD enclave, and the chain would refuse them."
                    exit 1 } }
            # The soak never exits.  Anywhere but last it blocks the run, or shares the chain with
            # whatever is scheduled next -- they contend for ann,
            # pioneer1 and the treasury, and the collisions read as chain bugs.
            [[ "$_cmd" == *run_regression_continually* ]] && (( _i != _n )) && {
                print -u2 "FAIL: run_regression_continually.sh never exits, so it must be the LAST"
                print -u2 "      --test on the command line.  It is currently entry $_i of $_n."
                exit 1 }
            # CAUGHT HERE RATHER THAN HALFWAY THROUGH A BRINGUP.  regression.sh refuses this flag
            # too, but by then a build and a genesis wipe have already happened.
            [[ "$_cmd" == *--with-enclave-upgrade* ]] && {
                print -u2 "FAIL: regression.sh --with-enclave-upgrade no longer exists -- the live-swap"
                print -u2 "      upgrade it drove was retired (ab839b3c), and an enclave change is a"
                print -u2 "      governance plan across the whole fleet now.  Use --test-fleet-upgrade,"
                print -u2 "      scheduled after the last --joiner."
                exit 1 }
            ;;
    esac
done
unset _n _i _seen_joiner _cmd

# ---------------------------------------------------------------------------------------------
# ONE DIRECTORY FOR THE WHOLE RUN.  Everything this script prints, everything the sub-scripts print,
# and a periodically-refreshed copy of each remote log, so the run can be watched from here without
# an ssh session per node.
STAMP=$(date +%Y%m%d-%H%M%S)
[[ -n "$RUN_DIR" ]] || RUN_DIR="$HOME/qadena-fleet-runs/$STAMP"
mkdir -p "$RUN_DIR" || { print -u2 "FAIL: could not create $RUN_DIR"; exit 1 }
ln -sfn "$RUN_DIR" "${RUN_DIR:h}/latest" 2>/dev/null

STATUS="$RUN_DIR/status.txt"

# Everything from here on is teed into the run directory as well as the terminal.
exec > >(tee -a "$RUN_DIR/run.log") 2>&1

note "run started: $INVOCATION"


# run_stage <letter> -- true once we have reached --from.  Stages are letters rather than numbers
# because they are named that way everywhere else (logs, --help, the run directory).
FROM_INDEX=$(stage_index "$FROM_STAGE") \
    || { print -u2 "FAIL: --from takes one of ${STAGE_ORDER[*]}, got \"$FROM_STAGE\""; exit 1 }

# RESUMING PAST A RED REGRESSION IS A DELIBERATE ACT.  --from D or later skips stage C entirely, so
# say so out loud: the guard that refuses to package off a failed suite is the point of this script,
# and stepping over it should never be quiet.
if [[ $FROM_INDEX -gt $(stage_index C) ]]; then
    print "  NOTE: --from $FROM_STAGE skips the regression (stage C).  Nothing will re-verify this"
    print "        chain before packaging and joining -- make sure you know why the last run stopped."
fi

# Trap 4: builds go through a LOGIN bash with the toolchain path prepended.  zsh -lc is not enough
# when the target's login shell is bash -- go is then absent and the failure names the enclave.

# Pull a remote log into the run directory.  Cheap, and it is what makes one-directory monitoring
# real rather than a claim -- the local copy is never more than a poll interval behind.

# Trap 7: the height must ADVANCE.  Processes being up says nothing -- a halted two-validator chain
# looks perfectly healthy from ps.

# Same probe 1st_node_bringup uses: 0 = SGX usable, 1 = SGX present, needs root, 2 = no SGX.

# READ THE MEASUREMENT FROM THE BINARY, TWO WAYS.  ego computes it on SGX; on ARM (no ego at all)
# and on debug builds the identity IS the embedded string.  Never `qadenad_enclave --unique-id` on
# SGX: it returns the embedded debug placeholder, which does not describe a signed enclave.

rsh_user "$PRIMARY" 'print $HOME' >/dev/null 2>&1 || fail "cannot ssh to $PRIMARY"
for j in "${JOINERS[@]}"; do
    rsh_user "$j" 'print $HOME' >/dev/null 2>&1 || fail "cannot ssh to joiner $j"
done
PHOME=$(rsh_user "$PRIMARY" 'print $HOME' | tr -d '\r')

# DECIDE THE BUILD KIND ON EVIDENCE.  The operator does not have to know what this hardware is.
PSTATE=$(sgx_state "$PRIMARY")
[[ "$PSTATE" == <-> ]] || fail "could not probe SGX state on $PRIMARY"
# ego is what build.sh actually keys on -- see the auto branch below.
PRIMARY_HAS_EGO=0
rsh_user "$PRIMARY" 'command -v ego >/dev/null 2>&1' && PRIMARY_HAS_EGO=1
case "$BUILD_SGX" in
    # THE BUILD KEYS ON ego, THE RUNTIME KEYS ON THE DEVICES, and they are not the same question.
    # This used to decide purely on devices, which is wrong in one direction that matters: a box with
    # ego but no /dev/sgx_* was called "debug" here while build.sh went on to build SGX anyway,
    # because ego is a BUILD dependency and needs no device.  Report what will actually be built.
    auto) if (( PRIMARY_HAS_EGO )); then
              if [[ "$PSTATE" == 2 ]]; then
                  # Can build SGX, cannot run it.  Do not pass --build-sgx (phase 1 would refuse on
                  # the missing devices) and do not claim debug either -- build.sh's default still
                  # produces a signed enclave this host cannot load.
                  SGX_FLAG=""; KIND="SGX (ego present, but NO devices -- see the warning below)"
              else
                  SGX_FLAG="--build-sgx"; KIND="SGX (ego and devices present)"
              fi
          else
              SGX_FLAG=""; KIND="debug (no ego on the primary, so build.sh cannot build SGX)"
          fi ;;
    yes)  SGX_FLAG="--build-sgx"; KIND="SGX (forced)"
          [[ "$PSTATE" == 2 ]] && fail "--build-sgx but $PRIMARY has no SGX devices: that would be a debug enclave wearing an SGX label, and it could not attest"
          (( PRIMARY_HAS_EGO )) || fail "--build-sgx but $PRIMARY has no ego, which is what signs the enclave. Provision it (ubuntu/setup_qadena_build.sh) or drop the flag." ;;
    # MUST PASS --no-sgx, not merely omit --build-sgx.  Omitting it left build.sh to its default,
    # which is "ego installed means SGX" -- so on an Intel box this printed "debug (forced)" in the
    # run log and produced a SIGNED SGX BUILD.  A flag that reported the opposite of what it did,
    # in a script written to catch exactly that.  It only appeared to work on ARM, where there is no
    # ego for the default to key on.  See TESTING-BACKLOG.md item 90.
    no)   SGX_FLAG="--no-sgx"; KIND="debug (forced with --no-sgx)" ;;
esac

# The one combination that cannot work: an ego-signed enclave needs /dev/sgx_enclave to RUN, so an
# SGX build cannot be installed onto a joiner without the devices.  The reverse is fine.  Refused
# here, before a ~24-minute build, rather than at that joiner's first start.
if [[ -n "$SGX_FLAG" ]]; then
    for j in "${JOINERS[@]}"; do
        [[ $(sgx_state "$j") == 2 ]] \
            && fail "$j has no SGX devices but the primary builds an SGX enclave -- that binary cannot run there. Drop that joiner, provision its devices, or pass --no-build-sgx for a debug fleet."
    done
fi

# THE PACKAGE IS ARCHITECTURE-LOCKED, AND NOTHING IN IT SAYS SO.  It ships BOTH libwasmvm variants
# -- aarch64 and x86_64 -- which makes it look portable, but there is exactly one qadenad and one
# qadenad_enclave and they are the builder's architecture.  Neither the manifest nor install.sh
# checks, so a cross-arch install "succeeds" and fails later, naming a loader error rather than the
# mismatch.  An ARM rehearsal therefore validates the SEQUENCE and produces nothing reusable on an
# x86 fleet: that fleet must build its own package.
PARCH=$(rsh_user "$PRIMARY" 'uname -m' | tr -d '\r')
[[ -n "$PARCH" ]] || fail "could not read the primary's architecture"
for j in "${JOINERS[@]}"; do
    jarch=$(rsh_user "$j" 'uname -m' | tr -d '\r')
    [[ "$jarch" == "$PARCH" ]] \
        || fail "$j is $jarch but the primary is $PARCH. The package carries only the builder's binaries, so it cannot be installed there -- run a separate bringup with a $jarch primary for that group."
done
info "architecture  $PARCH (primary and all joiners agree)"

# The one configuration that builds something it cannot run.  Not fatal -- a build host is a real
# use for it -- but it must not be discovered when the node fails to start.
if (( PRIMARY_HAS_EGO )) && [[ "$PSTATE" == 2 && "$BUILD_SGX" == "auto" ]]; then
    info ""
    info "WARNING: $PRIMARY has ego but NO /dev/sgx_* devices."
    info "  build.sh defaults to SGX whenever ego is present, so this will produce a SIGNED enclave"
    info "  that this host cannot load -- the node will fail at startup, not at build time."
    info "  Pass --no-sgx for a debug fleet, or provision the SGX devices."
    info ""
fi

{
    print "run       $STAMP"
    print "primary   $PRIMARY"
    print "joiners   ${JOINERS[*]:-<none>}"
    print "ref       $REF"
    print "build     $KIND"
} > "$RUN_DIR/fleet.txt"

info "run dir       $RUN_DIR"
info "primary       $PRIMARY"
info "joiners       ${JOINERS[*]:-<none>}"
info "ref           $REF"
info "build         $KIND"
info "pioneers      ${PIONEER_PREFIX}2 .. ${PIONEER_PREFIX}$(( ${#JOINERS[@]} + 1 ))"

# ---------------------------------------------------------------------------------------------
if run_stage A0; then
stage "A0. preflight every host BEFORE anything is stopped or moved"
# NOTHING DESTRUCTIVE UNTIL EVERY CHEAP CHECK HAS PASSED ON EVERY HOST.  This stage used to be the
# archive below, which meant a joiner's ~/qadena was moved aside and THEN the primary turned out to
# be unbuildable -- on the first run of this script that cost a 1.2G tree moved for a run that died
# at stage B seconds later.  Delegating to 1st_node_bringup's own phase 1 keeps one definition of
# "can this machine do the job": toolchain presence AND version, checkout cleanliness, disk, SGX.
# See TESTING-BACKLOG.md item 85.
mainnet_args=()
[[ -n "$MAINNET_SRC" ]]   && mainnet_args+=(--mainnet-source "$MAINNET_SRC")
[[ -n "$MNEMONIC_FILE" ]] && mainnet_args+=(--pioneer-mnemonic-file "$MNEMONIC_FILE")
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --ref "$REF" $SGX_FLAG "${mainnet_args[@]}" --only 1 \
    2>&1 | tee "$RUN_DIR/stage-A0-preflight.log"
[[ ${pipestatus[1]} -eq 0 ]] || fail "the primary failed preflight; nothing has been changed on any host. See $RUN_DIR/stage-A0-preflight.log"

# The joiners do not build, so they need less -- but they DO need to be reachable, stoppable and
# have room for the install, and finding that out after the primary's 24-minute build is a waste.
for j in "${JOINERS[@]}"; do
    javail=$(rsh_user "$j" 'df --output=avail -BG $HOME | tail -1 | tr -dc "0-9"' | tr -d '\r')
    [[ -n "$javail" && "$javail" -ge 10 ]] \
        || info "WARNING: only ${javail:-?}G free on $j; an install plus a chain wants more"
done
info "all hosts preflighted"

# ---------------------------------------------------------------------------------------------
fi

if run_stage A; then
stage "A. quiesce the primary, then archive each joiner's previous install"
# STOP ANY SUITE STILL RUNNING ON THE PRIMARY BEFORE STAGE B WIPES IT.  init.sh REMOVES
# $QADENAHOME entirely, and a soak left running through that keeps issuing transactions against a
# chain that is being deleted and then rebuilt underneath it -- it does not stop, it just starts
# failing, and its failures then interleave with this run's scheduled tests (trap 3: they contend
# for ann, pioneer1 and the treasury, and the collisions read as chain bugs).
#
# BEFORE THE WIPE, deliberately.  Stopping the loop after stage B would be too late: this run must
# be clean from genesis for the growth test to mean anything.
n=$(rsh_user "$PRIMARY" 'pgrep -f "run_regression_continuall[y]" | wc -l' | tr -d '[:space:]')
if [[ "$n" != "0" ]]; then
    info "a continuous loop is running on the primary; stopping it by PID and draining the in-flight run"
    rsh_user "$PRIMARY" 'pkill -f "run_regression_continuall[y]"' >/dev/null 2>&1 || true
    i=0
    while (( i < 60 )); do
        r=$(rsh_user "$PRIMARY" 'pgrep -f "regression\.s[h]" | wc -l' | tr -d '[:space:]')
        [[ "$r" == "0" ]] && break
        sleep 30; (( i++ ))
    done
    (( i < 60 )) || fail "an in-flight regression run would not drain; stop it by PID and re-run"
    info "loop stopped and the chain is idle"
else
    # A bare regression with no loop above it still shares the chain, and still has to go.
    r=$(rsh_user "$PRIMARY" 'pgrep -f "regression\.s[h]" | wc -l' | tr -d '[:space:]')
    [[ "$r" == "0" ]] || fail "a regression is running on the primary with no loop driving it; stop it BY PID and re-run"
    info "no suite running on the primary"
fi

# Trap 6.  Moved aside, never deleted: the old keyring and chain data stay recoverable.
for j in "${JOINERS[@]}"; do
    jhome=$(rsh_user "$j" 'print $HOME' | tr -d '\r')
    if rsh_user "$j" "test -d $jhome/qadena"; then
        if rsh_user "$j" "test -x $jhome/qadena/scripts/stop_qadena.sh"; then
            ssh -o ConnectTimeout=10 -o BatchMode=yes "$j" \
                "sudo zsh -lc $(printf '%q' "$jhome/qadena/scripts/stop_qadena.sh --all")" >/dev/null 2>&1 || true
            sleep 3
        fi
        left=$(ssh -o ConnectTimeout=10 "$j" 'ps -eo pid,cmd | grep -E "qaden[a]d|cosmoviso[r] run|eg[o] run|ego-hos[t]|signer_enclav[e]" | grep -v grep | wc -l' | tr -d '\r')
        [[ "$left" == "0" ]] || fail "$j still has $left node/enclave process(es); kill them BY PID and re-run"
        rsh_user "$j" "mv $jhome/qadena $jhome/qadena.pre-bringup.$STAMP.bak" \
            || fail "could not archive $j's old ~/qadena"
        info "$j: archived to $jhome/qadena.pre-bringup.$STAMP.bak"
    else
        info "$j: no ~/qadena to archive"
    fi
done

# ---------------------------------------------------------------------------------------------
fi

if run_stage B; then
stage "B. 1st_node_bringup phases 1-6: build, init and start the primary"
# Stops at 6 deliberately.  Packaging is stage D, AFTER the regression has upgraded the enclave --
# see trap 1.  This is the fix for the sequence that failed on 2026-08-18.
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --ref "$REF" $SGX_FLAG "${mainnet_args[@]}" --from 1 --until 6 \
    2>&1 | tee "$RUN_DIR/stage-B-bringup.log"
[[ ${pipestatus[1]} -eq 0 ]] || fail "1st_node_bringup phases 1-6 failed; it is phase-resumable (--from N) once fixed. See $RUN_DIR/stage-B-bringup.log"
assert_advancing "$PRIMARY" "after bringup"

# ---------------------------------------------------------------------------------------------
fi

if run_stage C; then
stage "C. scheduled --test commands before the first joiner"
# Everything the operator put between --primary and the first --joiner runs here: the primary is up
# and nothing has been packaged yet, which is the only window in which an enclave upgrade can still
# reach the package in stage D.
C_COUNT=0
for e in "${SCHEDULE[@]}"; do
    [[ "$e" == joiner:* ]] && break
    case "$e" in
        test:*)  (( C_COUNT++ ))
                 run_test_entry "primary $C_COUNT" "stage-C-primary-$C_COUNT" "${e#test:}" ;;
        local:*) (( C_COUNT++ ))
                 run_local_entry "primary $C_COUNT" "stage-C-local-$C_COUNT" ${=${e#local:}} ;;
        *)       continue ;;
    esac
done
if (( C_COUNT == 0 )); then
    info "none scheduled.  NOTHING HAS PROVED THIS CHAIN WORKS, and with no enclave upgrade here"
    info "stage D packages the build from stage B."
fi

# ---------------------------------------------------------------------------------------------
fi

if run_stage D; then
stage "D. package what is actually running on the primary"
# Trap 1 and 2: this packages the INSTALLED artifacts, which after the upgrade are the new enclave.
# It does not rebuild -- a rebuild here would silently produce the PRE-upgrade identity, because the
# upgrade suite restores the embedded id files on exit.
"$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --only 7 \
    2>&1 | tee "$RUN_DIR/stage-D-package.log"
[[ ${pipestatus[1]} -eq 0 ]] || fail "packaging failed; see $RUN_DIR/stage-D-package.log"

PRIM_UID=$(measurement_of "$PRIMARY")
[[ -n "$PRIM_UID" ]] || fail "could not read the primary's enclave measurement"
info "primary now runs: $PRIM_UID"
print "primary measurement: $PRIM_UID" >> "$RUN_DIR/fleet.txt"

# ---------------------------------------------------------------------------------------------
fi

if run_stage E; then
stage "E. install that package on each joiner"
# RESUMING INTO THIS STAGE: stage D would normally have set PRIM_UID.  Read it from the binary now
# if we skipped D, so --from E verifies against what the primary is ACTUALLY running rather than
# failing on an unset variable -- or, worse, comparing against nothing.
if [[ -z "$PRIM_UID" ]]; then
    PRIM_UID=$(measurement_of "$PRIMARY")
    [[ -n "$PRIM_UID" ]] || fail "could not read the primary's enclave measurement"
    info "primary runs: $PRIM_UID (read now, since stage D was skipped)"
fi
for j in "${JOINERS[@]}"; do
    info ""
    info "installing on $j"
    "$SCRIPT_DIR/1st_node_bringup.sh" --primary "$PRIMARY" --joiner "$j" --only 8 \
        2>&1 | tee "$RUN_DIR/stage-E-install-${j##*@}.log"
    [[ ${pipestatus[1]} -eq 0 ]] || fail "install failed on $j; see $RUN_DIR/stage-E-install-${j##*@}.log"

    # VERIFY THE BINARY, not the installer's report.  install.sh has historically staged an enclave
    # and not switched to it on a node with no chain to ask about the identity, reporting success
    # while the old measurement stayed in place.
    juid=$(measurement_of "$j")
    [[ "$juid" == "$PRIM_UID" ]] \
        || fail "$j measures $juid but the primary runs $PRIM_UID -- nth_node_bringup phase 1 would refuse it. The package may predate an enclave upgrade."
    info "$j measures $juid -- matches the primary"
    print "$j measurement: $juid" >> "$RUN_DIR/fleet.txt"
done

# ---------------------------------------------------------------------------------------------
fi

if (( ${#JOINERS[@]} == 0 )); then
    print ""
    print "fleet_bringup_with_tests: done (primary only).  Logs: $RUN_DIR"
    note "done: primary only"
    exit 0
fi

# ---------------------------------------------------------------------------------------------
if run_stage F; then
if (( BLOCK_SYNC )); then
    stage "F. (skipped -- --block-sync needs no snapshot)"
    # Block-sync replays from genesis, so it has no precondition beyond a chain producing blocks.
    # That is the whole saving: no ~50-minute wait for the snapshot interval.  It is a DIFFERENT
    # test, not a faster one -- see the note in stage H.
    assert_advancing "$PRIMARY" "before joining"
else
stage "F. wait for height past $SNAP_INTERVAL and a snapshot on disk"
# state-sync has nothing to sync FROM until the primary has taken a snapshot, and the joiner's
# failure in that case names a trust height rather than a missing snapshot.
i=0; h=""; s=""
while (( i < SNAP_WAIT_MIN )); do
    out=$(rsh_user "$PRIMARY" 'h=$(curl -s --max-time 5 localhost:26657/status | jq -r ".result.sync_info.latest_block_height // empty"); s=$(find $HOME/qadena/data/snapshots -maxdepth 1 -type d -regex ".*/[0-9]+" 2>/dev/null | wc -l); echo "$h $s"' 2>/dev/null | tr -d '\r')
    h=${out%% *}; s=${out##* }
    [[ -n "$h" && "$h" -gt $(( SNAP_INTERVAL + 5 )) && "$s" -ge 1 ]] && { info "ready: height=$h snapshots=$s"; break }
    (( i % 5 == 0 )) && info "height ${h:-?}, snapshots ${s:-0} -- waiting"
    sleep 60; (( i++ ))
done
(( i < SNAP_WAIT_MIN )) || fail "no snapshot after $SNAP_WAIT_MIN minutes (height=${h:-?} snapshots=${s:-?})"
fi
fi

# ---------------------------------------------------------------------------------------------
if run_stage G; then
# ONE definition of which sync ran, resolved BEFORE the header prints and reused by the join below.
# The header used to say "state-sync" unconditionally, so a --block-sync run wrote a log that
# claimed coverage of the one path block-sync never touches -- and the run directory is the only
# record anyone reads afterwards.  Two strings that can disagree about what happened is one too many.
if (( BLOCK_SYNC )); then
    SYNC_KIND="block-sync"; sync_arg=()
else
    SYNC_KIND="state-sync"; sync_arg=(--state-sync)
fi
# FUNDING KIND, recorded the same way and for the same reason as SYNC_KIND: the run directory is
# the only record anyone reads afterwards, and "the joiners were sponsored" is exactly the sort of
# thing that must not have to be inferred from a flag someone remembers passing.
if (( SPONSORED )); then
    FUND_KIND="foundation-sponsored (no coins to joiners)"; sponsor_arg=(--foundation-sponsored "$SPONSOR_GRANTER")
else
    FUND_KIND="funded by bank send from $FUNDER"; sponsor_arg=(--funder "$FUNDER")
fi
stage "G. join each node by $SYNC_KIND, $FUND_KIND, in turn"
note "join mode: $SYNC_KIND; funding: $FUND_KIND"
# WALK THE SCHEDULE, not the joiner list: a --test between two --joiner entries belongs to the
# joiner BEFORE it, and only the schedule knows which.  The leading tests were already run in stage
# C, so they are skipped here by only starting to honour test: entries once a joiner has been seen.
n=1
JOINED=()
seen_joiner=0
tcount=0
for e in "${SCHEDULE[@]}"; do

if [[ "$e" == test:* ]]; then
    (( seen_joiner )) || continue          # belonged to the primary; ran in stage C
    (( tcount++ ))
    # WAIT UNTIL THE NODE JUST ADDED IS ADDRESSABLE, not merely joined -- see the header.  $n is
    # its pioneer number, which is also the fleet size, which is also how many addressable pioneers
    # there should now be.  Done once per joiner, before its first test.
    if (( tcount == 1 )); then
        info "waiting for ${PIONEER_PREFIX}${n} to become addressable (first proposed block after bonding)"
        wait_addressable "$PRIMARY" "$n"
    fi
    run_test_entry "after ${PIONEER_PREFIX}${n} #$tcount" "stage-G-${PIONEER_PREFIX}${n}-$tcount" "${e#test:}"
    continue
fi

# THE ONE ENTRY THAT RUNS FROM HERE RATHER THAN ON THE PRIMARY.  --test commands are chain-level and
# run on the primary; a fleet upgrade has to reach every node, and the primary cannot ssh to them.
if [[ "$e" == local:* ]]; then
    (( tcount++ ))
    if (( tcount == 1 )); then
        info "waiting for ${PIONEER_PREFIX}${n} to become addressable (first proposed block after bonding)"
        wait_addressable "$PRIMARY" "$n"
    fi
    run_local_entry "local after ${PIONEER_PREFIX}${n} #$tcount" "stage-G-local-${PIONEER_PREFIX}${n}-$tcount" \
        ${=${e#local:}}
    continue
fi

if [[ "$e" == upgrade:* ]]; then
    (( tcount++ ))
    # Same gate as a --test: a node that has not proposed since bonding is not really in the fleet
    # yet, and upgrading around it would prove less than it appears to.
    if (( tcount == 1 )); then
        info "waiting for ${PIONEER_PREFIX}${n} to become addressable (first proposed block after bonding)"
        wait_addressable "$PRIMARY" "$n"
    fi
    # The fleet list comes from JOINED, not from anything the operator retyped -- that is the whole
    # reason this is a flag rather than a --test-local string.
    _up=()
    for _j in "${JOINED[@]}"; do _up+=(--joiner "$_j"); done
    run_local_entry "fleet upgrade" "stage-G-fleet-upgrade" \
        "$SCRIPT_DIR/test_fleet_upgrade.sh" --primary "$PRIMARY" "${_up[@]}" --run-dir "$RUN_DIR/fleet-upgrade"
    continue
fi

[[ "$e" == joiner:* ]] || continue
    j="${e#joiner:}"
    seen_joiner=1
    tcount=0
    (( n++ ))
    pioneer="${PIONEER_PREFIX}${n}"
    # From the second joiner on, corroborate the state-sync trust height against a node that is NOT
    # the primary.  nth_node_bringup's --seed2 defaults to the primary, which proves only that the
    # primary agrees with itself; an independent peer is what makes the cross-check mean anything.
    seed2_arg=()
    if (( ${#JOINED[@]} > 0 )); then
        seed2_arg=(--seed2 "${JOINED[1]##*@}")
        info "cross-checking the trust height against ${JOINED[1]}"
    fi
    info ""
    # WHICH SYNC RAN IS RECORDED, because "the joiner caught up" means something different in each
    # case: a state-synced joiner IMPORTED the enclave-private tables from a snapshot, a block-synced
    # one replayed history and never touched that path.  $SYNC_KIND and $sync_arg are resolved once
    # at the top of this stage, so the header and this line cannot disagree.
    # THROUGH PHASE 7, NOT 5 -- the difference is the whole growth test.  The old bringup stopped
    # at 5 deliberately ("stops short of converting it to a validator"), because converting re-splits
    # stake and is worth watching.  But a node that is not a VALIDATOR never proposes a block, and
    # updateIsValidator publishes a pioneer's external address ONLY under IsProposer -- so an
    # unbonded joiner never becomes addressable, never becomes an SS key owner, and the audit below
    # would sit at target=1 healing nothing while reporting success.  Phase 6 converts AND carries
    # the guard that matters here: it verifies neither node reaches 2/3, which is exactly the check
    # a hand-written loop skipped when it halted this fleet (TESTING-BACKLOG item 108).  Phase 7 is
    # test_peer_agreement.sh -- the first thing in the sequence that compares two nodes at all.
    # A SPONSORED JOIN ON A LAUNCH CHAIN CANNOT RUN UNATTENDED.  The sponsor is a bucket held as
    # an N-of-M multisig whose members are NOT on the primary, and nth_node_bringup's funding
    # phase signs on the primary.  There is nothing to fix here: a script that could sign for the
    # sponsor would have to hold the sponsor's keys, which is the property the multisig exists to
    # prevent.  Use --funder with a key the primary DOES hold (the genesis validator's own,
    # typically), or drive the joins by hand: nth_node_bringup --until 3, run the ceremony it
    # prints, then --from 5.
    # SPONSORED + LAUNCH CHAIN GOES THROUGH THE LOCAL CEREMONY WRAPPER.
    #
    # This used to be a hard refusal, and the reasoning above still stands for the PRIMARY: it does
    # not hold bucket keys and never should.  But THIS workstation does -- that is the test fleet's
    # standing shortcut -- so the ceremony can run here, between nth_node's phases, which is the one
    # place it fits: the joiner's address does not exist until phase 3 and phase 5 blocks waiting
    # for the grant.  A --test-local entry cannot do it; those fire only after a joiner is done.
    #
    # testscripts/sponsored_join_local.sh drives --until 3 / ceremony / --from 5 and is explicit
    # about being test-only.  Production is scripts/sponsor_join_node.sh.
    if [[ -n "$MAINNET_SRC" ]] && (( SPONSORED )); then
        if [[ ! -x "$SCRIPT_DIR/sponsored_join_local.sh" ]]; then
            fail "--mainnet-source with --foundation-sponsored needs testscripts/sponsored_join_local.sh
       (the sponsoring bucket is a multisig and the primary cannot sign for it)."
        fi
        info "joining $j as $pioneer by $SYNC_KIND, SPONSORED by $SPONSOR_GRANTER (ceremony runs here)"
        print "$j joined by: $SYNC_KIND (as $pioneer, sponsored by $SPONSOR_GRANTER)" >> "$RUN_DIR/fleet.txt"
        sjargs=(--primary "$PRIMARY" --joiner "$j" --pioneer "$pioneer"
                --granter "$SPONSOR_GRANTER" "${sync_arg[@]}" "${seed2_arg[@]}"
                --convert-to-validator)
        "$SCRIPT_DIR/sponsored_join_local.sh" "${sjargs[@]}" \
            2>&1 | tee "$RUN_DIR/stage-G-join-${j##*@}.log"
        [[ ${pipestatus[1]} -eq 0 ]] || fail "sponsored join failed for $j -- see $RUN_DIR/stage-G-join-${j##*@}.log
       nth_node_bringup is phase-resumable, so re-running picks up where it stopped."
        # SAME BOOKKEEPING AS THE UNSPONSORED PATH.  JOINED feeds the run summary and the
        # addressable-count gate that --test entries wait on; a joiner missing from it is invisible
        # to everything scheduled after it.
        JOINED+=("$j")
        assert_advancing "$j" "after join"
        assert_advancing "$PRIMARY" "primary after $j joined"
        info "$j joined as $pioneer (sponsored)"
        note "joined $j as $pioneer (sponsored by $SPONSOR_GRANTER)"
        continue
    fi
    amount_args=()
    [[ -n "$FUND_QDN_ARG" ]] && amount_args+=(--fund-qdn "$FUND_QDN_ARG")
    [[ -n "$STAKE_ARG" ]]    && amount_args+=(--stake "$STAKE_ARG")
    info "joining $j as $pioneer by $SYNC_KIND (through phase 8: join, bond, agree)"
    print "$j joined by: $SYNC_KIND (as $pioneer)" >> "$RUN_DIR/fleet.txt"
    "$SCRIPT_DIR/nth_node_bringup.sh" --primary "$PRIMARY" --joiner "$j" \
        --pioneer "$pioneer" "${sync_arg[@]}" "${seed2_arg[@]}" "${sponsor_arg[@]}" "${amount_args[@]}" \
        --convert-to-validator --from 1 --until 8 \
        2>&1 | tee "$RUN_DIR/stage-G-join-${j##*@}.log"
    [[ ${pipestatus[1]} -eq 0 ]] || fail "join failed for $j; nth_node_bringup is phase-resumable (--from N). See $RUN_DIR/stage-G-join-${j##*@}.log"
    JOINED+=("$j")
    assert_advancing "$j" "after join"
    assert_advancing "$PRIMARY" "primary after $j joined"
    info "$j joined as $pioneer"
    note "joined $j as $pioneer"
done

fi

print ""
print "fleet_bringup_with_tests: done.  Primary + ${#JOINED[@]} joiner(s) up."
print "  logs           : $RUN_DIR   (also ${RUN_DIR:h}/latest)"
print "  build          : $KIND"
print "  measurement    : ${PRIM_UID:-unknown}  (identical on every node)"
print "  joined         : ${JOINED[*]}"
# A bringup that quietly tested nothing is worse than one that tested nothing loudly.
print "  schedule       :"
_h="$PRIMARY"
for e in "${SCHEDULE[@]}"; do
    case "$e" in
        joiner:*) _h="${e#joiner:}"; print "                     joiner  $_h" ;;
        test:*)   print "                       test  ${e#test:}" ;;
        local:*)  print "                 test-local  ${e#local:}   (runs here, not on the primary)" ;;
        upgrade:*) print "             fleet upgrade  test_fleet_upgrade.sh (all nodes, by governance)" ;;
    esac
done
print "  archives       : ~/qadena.pre-bringup.$STAMP.bak on each joiner (delete once satisfied)"
print ""
# WHAT THIS SCRIPT DID AND DID NOT DO -- and it must describe THIS script.  This block was once a
# copy of the old bringup's, which stopped at phase 5 and said so; here the joiners are bonded by
# phase 7, so the text told the operator to go and re-run a conversion that had already happened.
print "Joiners WERE converted to validators: nth_node_bringup ran --convert-to-validator --until 8, so each one is"
print "bonded, has proposed a block, and is therefore addressable, an SS key owner and visible to the"
print "re-share audit.  Stopping at phase 5 instead would leave them unbonded, and every audit would"
print "sit at target=1 healing nothing.  See the stage G comment."
# (I) is the INDEX of the last match, 0 when there is none -- so this asks "was any --test
# scheduled?" without a loop.  A plain `print ... || print ...` chain would have made only the
# FIRST line of each group conditional and printed the rest unconditionally.
#
# The heading is printed only if something goes under it: a bare "Not covered by this run:" with an
# empty list reads as a truncated summary, which is the opposite of the reassurance it should give.
if (( ${SCHEDULE[(I)test:*]} == 0 || BLOCK_SYNC )); then
    print ""
    print "Not covered by this run:"
fi
if (( ${SCHEDULE[(I)test:*]} == 0 )); then
    print "  - anything chain-level.  No --test was scheduled, so nothing beyond join, bond and peer"
    print "    agreement was exercised -- and NO WAIT-UNTIL-ADDRESSABLE RAN either, because that gate"
    print "    lives with the first --test.  Check it by hand before trusting the fleet:"
    print "      qadenad q qadena list-interval-public-key-id --limit 5000 -o json | jq '[.intervalPublicKeyID[]? | select(.nodeType==\"pioneer\" and .externalIPAddress!=\"\")] | length'"
fi
if (( BLOCK_SYNC )); then
    print "  - state-sync, and the private-state transfer it depends on.  --block-sync replays history"
    print "    and never seeds the joiner's enclave store from a snapshot."
fi
note "done: ${#JOINED[@]} joiner(s)"
