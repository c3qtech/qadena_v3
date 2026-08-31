#!/bin/zsh
#
# Upgrade a WHOLE FLEET by governance and prove every node came across -- the replacement for the
# retired enclave-upgrade suite (ab839b3c).
#
#   ./testscripts/test_fleet_upgrade.sh --primary m1 --joiner m2 --joiner m3 --joiner m4
#
# WHY THIS IS NOT A REGRESSION SUITE.  The thing it tests is no longer a single-node operation.  The
# old suite live-swapped one node's enclave binary; an enclave change is now a governance plan at a
# HEIGHT, and x/upgrade halts EVERY node there.  A node that reaches that height without the new
# binary staged stays halted -- so an upgrade is only safe once every node has the release, which is
# what upgrade_fleet.sh does and what a suite running on one node cannot.  It is also why this is
# driven from the workstation: --test commands run ON THE PRIMARY, and the primary cannot ssh to the
# other nodes (verified: "Permission denied (publickey,password)").
#
# WHAT IT DOES
#   1. baseline -- every node's measurement and chain version, and they must already agree
#   2. bump the identity on the primary and COMMIT IT TEMPORARILY
#   3. upgrade_fleet.sh --node <each> --build-from <primary> --quiesce
#   4. assert every node moved: new measurement, cosmovisor current -> upgrades/v<new>, advancing
#   5. assert the SEALED STATE SURVIVED -- see below
#
# WHY THE BUMP IS THREE FILES AND WHICH THREE.  The plan is named v<chain version>, and "a plan whose
# name the running binary already registers a handler for is a SILENT NO-OP -- no halt, no swap"
# (buildscripts/build.sh).  So the CHAIN version must move or the fleet ignores the plan entirely.
# The enclave version must move because the attested handover requires strictly-greater.  And
# test_unique_id.txt is //go:embed-ed, so bumping it is what actually changes the debug measurement.
#
#   cmd/qadenad_enclave/test_unique_id.txt   increment_id       unique061 -> unique062
#   cmd/qadenad_enclave/version.txt          increment_version  1.1.23    -> 1.1.24
#   cmd/qadenad/version.txt                  increment_version  1.1.28    -> 1.1.29
#
# THE SIGNER ID IS NOT TOUCHED, and that is deliberate rather than an omission.  In a debug build
# signerID and uniqueID ARE the sealing keys, and product-key sealing is what lets an upgraded
# enclave still read what the previous measurement sealed.  Bumping the signer once moved
# signer051 -> signer052 and the upgraded enclave panicked in getPrivKCache with "Couldn't unseal,
# unrecognized prefix" -- the SS interval key cache was no longer readable by anything, while the
# handover itself reported success.  On real SGX a rebuild changes MRENCLAVE and nothing else.
#
# WHY A TEMPORARY COMMIT.  upgrade_fleet.sh refuses a tree that matches no commit ("the artefact
# would match no commit, and nobody could later say what was deployed"), and --build-sgx runs
# `git checkout -f && git clean -fd` before building, which would DISCARD an uncommitted bump and
# reproduce the identical measurement -- leaving nothing to upgrade to while looking like it worked.
# So the bump is committed on the primary and the commit is reset on every exit path.
#
# WHAT AN UPGRADE HAS TO PRESERVE.  The enclave holds the jar and regulator private keys in sealed
# state.  They exist nowhere else and nobody -- including the regulator -- can recover them if a node
# throws them away, so an upgrade that starts with fresh keys does not merely lose state: it makes
# every suspicious-transaction report ever filed permanently undecryptable, silently, with the chain
# still producing blocks and looking healthy.  That is why step 5 exists and why it is not optional.
# On a debug enclave the check is direct (the params file is readable).  On real SGX it cannot be --
# the file is ciphertext to everyone including this test -- so there the assertion inverts: prove it
# really IS opaque, and report honestly that decryption was not verified.

set -u
SCRIPT_DIR="${0:A:h}"
FLEET_NAME="fleet-upgrade"
source "$SCRIPT_DIR/fleet_lib.sh"

PRIMARY=""; JOINERS=(); RUN_DIR=""; QUIESCE_ARG="--quiesce"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary)   PRIMARY="$2"; shift 2 ;;
        --joiner)    JOINERS+=("$2"); shift 2 ;;
        --run-dir)   RUN_DIR="$2"; shift 2 ;;
        --quiesce-immediate) QUIESCE_ARG="--quiesce-immediate"; shift ;;
        --help)
            print "Usage: test_fleet_upgrade.sh --primary <[user@]host> [--joiner <[user@]host>]..."
            print "                             [--run-dir <dir>] [--quiesce-immediate]"
            print ""
            print "  Bumps the enclave identity and both versions on the primary, commits that"
            print "  temporarily, rolls the release to EVERY node by governance, and asserts each"
            print "  one swapped and that the sealed keys survived."
            print ""
            print "  --quiesce-immediate  end an in-flight regression now instead of waiting it out."
            exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$PRIMARY" ]] || { print -u2 -- "--primary is required"; exit 1 }

[[ -n "$RUN_DIR" ]] || RUN_DIR="$HOME/qadena-fleet-runs/fleet-upgrade-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR" || exit 1
STATUS="$RUN_DIR/status.txt"
ALL=("$PRIMARY" "${JOINERS[@]}")
note "run started: $0 $*"
info "primary  $PRIMARY"
info "joiners  ${JOINERS[*]:-<none>}"
info "run dir  $RUN_DIR"

PHOME=$(rsh_user "$PRIMARY" 'print $HOME' | tr -d '\r')
REPO="$PHOME/qv3"

# The bump is committed on the primary; leaving that commit behind would make the next run build
# from a tree nobody recognises.  ZERR as well, because a hard zsh error can tear the shell down
# without running an EXIT trap and would strand the commit.
ORIG_HEAD=""
restore_primary_tree() {
    [[ -n "$ORIG_HEAD" ]] || return 0
    info "restoring $PRIMARY's checkout to $ORIG_HEAD"
    rsh_user "$PRIMARY" "git -C $REPO reset --quiet --hard $ORIG_HEAD" >/dev/null 2>&1 \
        || print -u2 "WARNING: could not reset $REPO on $PRIMARY to $ORIG_HEAD -- do it by hand"
    ORIG_HEAD=""
}
trap restore_primary_tree EXIT INT TERM ZERR

# ---------------------------------------------------------------------------------------------
stage "A. baseline -- every node must already agree"
for h in "${ALL[@]}"; do
    rsh_user "$h" 'true' >/dev/null 2>&1 || fail "cannot ssh to $h"
done

# measurement_of lives in fleet_lib.sh and reads it from the INSTALLED BINARY, which is the only
# honest source: a debug build's identity is the embedded string, an SGX build's is MRENCLAVE.
BASE_UID=$(measurement_of "$PRIMARY")
[[ -n "$BASE_UID" ]] || fail "could not read the primary's measurement"
for h in "${ALL[@]}"; do
    u=$(measurement_of "$h")
    [[ "$u" == "$BASE_UID" ]] \
        || fail "$h measures $u but the primary measures $BASE_UID -- this fleet is already inconsistent, and an upgrade would hide that rather than fix it"
    info "$h: $BASE_UID"
done

BASE_CHAIN_VER=$(rsh_user "$PRIMARY" "cat $REPO/cmd/qadenad/version.txt" | tr -d '\r')
BASE_ENCL_VER=$(rsh_user "$PRIMARY" "cat $REPO/cmd/qadenad_enclave/version.txt" | tr -d '\r')
info "chain version $BASE_CHAIN_VER   enclave version $BASE_ENCL_VER"

dirty=$(rsh_user "$PRIMARY" "git -C $REPO status --porcelain | wc -l" | tr -d '[:space:]')
[[ "$dirty" == "0" ]] \
    || fail "$REPO on $PRIMARY has uncommitted work. The bump is committed on top of HEAD and reset afterwards, which would take that work with it -- commit or stash it first."
ORIG_HEAD=$(rsh_user "$PRIMARY" "git -C $REPO rev-parse HEAD" | tr -d '\r')
info "primary HEAD $ORIG_HEAD (restored on exit)"

# CAPTURED BEFORE ANYTHING MOVES.  Reading sealed keys is a DEBUG-ONLY capability and that asymmetry
# is the security property, not a gap in the test: a debug enclave "seals" by prefixing an id onto
# plaintext JSON, a real one seals with the hardware key and the same file is ciphertext to everyone.
OLD_PARAMS=$(rsh_user "$PRIMARY" "ls -t $PHOME/qadena/enclave_config/enclave_params_*.json 2>/dev/null | head -1" | tr -d '\r')
CAN_READ_SEALED=0
OLD_REGULATOR=""
if [[ -n "$OLD_PARAMS" ]]; then
    OLD_REGULATOR=$(rsh_user "$PRIMARY" "sed 's/^[^{]*//' $OLD_PARAMS 2>/dev/null | jq -r '.SharedEnclaveParams.RegulatorPrivK' 2>/dev/null" | tr -d '\r')
    if [[ -n "$OLD_REGULATOR" && "$OLD_REGULATOR" != "null" ]]; then
        CAN_READ_SEALED=1
        info "debug sealing: regulator key readable, so decryption can be verified across the upgrade"
    else
        info "REAL SGX SEALING: $OLD_PARAMS is ciphertext, so keys cannot be compared across the upgrade"
    fi
fi

REPORTS_BEFORE=$(rsh_user "$PRIMARY" "\$HOME/qadena/bin/qadenad --home \$HOME/qadena query qadena list-suspicious-transaction --count-total --output json 2>/dev/null | jq -r '.pagination.total'" | tr -d '\r')
[[ -n "$REPORTS_BEFORE" ]] || REPORTS_BEFORE=0
info "$REPORTS_BEFORE suspicious-transaction report(s) on record"
if (( CAN_READ_SEALED )) && [[ "$REPORTS_BEFORE" == "0" ]]; then
    # A vacuous pass on the one assertion that would actually catch lost keys is worse than no
    # assertion, because it reports coverage that was never exercised.
    info "NOTE: no reports on record, so the decryption assertion in step 5 would pass vacuously."
    info "      Run test_suspicious.sh first if you want that assertion to mean anything."
fi

# ---------------------------------------------------------------------------------------------
stage "B. bump the identity on the primary and commit it"
# The helpers live in setup_env.sh and write with `echo -n`: these files carry NO trailing newline
# because test_unique_id.txt is //go:embed-ed, and one added byte changes the measurement.  Hand-
# writing them is how that gets broken, so the helpers do it.
BUMP=$(rsh_user "$PRIMARY" "cd $REPO && source scripts/setup_env.sh >/dev/null 2>&1; \
    u=\$(increment_id cmd/qadenad_enclave/test_unique_id.txt); \
    e=\$(increment_version cmd/qadenad_enclave/version.txt); \
    c=\$(increment_version cmd/qadenad/version.txt); \
    print \"\$u \$e \$c\"" | tr -d '\r')
NEW_UID="${BUMP%% *}"; rest="${BUMP#* }"; NEW_ENCL_VER="${rest%% *}"; NEW_CHAIN_VER="${rest##* }"
[[ -n "$NEW_UID" && -n "$NEW_ENCL_VER" && -n "$NEW_CHAIN_VER" ]] \
    || fail "the bump produced \"$BUMP\" -- expected three values"
[[ "$NEW_UID" != "$BASE_UID" ]] || fail "the unique id did not move ($BASE_UID)"
[[ "$NEW_CHAIN_VER" != "$BASE_CHAIN_VER" ]] \
    || fail "the chain version did not move ($BASE_CHAIN_VER) -- the plan would be a silent no-op"
info "unique id       $BASE_UID -> $NEW_UID"
info "enclave version $BASE_ENCL_VER -> $NEW_ENCL_VER"
info "chain version   $BASE_CHAIN_VER -> $NEW_CHAIN_VER   (plan will be v$NEW_CHAIN_VER)"

rsh_user "$PRIMARY" "cd $REPO && git add -A cmd/qadenad_enclave/test_unique_id.txt cmd/qadenad_enclave/version.txt cmd/qadenad/version.txt && \
    git -c user.name='fleet-upgrade-test' -c user.email='noreply@qadena.test' commit --quiet -m 'test: fleet upgrade to $NEW_UID / v$NEW_CHAIN_VER'" \
    || fail "could not commit the bump on $PRIMARY"
info "committed on the primary (reset to $ORIG_HEAD on exit)"

# ---------------------------------------------------------------------------------------------
stage "C. roll it to every node by governance"
# --quiesce because the roll restarts nodes and a regression running through that is a second node
# down; upgrade_fleet.sh only WARNS without it.  --build-from the primary, which is the node whose
# checkout carries the bump.
node_args=()
for h in "${ALL[@]}"; do node_args+=(--node "$h"); done
"$SCRIPT_DIR/upgrade_fleet.sh" "${node_args[@]}" --build-from "$PRIMARY" "$QUIESCE_ARG" \
    2>&1 | tee "$RUN_DIR/stage-C-upgrade.log" | while read -r l; do info "$l"; done
[[ ${pipestatus[1]} -eq 0 ]] || fail "the roll failed -- see $RUN_DIR/stage-C-upgrade.log"

# ---------------------------------------------------------------------------------------------
stage "D. every node must be on the new measurement and the new generation"
# upgrade_fleet.sh has its own per-node check; this one is independent and asserts the things THIS
# test promised: the measurement moved, cosmovisor swapped generation, and the node is still making
# progress.  "Processes are up" is not health -- a halted node looks perfectly healthy from ps.
# THE MEASUREMENT IS READ FROM THE NODES, NOT ASSUMED FROM THE FILE.
#
# $NEW_UID is what increment_id wrote into test_unique_id.txt, and on a DEBUG enclave that string
# IS the identity, so comparing against it works.  On real SGX it is not: measurement_of returns the
# 64-hex MRENCLAVE that ego computed from the signed binary, and this assertion would compare a
# hash against "unique062" and fail on every node of a perfectly good upgrade.  So ask the primary
# what it actually runs, require it to have MOVED, and require every other node to match it.
NEW_MEASURED=$(measurement_of "$PRIMARY")
[[ -n "$NEW_MEASURED" ]] || fail "could not read the primary's measurement after the upgrade"
[[ "$NEW_MEASURED" != "$BASE_UID" ]] \
    || fail "the primary still measures $BASE_UID after the upgrade -- nothing was swapped"
# On a debug enclave the identity is the embedded string, so it must equal what we bumped it to.
# On SGX there is nothing to compare it against but itself, and the != above is the whole check.
if [[ "$BASE_UID" == unique<-> ]]; then
    [[ "$NEW_MEASURED" == "$NEW_UID" ]] \
        || fail "debug enclave measures $NEW_MEASURED but test_unique_id.txt was bumped to $NEW_UID"
fi
info "new measurement: $NEW_MEASURED"

for h in "${ALL[@]}"; do
    u=$(measurement_of "$h")
    [[ "$u" == "$NEW_MEASURED" ]] || fail "$h measures $u, expected $NEW_MEASURED -- it did not take the upgrade"
    cur=$(cosmovisor_current_of "$h")
    [[ "$cur" == *"upgrades/v$NEW_CHAIN_VER"* ]] \
        || fail "$h's cosmovisor current -> '$cur', expected upgrades/v$NEW_CHAIN_VER"
    assert_advancing "$h" "after the upgrade"
    info "$h: $NEW_MEASURED, current -> $cur, advancing"
done

# ---------------------------------------------------------------------------------------------
stage "E. the sealed state survived"
REPORTS_AFTER=$(rsh_user "$PRIMARY" "\$HOME/qadena/bin/qadenad --home \$HOME/qadena query qadena list-suspicious-transaction --count-total --output json 2>/dev/null | jq -r '.pagination.total'" | tr -d '\r')
[[ -n "$REPORTS_AFTER" ]] || REPORTS_AFTER=0
# NOT EQUALITY.  The failure this guards against is reports being LOST -- an enclave that came up
# with fresh keys makes every existing report undecryptable -- and losing them is what must fail.
# GAINING one is normal: the chain keeps running between the baseline and the plan height, and any
# transaction in flight when the suites were stopped can still be scanned and filed.  Equality
# failed a run in which nothing was wrong (358 -> 359, one late report) AFTER the upgrade had
# succeeded and the keys had demonstrably come across byte-for-byte.  Assert the floor instead.
(( REPORTS_AFTER >= REPORTS_BEFORE )) \
    || fail "reports were LOST across the upgrade ($REPORTS_BEFORE -> $REPORTS_AFTER) -- the migrated enclave cannot see reports the old one filed"
(( REPORTS_AFTER > REPORTS_BEFORE )) \
    && info "note: $((REPORTS_AFTER - REPORTS_BEFORE)) report(s) filed after the baseline (traffic in flight); none were lost"

NEW_PARAMS=$(rsh_user "$PRIMARY" "ls -t $PHOME/qadena/enclave_config/enclave_params_*.json 2>/dev/null | head -1" | tr -d '\r')
[[ -n "$NEW_PARAMS" ]] || fail "no sealed params on the primary after the upgrade"

if (( CAN_READ_SEALED )); then
    NEW_REGULATOR=$(rsh_user "$PRIMARY" "sed 's/^[^{]*//' $NEW_PARAMS 2>/dev/null | jq -r '.SharedEnclaveParams.RegulatorPrivK' 2>/dev/null" | tr -d '\r')
    [[ -n "$NEW_REGULATOR" && "$NEW_REGULATOR" != "null" ]] \
        || fail "could not read RegulatorPrivK from $NEW_PARAMS after the upgrade"
    [[ "$NEW_REGULATOR" == "$OLD_REGULATOR" ]] \
        || fail "the regulator key CHANGED across the upgrade -- every report ever filed on this chain is now undecryptable"
    info "the regulator key came across byte-for-byte"

    if [[ "$REPORTS_AFTER" != "0" ]]; then
        # --limit $REPORTS_AFTER READS EVERY REPORT.  Unqualified this takes the default page (the
        # oldest 100) and would claim every report verified having looked at a hundred; a negative
        # assertion is only as wide as the page it ran over.
        dec=$(rsh_user "$PRIMARY" "\$HOME/qadena/bin/qadenad --home \$HOME/qadena query qadena list-suspicious-transaction $NEW_REGULATOR --limit $REPORTS_AFTER 2>&1")
        print -r -- "$dec" | grep -q "Suspicious Transaction" \
            || { print -r -- "$dec" | head -5; fail "the migrated regulator key could not decrypt any report"; }
        print -r -- "$dec" | grep -qiE "couldn't decrypt|invalid length|generic error" \
            && { print -r -- "$dec" | head -5; fail "a report failed to decrypt with the migrated key"; }
        seen=$(print -r -- "$dec" | grep -c "Suspicious Transaction")
        [[ "$seen" == "$REPORTS_AFTER" ]] \
            || fail "only $seen of $REPORTS_AFTER reports came back; the listing was truncated and this check would be partial"
        info "$seen of $REPORTS_AFTER reports still decrypt with the migrated key"
    else
        info "no reports on record, so decryption was NOT exercised in this run"
    fi
else
    # Assert it really IS opaque rather than assuming so.  If a real enclave ever wrote its params in
    # the clear, every private key on the node would be readable, and this is the one place
    # positioned to notice.
    if rsh_user "$PRIMARY" "sed 's/^[^{]*//' $NEW_PARAMS 2>/dev/null | jq -e '.SharedEnclaveParams.RegulatorPrivK' >/dev/null 2>&1"; then
        fail "$NEW_PARAMS is READABLE PLAINTEXT under a real SGX enclave -- the migrated keys are exposed on disk"
    fi
    info "REAL SGX: params are opaque, so key preservation and report decryption were NOT verified here."
    info "VERIFIED INSTEAD: $REPORTS_AFTER report(s) still on record, and every node runs the new measurement."
fi

restore_primary_tree

print ""
print "FLEET UPGRADE: PASSED"
print "  $BASE_UID -> $NEW_MEASURED   on ${#ALL[@]} node(s)"
print "  chain v$BASE_CHAIN_VER -> v$NEW_CHAIN_VER   (governance plan v$NEW_CHAIN_VER)"
print "  logs: $RUN_DIR"
exit 0
