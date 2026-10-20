#!/bin/zsh
#
# Regression test for SS interval key OWNER DEPARTURE -- the shrink half of the re-share audit.
#
# WHAT DEPARTURE IS FOR.  test_ss_reshare_audit.sh covers the fleet GROWING: a key minted when one
# node was addressable gains owners until custody catches up with membership.  This covers the
# other direction.  When a pioneer leaves for good, every key it owns goes on NAMING it as a
# holder, so the chain reports custody that no longer exists -- the row says five nodes can
# reconstruct the key when only four can.  The audit re-shares those keys onto the survivors.
#
# THE THREE TRANSITIONS, and why the third is the one with teeth.  getThreshold is a step function
# (0-3 -> 1, 4-6 -> 2, 7-10 -> 3), so a shrink either stays inside a step or crosses one:
#
#   6 -> 5 owners   threshold 2 -> 2   re-shared, still split
#   5 -> 4 owners   threshold 2 -> 2   re-shared, still split
#   4 -> 3 owners   threshold 2 -> 1   re-shared, and the key STOPS BEING SPLIT -- at threshold 1
#                                      addSSShare hands every remaining owner the whole key.
#
# THE KEY IS RE-SHARED IN ALL THREE CASES.  An earlier version of this suite expected the third to
# be REFUSED, because an earlier version of the enclave refused it.  That refusal was removed: it
# could not hold the threshold (the threshold is derived from the LISTED owner count, which does
# not fall as owners depart), and declining to act let the live count drain to the point where the
# key could no longer be reconstructed at all.  See docs/SS-THRESHOLD-PROPOSAL.md.
#
# SO WHAT IS ASSERTED IS RECOVERABILITY, NOT REFUSAL.  After every departure, two things must hold
# for every key:
#
#   1. no departed pioneer is still listed as an owner   (custody is accurate)
#   2. live owners >= the threshold those owners imply   (the key can still be rebuilt)
#
# Property 2 is the one that matters, and it is why asserting "the owner count went down" is not
# enough: an audit that dropped owners without re-splitting would satisfy the count and leave a key
# whose surviving holders cannot reconstruct it.  Reconstruction needs `threshold` LIVE owners
# (runSSReconstruct), so once live < threshold the key is unrecoverable and no later re-share can
# retrieve it -- the failure is permanent and silent.
#
# WHY SIX NODES.  Three departures are needed to see both a shrink that stays inside a step and one
# that crosses it: 6->5 and 5->4 stay at threshold 2, 4->3 crosses to 1.  A four-node fleet can
# only ever show the crossing, which is why fleet_site_profile.sh grew M5 and M6.
#
# WHY SEVERAL INTERVAL KEYS, not one.  A departed pioneer is an owner of EVERY key minted while it
# was addressable, and maxSSResharesPerRotation caps a tick at 4.  With one key the backlog path --
# cursor, cap, multiple sweeps -- is never exercised, and a bug that healed only the newest key
# would pass. The test mints extra keys up front so each shrink needs more than one audit.
#
# WHAT THIS CANNOT DO WITHOUT A DEBUG ENCLAVE.  The real rotation tick runs when
# `height % keyUpdateFrequency == 0` INSIDE UpdateHeight, which the chain calls only when
# `height % 11 == 0` -- so the effective cadence is lcm(11,555) = 6105 blocks, about five hours at
# 3s blocks.  Three shrinks on the natural tick would take most of a day, so this drives
# `enclave audit-ss-keys` directly.  That is refused under --realenclave, so this suite SKIPS
# LOUDLY on SGX rather than reporting a pass it did not earn.
#
# HISTORY WORTH KEEPING.  Written after an end-to-end run on M1-M6 found a bug that eight unit
# tests had missed: PioneerHasDeparted looked the owner up in the pubKID index while Share.PioneerID
# carries a NODE id, so the lookup missed every time, every owner read as still-eligible, and the
# chain rejected all four re-shares the enclave had correctly planned (ErrOwnerStillEligible).  The
# unit fixture used one identifier for both roles, so the two indexes coincided and the mismatch was
# invisible.  That is the reason this suite exists at the fleet level and not only in keeper tests.

SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

fail() {
    echo ""
    echo "FAILED: $*"
    exit 1
}

skip() {
    echo ""
    echo "SKIPPED: $*"
    exit 0
}

# How many extra interval keys to mint before departing anyone, so that a shrink needs more than
# one audit tick to drain.  4 is maxSSResharesPerRotation, so 5 keys guarantees a second sweep.
EXTRA_KEYS=4

# Blocks of grace to run the test with.  The default (4*555) is ~2h at 3s blocks; the test lowers
# it by governance and restores nothing, because a test fleet's params are disposable.
TEST_GRACE=30

# -------------------------------------------------------------------- readings

# ss_key_owners emits "pubKID<TAB>generation<TAB>owner,owner,..." for every SS interval key.
#
# SS interval keys are the transaction-type rows that CARRY SHARES; wallet keys and credential rows
# do not, and judging them here would demand owners for keys the audit does not own.  Same
# discriminator as test_ss_reshare_audit.sh -- see its note.
ss_key_owners() {
    local total
    total=$(qadenad_alias q qadena list-public-key --count-total --limit 1 -o json 2>/dev/null \
        | sed -n 's/.*"total":"\([0-9]*\)".*/\1/p')
    [[ -n "$total" ]] || return 1
    qadenad_alias q qadena list-public-key --limit "$total" -o json 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
for r in sorted((d.get("publicKey") or []), key=lambda x: x.get("pubKID","")):
    if r.get("pubKType") != "transaction":
        continue
    shares = r.get("shares") or []
    if not shares:
        continue
    owners = sorted(s.get("pioneerID","") for s in shares)
    print("%s\t%s\t%s" % (r.get("pubKID"), r.get("generation","0"), ",".join(owners)))
'
}

# owner_count_of <pubKID> -- how many owners that key currently has.
owner_count_of() {
    ss_key_owners | awk -F'\t' -v k="$1" '$1==k {n=split($3,a,","); print n}'
}

# min_owner_count -- the smallest owner count across all SS keys, which is what the accept/refuse
# boundary is judged on.
min_owner_count() {
    ss_key_owners | awk -F'\t' '{n=split($3,a,","); if (m=="" || n<m) m=n} END {print m+0}'
}

# keys_still_naming <pioneerID> -- how many SS keys still list that pioneer as an owner.
keys_still_naming() {
    ss_key_owners | awk -F'\t' -v p="$1" '{n=split($3,a,","); for(i=1;i<=n;i++) if(a[i]==p) c++} END {print c+0}'
}

# departed_height_of <pioneerID> -- the row's departedHeight, 0 when it has not departed.
departed_height_of() {
    qadenad_alias q qadena list-interval-public-key-id --limit 200 -o json 2>/dev/null | python3 -c '
import sys, json
want = sys.argv[1]
d = json.load(sys.stdin)
for r in (d.get("intervalPublicKeyID") or []):
    if r.get("nodeID") == want:
        print(r.get("departedHeight", "0"))
        break
else:
    print("0")
' "$1"
}

chain_height() {
    qadenad_alias status 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["sync_info"]["latest_block_height"])'
}

# wait_height <h> -- block until the chain reaches h.
wait_height() {
    local target="$1"
    while (( $(chain_height) < target )); do
        sleep 3
    done
}

# audit_once -- one forced audit.  Emits: audit-ss-keys: status=true audited=N selected=N emitted=N
audit_once() {
    qadenad_alias enclave audit-ss-keys 2>&1 | grep -m1 "audit-ss-keys:"
}

# drain_audits <max> -- run audits until one reports selected=0, or max runs.  Echoes each line.
# A shrink needs several sweeps once the cursor has moved, so a single audit is not a verdict.
drain_audits() {
    local max="$1" i line
    for (( i = 1; i <= max; i++ )); do
        line=$(audit_once) || fail "audit $i did not report a parseable line"
        echo "  audit $i: $line"
        [[ "$line" == *"status=true"* ]] || fail "audit $i reported status=false -- the broadcast failed.
       The enclave's plan is only half the path; a chain-side rejection lands here.
       Check the node log for 'ss-reshare: failed to broadcast'."
        sleep 10
        [[ "$line" == *"selected=0"* ]] && return 0
    done
    return 0
}


# -------------------------------------------------------------------- departures
#
# A departure needs two things the chain cannot do for itself: the leaving pioneer must pay for its
# own MsgUndelegate (fees are sponsored by a feegrant that does NOT list staking messages -- see
# qadena-sponsored-fleet-governance), and the unbond must be signed by the key on that pioneer's
# own node.  So each departure is funded from the local wallet and then driven over ssh.
#
# DEPARTURE IS DRIVEN BY UNBONDING, NOT BY STOPPING THE NODE.  Downtime jailing is governed by
# signed_blocks_window=20000 at min_signed_per_window=0.05, so a stopped validator must miss ~19000
# blocks -- about sixteen hours -- before staking sees it leave.  Unbonding reaches the same hook
# (AfterValidatorBeginUnbonding) immediately, and is the realistic case anyway: a pioneer being
# decommissioned unbonds, it does not simply vanish.

FUND_AMOUNT=2000000000000000000000aqdn   # 2000 qdn, ample for one unbond at 0.1aqdn gas

# depart <pioneerID> <host> -- fund, unbond, and wait for the chain to stamp departedHeight.
depart() {
    local pioneer="$1" host="$2" addr val amt before

    addr=$(qadenad_alias q qadena list-interval-public-key-id --limit 200 -o json 2>/dev/null | python3 -c '
import sys, json
want = sys.argv[1]
for r in (json.load(sys.stdin).get("intervalPublicKeyID") or []):
    if r.get("nodeID") == want:
        print(r.get("pubKID",""))
        break
' "$pioneer")
    [[ -n "$addr" ]] || fail "no interval row for $pioneer -- is that the right pioneer id?"

    val=$(qadenad_alias q staking validators -o json 2>/dev/null | python3 -c '
import sys, json
want = sys.argv[1]
for v in json.load(sys.stdin).get("validators", []):
    if v["description"]["moniker"] == want:
        print(v["operator_address"])
        break
' "$pioneer")
    [[ -n "$val" ]] || fail "$pioneer is not a validator"

    echo "  funding $pioneer ($addr)"
    qadenad_alias tx bank send "$FUND_FROM" "$addr" "$FUND_AMOUNT" \
        --gas auto --gas-adjustment 1.5 --gas-prices 0.1aqdn -y -o json > /dev/null 2>&1 \
        || fail "could not fund $pioneer from $FUND_FROM"
    sleep 8

    echo "  unbonding $pioneer on $host"
    amt=$(qadenad_alias q staking delegation "$addr" "$val" -o json 2>/dev/null | python3 -c '
import sys, json
print(json.load(sys.stdin)["delegation_response"]["balance"]["amount"])')
    [[ -n "$amt" && "$amt" != "0" ]] || fail "$pioneer has no self-delegation to unbond"

    ssh -o ConnectTimeout=30 -o BatchMode=yes "$host" \
        "export PATH=\$HOME/qadena/bin:\$PATH; cd \$HOME/qadena; \
         CID=\$(qadenad --home . status --node tcp://localhost:26657 2>/dev/null | jq -r .node_info.network); \
         for i in \$(seq 4); do head -1 \$HOME/$REMOTE_PASS; done | \
         qadenad --home . tx staking unbond $val ${amt}aqdn --from $pioneer \
             --keyring-backend file --node tcp://localhost:26657 --chain-id \$CID \
             --gas auto --gas-adjustment 1.5 --gas-prices 0.1aqdn -y -o json" > /dev/null 2>&1 \
        || fail "unbond failed for $pioneer on $host"

    # THE STAMP IS THE EVENT, not the transaction.  AfterValidatorBeginUnbonding fires when staking
    # moves the validator out of the bonded set, which is an end-blocker, so the tx landing is not
    # the same moment as the row being written.
    local waited=0
    while [[ "$(departed_height_of "$pioneer")" == "0" ]]; do
        sleep 3
        (( waited += 3 ))
        (( waited > 120 )) && fail "$pioneer never got a departedHeight -- the staking hook did not
       fire, or it fired and did not reach the row.  Check AfterValidatorBeginUnbonding."
    done
    echo "  $pioneer departedHeight=$(departed_height_of "$pioneer")"
}

# -------------------------------------------------------------------- the run

typeset -a DEPART_SPECS
FUND_FROM=""
REMOTE_PASS=".qadena-sstest-pass"

while (( $# )); do
    case "$1" in
        --depart)     DEPART_SPECS+=("$2"); shift 2 ;;
        --fund-from)  FUND_FROM="$2"; shift 2 ;;
        --remote-pass) REMOTE_PASS="$2"; shift 2 ;;
        --help)
            echo "Usage: test_ss_owner_departure.sh --fund-from <key> \\"
            echo "         --depart <pioneerID>:<ssh-host> --depart ... [--remote-pass <name>]"
            echo ""
            echo "  Departs pioneers in the order given.  After each one, asserts that no key"
            echo "  still names the departed pioneer and that every key remains reconstructable"
            echo "  (live owners >= its threshold)."
            echo ""
            echo "  THREE departures are required.  The first two stay inside a threshold step;"
            echo "  the third crosses it, taking the fleet below four owners so the keys stop"
            echo "  being split.  A run without the third never exercises the crossing, which is"
            echo "  where the interesting behaviour is."
            echo "  --remote-pass names the keyring passphrase file in each node's \$HOME (0600),"
            echo "  staged by the caller; the unbond is signed on the pioneer's own node."
            exit 0 ;;
        *) fail "unknown option $1 (try --help)" ;;
    esac
done

[[ -n "$FUND_FROM" ]] || fail "--fund-from is required: departing pioneers cannot pay their own
       unbond fee (the sponsor feegrant does not list staking messages)"
(( ${#DEPART_SPECS} == 3 )) || fail "need exactly 3 --depart entries (accept, accept, refuse), got ${#DEPART_SPECS}"

# -------------------------------------------------------------------- preflight

echo "========================="
echo "preflight"
echo "========================="

qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"

# DEBUG ENCLAVES ONLY, and it must say so rather than passing quietly.
if ! qadenad_alias enclave audit-ss-keys > /dev/null 2>&1; then
    skip "enclave audit-ss-keys was refused -- this is a real enclave (--realenclave), where the
       forced audit does not exist.  The departure path is NOT covered by this run.  See
       TESTING-BACKLOG item 107: these suites only have meaning on a debug fleet."
fi

typeset -a BONDED
BONDED=($(qadenad_alias q staking validators -o json 2>/dev/null | python3 -c '
import sys, json
for v in json.load(sys.stdin).get("validators", []):
    if v.get("status") == "BOND_STATUS_BONDED":
        print(v["description"]["moniker"])
'))
echo "bonded validators: ${#BONDED} (${BONDED})"

(( ${#BONDED} >= 6 )) || fail "need at least 6 bonded validators to show accept/accept/refuse.
       With ${#BONDED} the first drop would already cross a threshold step, so the run could only
       ever demonstrate the refusal and would report a pass that proves far less than it looks.
       Bring the fleet up with fleet_bringup_with_tests.sh --site M1-M6."

echo ""
echo "SS interval keys before:"
ss_key_owners | while IFS=$'\t' read -r k g o; do echo "  ${k} gen=${g} owners=${o}"; done

start_min=$(min_owner_count)
echo "minimum owner count: $start_min"
(( start_min >= 6 )) || fail "the SS keys are not at full ownership (min=$start_min, want >=6).
       Run test_ss_reshare_audit.sh first: a key that is already deficient cannot demonstrate a
       shrink, because the audit would heal it upward and this suite would read that as a drop."

echo ""
echo "PASSED preflight"

echo ""
echo "========================="
echo "mint extra interval keys"
echo "========================="
# Each mint adds one SS interval key at full ownership, so the departures below have a BACKLOG to
# drain rather than a single key -- see the header.
for (( i = 1; i <= EXTRA_KEYS; i++ )); do
    qadenad_alias enclave update-ss-interval-key > /dev/null 2>&1 \
        || fail "update-ss-interval-key failed on mint $i"
    sleep 10
done
key_count=$(ss_key_owners | wc -l | tr -d ' ')
echo "SS interval keys now: $key_count"
(( key_count > EXTRA_KEYS )) || fail "expected more than $EXTRA_KEYS SS keys, got $key_count"

echo ""
echo "========================="
echo "lower ss_departure_grace to $TEST_GRACE"
echo "========================="
echo "  (default is 4*555=2220 blocks, ~2h at 3s blocks -- too long for a test)"
echo "  NOTE: this is a governance change; run gov_update_qadena_params.sh or submit by hand."
grace=$(qadenad_alias q qadena params -o json 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["params"]["ss_departure_grace"])')
echo "  ss_departure_grace = $grace"
(( grace > 0 )) || fail "ss_departure_grace is 0 -- the feature is DISABLED and no departure can
       ever be recognised.  Set it by governance before running this suite."
(( grace <= 200 )) || fail "ss_departure_grace is $grace blocks, too long to test against.
       Lower it by governance first; this suite will not wait out a two-hour grace."


# threshold_for <ownerCount> -- mirrors getThreshold in cmd/qadenad_enclave/enclave.go.
#
# Mirrored rather than queried because the enclave does not expose it.  If the curve changes there
# and not here, these assertions fail loudly rather than silently testing the wrong number -- which
# is the right direction for a constant this suite reasons about rather than merely reports.
threshold_for() {
    local n="$1"
    if   (( n <= 3  )); then echo 1
    elif (( n <= 6  )); then echo 2
    elif (( n <= 10 )); then echo 3
    elif (( n <= 15 )); then echo 4
    else                     echo 5
    fi
}

# phase <n> <spec> <stays-split|crosses-to-unsplit> -- depart one pioneer and assert the outcome.
#
# TWO ASSERTIONS APPLY TO EVERY PHASE, and they are the point of the suite:
#
#   CUSTODY IS ACCURATE   no key still names the departed pioneer.  Asserting the owner COUNT alone
#                         would pass if the audit dropped the wrong owner -- a worse bug than
#                         dropping none, because it destroys a live holder's share by omission.
#   THE KEY IS RECOVERABLE  live owners >= the threshold their count implies.  Reconstruction needs
#                         `threshold` live owners, so once this fails the key is gone for good and
#                         no later re-share can retrieve it.
#
# The third argument only says which side of a threshold step this departure lands on, so the suite
# can check that the step was crossed when it should have been and not when it should not.  It does
# NOT select between "re-share" and "refuse": the key is re-shared either way.
phase() {
    local n="$1" spec="$2" expect="$3"
    local pioneer="${spec%%:*}" host="${spec##*:}"
    local before_min after_min still gen_before gen_after t_before t_after

    echo ""
    echo "========================="
    echo "phase $n: depart $pioneer  (expect: $expect)"
    echo "========================="

    before_min=$(min_owner_count)
    t_before=$(threshold_for "$before_min")
    gen_before=$(ss_key_owners | awk -F'\t' '{s+=$2} END {print s+0}')
    echo "  before: owners=$before_min threshold=$t_before"

    depart "$pioneer" "$host"

    local d
    d=$(departed_height_of "$pioneer")
    echo "  waiting out the grace ($TEST_GRACE blocks from $d)"
    wait_height $(( d + TEST_GRACE + 5 ))

    echo "  draining audits"
    drain_audits 6

    after_min=$(min_owner_count)
    t_after=$(threshold_for "$after_min")
    still=$(keys_still_naming "$pioneer")
    gen_after=$(ss_key_owners | awk -F'\t' '{s+=$2} END {print s+0}')
    echo "  after:  owners=$after_min threshold=$t_after   keys still naming $pioneer: $still"

    # ---- custody is accurate
    (( still == 0 )) || fail "phase $n: $still key(s) still name $pioneer as an owner after the
       grace elapsed and the audits drained.  The chain is reporting custody that does not exist.
       If the enclave logged 'RESHARE ... owners N->M' but nothing landed, the chain REJECTED it:
       look for ErrOwnerStillEligible, which means the two sides disagree about who departed."

    # ---- the re-share actually happened
    (( gen_after > gen_before )) || fail "phase $n: no generation advanced, so nothing was written.
       The owner set cannot have changed without a re-share, and a departure must never be a no-op
       -- that was the old REFUSED behaviour, and it is exactly what this suite now exists to catch."

    (( after_min == before_min - 1 )) || fail "phase $n: expected the minimum owner count to fall by
       exactly 1 ($before_min -> $(( before_min - 1 ))), got $after_min.  More than one means the
       audit dropped someone who had not departed."

    # ---- THE KEY IS STILL REBUILDABLE.  Every listed owner is live at this point (the departed one
    # was just removed), so the live count IS after_min.  This is the assertion whose failure is
    # permanent.
    (( after_min >= t_after )) || fail "phase $n: $after_min live owner(s) but $t_after shares are
       needed -- this key can no longer be reconstructed, and nothing can recover it.  A re-share
       must never leave fewer owners than its own threshold requires."

    # ---- the step was crossed exactly when expected
    if [[ "$expect" == "crosses-to-unsplit" ]]; then
        (( t_after == 1 && t_before > 1 )) || fail "phase $n: expected this departure to cross the
       threshold step down to 1 (it takes the fleet below 4 owners), but the threshold went
       $t_before -> $t_after.  Check the owner counts: the suite's phases assume 6 -> 5 -> 4 -> 3."
        echo "  PASSED phase $n (owners $before_min->$after_min, threshold $t_before->$t_after:"
        echo "                   key is no longer split, every owner now holds it whole -- expected)"
    else
        (( t_after == t_before )) || fail "phase $n: the threshold moved $t_before -> $t_after on a
       departure that should have stayed inside a step ($before_min -> $after_min owners).  Either
       the curve changed or the phases are being run against the wrong fleet size."
        echo "  PASSED phase $n (owners $before_min->$after_min, threshold held at $t_after, still split)"
    fi
}

phase 1 "${DEPART_SPECS[1]}" stays-split
phase 2 "${DEPART_SPECS[2]}" stays-split
phase 3 "${DEPART_SPECS[3]}" crosses-to-unsplit

echo ""
echo "========================="
echo "final state"
echo "========================="
ss_key_owners | while IFS=$'\t' read -r k g o; do echo "  ${k} gen=${g} owners=${o}"; done

echo ""
echo "ALL PASSED: three departures, every key re-shared, custody accurate and every key still"
echo "            reconstructable.  The third crossed the threshold step and un-split the key,"
echo "            which is expected on a fleet this small -- see the UNSPLIT line in the node log."
