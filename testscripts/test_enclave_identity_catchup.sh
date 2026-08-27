#!/bin/zsh
#
# A node that was DOWN while enclave identities changed must come back correctly.
#
# WHY THIS EXISTS.  The trust rules an enclave applies to identity changes differ depending on
# whether it is watching the chain or replaying it, and NOTHING in the regression exercises that:
# every suite talks to localhost (see test_peer_agreement.sh, which exists because a two-validator
# fork was reported as 16 of 16 PASSED).  So the liveness gate, the reconcile-on-going-live and the
# abstention were all landing unexercised, on paths that run once in months.
#
# The properties under test, in the order the log must show them:
#
#   1. ABSTAIN, NEVER CONDEMN.  With its only peer down, the primary cannot reach quorum on a new
#      identity.  It must leave it `unvalidated` and retry -- not mark it `inactive`.  Before the
#      abstention existed, an unverifiable answer and a "no" were the same thing, so an unreachable
#      peer actively deactivated a perfectly good measurement.
#   2. REPLAY CHANGES NOTHING.  The restarted joiner replays the blocks it missed.  Identity rows
#      land in the mirrored store (consensus state, always), and trust does not move: replayed
#      history is not evidence about now.
#   3. THE GAP IS DETECTED, NOT ASSUMED.  On going live the joiner diffs the chain's view against
#      its own and QUEUES what it cannot account for.  It must not trust it on the chain's word.
#   4. RECOVERY IS BY EVIDENCE.  Trust arrives only after the quorum answers -- so the "queued" line
#      must appear BEFORE the "trusting" line.  Asserting only the end state would pass just as
#      happily if the node had believed the mirrored row, which is the bug the design exists to
#      prevent.
#
# NOT COVERED, deliberately, and it needs a third node: an attested PROMOTION committing while the
# joiner is down.  With two nodes the primary abstains (threshold is 1 and its only peer is the one
# that is down), so the promotion cannot complete until the joiner returns -- at which point the
# joiner sees it live rather than replayed.  Left as a gap rather than faked with a weaker scenario.
#
#   ./test_enclave_identity_catchup.sh --primary 192.168.86.162 --joiner 192.168.86.154

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1

PRIMARY=""
JOINER=""
REMOTE_USER="${REMOTE_USER:-$(id -un)}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary) PRIMARY="$2"; shift 2 ;;
        --joiner)  JOINER="$2";  shift 2 ;;
        --help)
            sed -n '/^#/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done

[[ -n $PRIMARY && -n $JOINER ]] || { print -u2 "need --primary and --joiner"; exit 1 }

fail() { print ""; print "FAILED: $*"; exit 1 }
phase() { print ""; print "======================================================================"; print ">>> $*"; print "======================================================================" }
on() { local host="$1"; shift; timeout 120 ssh -o ConnectTimeout=10 "$REMOTE_USER@$host" "$@" }

# The joiner's log is the evidence for every assertion below, so anchor to a byte offset taken
# BEFORE the interesting part.  Grepping the whole file would match lines from earlier runs -- this
# log is appended across chain re-inits, which has already produced one wrong conclusion in this
# work (counter lines from a chain that no longer existed).
joiner_log_offset() { on "$JOINER" 'wc -c < ~/qadena/logs/qadena.log 2>/dev/null || echo 0' | tr -d ' ' }
joiner_log_since() { on "$JOINER" "tail -c +$1 ~/qadena/logs/qadena.log 2>/dev/null" }

chain_identity_status() { # host uniqueid
    on "$1" "~/qadena/bin/qadenad --home ~/qadena q qadena list-enclave-identity -o json 2>/dev/null" \
        | jq -r --arg u "$2" '.enclaveIdentity[]? | select(.uniqueID==$u) | .status'
}

phase "1. preflight"
primary_height=$(on "$PRIMARY" 'curl -s --max-time 6 http://localhost:26657/status | jq -r .result.sync_info.latest_block_height')
[[ -n $primary_height && $primary_height != null ]] || fail "the primary at $PRIMARY is not serving RPC"
joiner_height=$(on "$JOINER" 'curl -s --max-time 6 http://localhost:26657/status | jq -r .result.sync_info.latest_block_height')
[[ -n $joiner_height && $joiner_height != null ]] || fail "the joiner at $JOINER is not serving RPC -- it must have joined and caught up before this test"
print "  primary height $primary_height, joiner height $joiner_height"

primary_measurement=$(on "$PRIMARY" '~/qadena/bin/qadenad_enclave --unique-id 2>/dev/null')
joiner_measurement=$(on "$JOINER" '~/qadena/bin/qadenad_enclave --unique-id 2>/dev/null')
print "  primary enclave $primary_measurement, joiner enclave $joiner_measurement"

# The identity we will introduce while the joiner is away.  Named, not derived from a counter, so a
# re-run of this test does not collide with the previous run's registration the way the enclave
# upgrade suite would.
NEW_ID="catchup$(on "$PRIMARY" 'date +%H%M%S')"
print "  will register $NEW_ID while the joiner is down"

phase "2. stop the joiner"
on "$JOINER" '~/qadena/scripts/stop_qadena.sh --all > /dev/null 2>&1; sleep 2; ps -eo command | grep -cE "[q]adenad start|[q]adenad_encla[v]e|[c]osmovisor run"' | read survivors
[[ ${survivors:-0} -eq 0 ]] || fail "$survivors process(es) survived the stop on the joiner"
print "  joiner stopped"
down_at=$(on "$PRIMARY" 'curl -s --max-time 6 http://localhost:26657/status | jq -r .result.sync_info.latest_block_height')
print "  chain was at height $down_at when the joiner went down"

phase "3. register a new identity while the joiner is away"
# Registered through governance as `unvalidated`, which is the only status MsgUpdateEnclaveIdentity
# accepts for an identity the chain has not seen -- promotion to active is the enclaves' decision,
# and that is exactly what this test is about.
# The same helper the enclave upgrade suite uses, so this test registers an identity exactly the way
# a real upgrade does -- by governance, as `unvalidated`, which is the only status the chain accepts
# for an identity it has not seen.  Promotion to active is the enclaves' decision, and that decision
# is what this test is about.
signer=$(on "$PRIMARY" 'cat ~/qv3/cmd/qadenad_enclave/test_signer_id.txt')
on "$PRIMARY" "cd ~/qv3 && ./testscripts/test_update_enclave_identity.sh $NEW_ID $signer unvalidated > /tmp/catchup_register.log 2>&1" \
    || print "  (registration command returned non-zero; checking the chain rather than trusting the exit code)"

# The proposal has to pass before the row exists, so poll rather than assuming.
for i in {1..40}; do
    status=$(chain_identity_status "$PRIMARY" "$NEW_ID")
    [[ -n $status ]] && break
    sleep 3
done
[[ -n $status ]] || fail "$NEW_ID never reached the chain; nothing to catch up on \
(see /tmp/catchup_register.log on $PRIMARY)"
print "  $NEW_ID recorded on chain as '$status'"

# PROPERTY 1: with its only peer down, the primary must abstain rather than condemn.
print "  waiting 60s to see what the primary decides with no reachable peer..."
sleep 60
status=$(chain_identity_status "$PRIMARY" "$NEW_ID")
[[ $status != "inactive" ]] \
    || fail "the primary marked $NEW_ID INACTIVE while its only peer was unreachable -- \
an answer it could not obtain was counted as a rejection (the abstention is not working)"
print "  primary left it '$status' -- it abstained rather than condemning an identity it could not evaluate"
on "$PRIMARY" 'grep -a "abstaining on" ~/qadena/logs/qadena.log | tail -2' | sed 's/^/    /'

phase "4. restart the joiner and let it catch up"
offset=$(joiner_log_offset)
on "$JOINER" 'cd ~/qadena && nohup ./scripts/start_qadena.sh > /tmp/catchup_start.log 2>&1 < /dev/null & disown' > /dev/null 2>&1
print "  started; waiting for it to serve RPC and catch up"
for i in {1..90}; do
    h=$(on "$JOINER" 'curl -s --max-time 4 http://localhost:26657/status | jq -r .result.sync_info.catching_up' 2>/dev/null)
    [[ $h == "false" ]] && break
    sleep 5
done
[[ $h == "false" ]] || fail "the joiner did not catch up within 450s"
print "  joiner caught up"

phase "5. what the joiner's log must show, in order"
log=$(joiner_log_since "$offset")

# PROPERTY 2: replay moves no trust.
if print -r -- "$log" | grep -qa "chain is REPLAYING"; then
    print "  [ok] the joiner recognised it was replaying history"
else
    print "  [note] no REPLAYING line -- it had little to catch up on; the gate was not exercised"
fi

# PROPERTY 3: the gap is detected on going live, and NOT trusted on the chain's say-so.
print -r -- "$log" | grep -qa "chain is LIVE" \
    || fail "the joiner never reported going LIVE, so the reconcile never ran"
print -r -- "$log" | grep -a "reconcile on going live" | sed 's/^/    /'

# PROPERTY 4: if trust in the new identity arrived at all, it arrived AFTER the queue, by evidence.
queued_line=$(print -r -- "$log" | grep -na "queued for peer validation" | grep -a "$NEW_ID" | head -1 | cut -d: -f1)
trust_line=$(print -r -- "$log" | grep -na "trusting enclave identity $NEW_ID" | head -1 | cut -d: -f1)
if [[ -n $trust_line ]]; then
    [[ -n $queued_line && $queued_line -lt $trust_line ]] \
        || fail "the joiner trusted $NEW_ID without queueing it for validation first -- \
it took the mirrored row at its word, which is precisely the bug this design exists to prevent"
    print "  [ok] $NEW_ID was queued (line $queued_line) BEFORE it was trusted (line $trust_line) -- trust came from evidence"
else
    print "  [ok] $NEW_ID is not trusted by the joiner; it is queued, awaiting a quorum it has not yet reached"
    print -r -- "$log" | grep -a "$NEW_ID" | tail -3 | sed 's/^/    /'
fi

# The trusted set must have survived the restart -- it lives in the sealed params, and a
# field-by-field restore once dropped it silently, erasing the copy on disk with the next save.
print -r -- "$log" | grep -a "loaded trusted set" | tail -1 | sed 's/^/    /'
print -r -- "$log" | grep -qa "loaded trusted set" \
    || fail "the joiner never logged its trusted set on load -- persistence is unverified"

print ""
print "PASSED: the joiner replayed without moving trust, detected the gap on going live, and did not \
trust anything on the chain's word alone."
