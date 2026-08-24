#!/bin/zsh
#
# Regression test for the SS interval key RE-SHARE AUDIT, measured before and after.
#
# WHAT THE AUDIT IS FOR.  An SS interval key is minted with one share per addressable pioneer at the
# moment of minting.  A fleet that GROWS therefore accumulates keys that are under-owned: a key made
# when one node was addressable has one share, and the three nodes that joined afterwards cannot
# reconstruct it.  The audit walks the owners table and re-shares those keys up to the current fleet
# size, so custody catches up with membership.
#
# WHAT IS ASSERTED, and why before/after rather than a single reading: "every key has enough owners"
# is not a property of a run, it is a property of a TRANSITION.  A chain that was already healthy
# satisfies it without the audit doing anything, so a single reading cannot tell a working audit
# from an audit that did nothing.  This measures both ends and asserts the direction of travel:
#
#   1. the audit RAN and reported parseable numbers        (status=true)
#   2. NO KEY LOST AN OWNER                                 (monotonic -- re-sharing never removes)
#   3. the deficient count did not INCREASE
#   4. after a full sweep, NO KEY IS DEFICIENT              (the guarantee the cursor buys)
#   5. it acted when there was work, and only then:
#        deficient before > 0  =>  some run reported selected > 0
#        deficient before == 0 =>  every run reported selected == 0   (no churn when quiescent)
#
# Assertion 5 is the one that catches a no-op audit.  Without it, an audit that always returned
# selected=0 would pass 1-4 on any healthy chain forever.
#
# enclave.go has maxSSResharesPerRotation, which is the number of keys the audit will re-share in a single run.
# it is deliberately capped at 4, so a single audit run cannot guarantee to sweep the whole table.

# CHECK THIS PART, IT MAY NOT BE CORRECT ANYMORE 
# ONE AUDIT DOES NOT SEE THE WHOLE TABLE.  maxSSAuditScan caps a run at 256 keys, deliberately: the
# audit runs on the block-execution thread and the owners table grows one entry per rotation
# forever, so an uncapped scan is an unbounded and GROWING stall.  Coverage comes from a PERSISTENT
# CURSOR -- ceil(N/256) runs sweep the table with a guarantee.  This sweeps ceil(N/4)+1 times so
# assertion 4 is entitled to demand zero.  (It used to be a random start offset, which gave fair but
# not systematic coverage; a straggler survived k runs with probability (1-256/N)^k, and clearing
# seven of them on M1-M4 took about twenty forced audits.  TESTING-BACKLOG item 106.)
#
# DEBUG ENCLAVES ONLY.  `enclave audit-ss-keys` is a debug affordance and is refused under
# --realenclave, so on SGX this suite cannot run at all.  It SKIPS LOUDLY: a silent pass would read
# as "the audit works on SGX", which this run has not shown and cannot show.
#
# Needs no test users -- it reads chain rows and drives the enclave, so it runs on a bare chain.
# Intended to be scheduled between joins by fleet_bringup_with_tests.sh; see TESTING-BACKLOG 107.

SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

fail() {
    echo ""
    echo "FAILED: $*"
    exit 1
}

# The cap the enclave applies to how many owners a key may have (effectiveShareCap: max of
# maxSSShareSplits=20 and minSSShareSplits=4).  Mirrored rather than queried because the enclave
# does not expose it; if it changes there, change it here and the mismatch shows up as a failure
# rather than as a silently weaker assertion.
SHARE_CAP=20

# Every SS key's owner count, as "pubKID count" lines.  OWNERS ARE THE SHARES ON THE CHAIN ROW --
# PublicKey.shares is repeated, one per pioneerID -- so this is the same number the audit is trying
# to raise.  --count-total/--limit: the default page is 100 and a soak chain holds thousands, so an
# unqualified read would silently measure the oldest 100 and report the rest as unchanged.
owner_counts() {
    local total
    total=$(qadenad_alias q qadena list-public-key --count-total --limit 1 -o json 2>/dev/null \
        | sed -n 's/.*"total":"\([0-9]*\)".*/\1/p')
    [[ -n "$total" ]] || return 1
    qadenad_alias q qadena list-public-key --limit "$total" -o json 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
for r in (d.get("publicKey") or []):
    # WHICH ROWS ARE SS INTERVAL KEYS.  The table holds credential and enclave keys too, and
    # transaction keys that belong to wallets rather than to an interval -- none of which the audit
    # owns or should be judged against.  The discriminator is that an SS interval key is MINTED
    # WITH SHARES: one per addressable pioneer at the moment of minting, so never fewer than one.
    # A transaction row with no shares at all is therefore not an interval key, and counting it made
    # this suite demand owners for wallet keys and fail on a healthy chain.  Verified against the
    # enclave: the filter below yields exactly the count audit-ss-keys reports as audited=.
    if r.get("pubKType") != "transaction":
        continue
    n = len(r.get("shares") or [])
    if n == 0:
        continue
    # KEYED BY pubKID AND TYPE.  The same pubKID legitimately appears under several types (the
    # query itself takes both: show-public-key [pub-kid] [pubk-type]), so pubKID alone collides and
    # the before/after join then compares unrelated rows.
    print(r.get("pubKID","") + "/" + r.get("pubKType",""), n)
'
}

# One forced audit.  Emits: audit-ss-keys: status=true audited=N selected=N emitted=N
audit_once() {
    qadenad_alias enclave audit-ss-keys 2>&1 | grep -m1 "audit-ss-keys:"
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"

if use_real_enclave "$qadenabin/qadenad_enclave"; then
    echo "SKIPPED: this is a real SGX enclave."
    echo "  audit-ss-keys is debug-only and is refused when --realenclave is set, so the re-share"
    echo "  audit cannot be driven here.  It is therefore UNTESTED in this run -- covered on a"
    echo "  debug enclave, and by the unit tests around planSSReshare."
    exit 0
fi

# THE TARGET IS min(addressable pioneers, cap), not the number of nodes: a node that has joined but
# not yet proposed a block since bonding has no external address published, so the audit cannot
# re-share to it and is right not to.  Counting anything else here would demand owners the audit
# has no way to create, and the suite would fail on a healthy chain.
fleet=$(qadenad_alias q qadena list-interval-public-key-id --limit 5000 -o json 2>/dev/null | python3 -c '
import sys, json
rows = json.load(sys.stdin).get("intervalPublicKeyID") or []
print(len([r for r in rows if r.get("nodeType") == "pioneer" and (r.get("externalIPAddress") or "")]))
')
[[ "$fleet" == <-> ]] && (( fleet > 0 )) || fail "could not count addressable pioneers (got \"$fleet\")"
target=$fleet
(( target > SHARE_CAP )) && target=$SHARE_CAP
echo "addressable pioneers: $fleet   target owners per key: $target (cap $SHARE_CAP)"

echo "========================="
echo "1. before"
echo "========================="
before=$(owner_counts) || fail "could not read public keys"
[[ -n "$before" ]] || fail "no SS interval keys on this chain (transaction-type rows carrying shares); nothing to audit"
n_keys=$(print -r -- "$before" | wc -l | tr -d '[:space:]')
def_before=$(print -r -- "$before" | awk -v t="$target" '$2 < t' | wc -l | tr -d '[:space:]')
echo "keys: $n_keys   deficient (< $target owners): $def_before"
print -r -- "$before" | awk '{print $2}' | sort -n | uniq -c \
    | awk '{printf "  %s key(s) with %s owner(s)\n", $1, $2}'

echo "========================="
echo "2. sweep"
echo "========================="
# ceil(n_keys / 4) + 1: enough runs for the cursor to cover the table, plus one so a sweep that
# started mid-table still wraps past every entry.
sweeps=$(( (n_keys + 4) / 4 + 1 ))
echo "running $sweeps audit(s) to guarantee a full sweep of $n_keys key(s)"
sel_total=0
for i in $(seq 1 $sweeps); do
    line=$(audit_once) || fail "audit run $i produced no parseable output"
    echo "  $line"
    [[ "$line" == *"status=true"* ]] || fail "audit run $i did not report status=true: $line"
    sel=$(print -r -- "$line" | sed -n 's/.*selected=\([0-9]*\).*/\1/p')
    emi=$(print -r -- "$line" | sed -n 's/.*emitted=\([0-9]*\).*/\1/p')
    [[ -n "$sel" && -n "$emi" ]] || fail "audit run $i did not report selected/emitted: $line"
    # SELECTING WITHOUT EMITTING IS THE INTERESTING FAILURE: it means the audit found deficient keys
    # and then failed to act, which looks identical to "nothing to do" in the summary count.
    (( sel > 0 && emi == 0 )) && fail "audit run $i selected $sel key(s) but emitted nothing: $line"
    sel_total=$(( sel_total + sel ))
    sleep 6
done
echo "selected across the sweep: $sel_total"

echo "========================="
echo "3. after"
echo "========================="
after=$(owner_counts) || fail "could not re-read public keys"
def_after=$(print -r -- "$after" | awk -v t="$target" '$2 < t' | wc -l | tr -d '[:space:]')
echo "deficient (< $target owners): $def_before -> $def_after"
print -r -- "$after" | awk '{print $2}' | sort -n | uniq -c \
    | awk '{printf "  %s key(s) with %s owner(s)\n", $1, $2}'

# 2. NO KEY LOST AN OWNER.  Re-sharing adds custody; it must never remove it, and a key that lost a
# share has lost the only copy someone held.
lost=$(join <(print -r -- "$before" | sort) <(print -r -- "$after" | sort) \
    | awk '$3 < $2 {print "    " $1 ": " $2 " -> " $3}')
[[ -z "$lost" ]] || fail "a key LOST owners across the audit:
$lost"
echo "no key lost an owner"

# 3. and 4.
(( def_after <= def_before )) || fail "the audit INCREASED the deficient count ($def_before -> $def_after)"
(( def_after == 0 )) || {
    print -r -- "$after" | awk -v t="$target" '$2 < t {printf "    %s has %s owner(s), want %s\n", $1, $2, t}'
    fail "$def_after key(s) still short of $target owners after a full sweep of $sweeps run(s).
         The cursor is supposed to make coverage a guarantee rather than a probability, so a
         straggler here is a real gap, not bad luck."
}
echo "every key has $target owner(s)"

# 5. THE NO-OP CATCH.  Everything above passes on a chain that was already healthy, so the audit has
# to be shown to have DONE something when there was something to do -- and to have left a healthy
# chain alone when there was not.
if (( def_before > 0 )); then
    (( sel_total > 0 )) || fail "there were $def_before deficient key(s) before, yet no audit run selected any.
         The audit is reporting success while doing nothing, which is exactly what this
         assertion exists to catch."
    echo "the audit acted: $def_before deficient key(s) before, $sel_total selected, 0 after"
else
    (( sel_total == 0 )) || fail "nothing was deficient, yet the audit selected $sel_total key(s).
         Re-sharing a key that already has every owner is churn, and it means the deficiency
         test disagrees with the chain rows this suite is reading."
    echo "nothing was deficient and the audit correctly did nothing"
fi

echo ""
echo "SS RE-SHARE AUDIT: PASSED"
