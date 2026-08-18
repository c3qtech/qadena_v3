#!/bin/zsh
#
# add_full_node.sh must REFUSE, and destroy nothing, when the joiner's enclave is not the seed's.
#
# WHY THIS EXISTS.  A joiner bootstraps its trusted set from the seed during sync-enclave, and it can
# only accept that from a seed running its OWN measurement -- that is the single anchor a fresh
# enclave can verify (see verifySeedIsOurBuild).  A mismatch therefore CANNOT succeed.  The question
# this test asks is not "does it fail" but "does it fail BEFORE doing damage": add_full_node.sh
# stops the node, wipes config/, data/, keyring-test/ and all three enclave directories, mints a
# pioneer key and spends a funding transfer, and only then reaches the handshake that must refuse.
#
# The first time this was tried by hand, the pre-check misfired -- it could not reach the seed's
# enclave-measurement query, said so, and CONTINUED, wiping the node exactly as if there were no
# check at all:
#
#     add_full_node.sh: could not ask 192.168.86.162 which enclave it runs
#     Removing configuration directories from: /home/alvillarica/qadena
#
# So this asserts three separate things, and the last two are the ones with teeth:
#
#   1. the run FAILS;
#   2. it names BOTH measurements, so the operator knows which side to fix;
#   3. NOTHING was destroyed or spent -- no key minted, no funding transfer, and the joiner's
#      existing config still there.
#
# A check that is advisory when its query fails is not a check.  If the seed cannot be asked, that is
# itself a reason to stop, since proceeding risks precisely the damage above; the escape hatch should
# be an explicit flag, not a silent fallback.
#
#   ./test_add_full_node_mismatch.sh --primary 192.168.86.162 --joiner 192.168.86.154

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1

PRIMARY=""
JOINER=""
REMOTE_USER="${REMOTE_USER:-$(id -un)}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary) PRIMARY="$2"; shift 2 ;;
        --joiner)  JOINER="$2";  shift 2 ;;
        --help) sed -n '/^#/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n $PRIMARY && -n $JOINER ]] || { print -u2 "need --primary and --joiner"; exit 1 }

fail() { print ""; print "FAILED: $*"; restore; exit 1 }
phase() { print ""; print "=== $* ===" }
on() { local h="$1"; shift; timeout 180 ssh -o ConnectTimeout=10 "$REMOTE_USER@$h" "$@" }

# The joiner's real enclave is put back whatever happens -- including on failure, which is why this
# is a function and not a line at the end.  Leaving a machine with a deliberately wrong enclave
# would poison every later test on it, and the cause would be invisible.
restore() {
    if [[ -n $SAVED ]]; then
        on "$JOINER" "cp '$SAVED' ~/qadena/bin/qadenad_enclave 2>/dev/null && chmod +x ~/qadena/bin/qadenad_enclave"
        print "  restored the joiner's original enclave"
    fi
}
SAVED=""

phase "1. preflight"
seed_measurement=$(on "$PRIMARY" '~/qadena/bin/*d_enclave --unique-id 2>/dev/null' | tr -d '[:space:]')
joiner_measurement=$(on "$JOINER" '~/qadena/bin/*d_enclave --unique-id 2>/dev/null' | tr -d '[:space:]')
[[ -n $seed_measurement && -n $joiner_measurement ]] || fail "could not read both measurements (seed='$seed_measurement' joiner='$joiner_measurement')"
print "  seed runs $seed_measurement, joiner runs $joiner_measurement"

# A binary that is NOT the seed's measurement.  An upgraded chain leaves the previous one on disk as
# qadenad_enclave.<id>, which is exactly what is wanted; without one there is nothing to test with.
other=$(on "$PRIMARY" "ls ~/qadena/bin/qadenad_enclave.* 2>/dev/null" | grep -v "\.$seed_measurement\$" | head -1)
[[ -n $other ]] || { print "SKIPPED: no enclave binary on $PRIMARY with a measurement other than $seed_measurement"; print "         (run the enclave upgrade first -- it leaves the previous build on disk)"; exit 0 }
print "  will give the joiner: $other"

phase "2. record what must survive"
keys_before=$(on "$JOINER" '~/qadena/bin/qadenad --home ~/qadena keys list --keyring-backend test 2>/dev/null | grep -c "^- name:" || echo 0' | tr -d '[:space:]')
config_before=$(on "$JOINER" '[ -f ~/qadena/config/config.toml ] && echo present || echo absent' | tr -d '[:space:]')
print "  joiner has $keys_before key(s), config.toml $config_before"

phase "3. give the joiner a mismatched enclave"
SAVED=$(on "$JOINER" 'cp ~/qadena/bin/qadenad_enclave /tmp/enclave_under_test.bak && echo /tmp/enclave_under_test.bak')
[[ -n $SAVED ]] || fail "could not back up the joiner's enclave"
timeout 300 scp -o ConnectTimeout=10 -q "$REMOTE_USER@$PRIMARY:$other" "/tmp/mismatch_enclave.$$" || fail "could not fetch $other"
timeout 300 scp -o ConnectTimeout=10 -q "/tmp/mismatch_enclave.$$" "$REMOTE_USER@$JOINER:~/qadena/bin/qadenad_enclave" || fail "could not install the mismatched enclave"
rm -f "/tmp/mismatch_enclave.$$"
on "$JOINER" 'chmod +x ~/qadena/bin/qadenad_enclave'
now=$(on "$JOINER" '~/qadena/bin/*d_enclave --unique-id 2>/dev/null' | tr -d '[:space:]')
[[ $now != $seed_measurement ]] || fail "the joiner still measures $now, same as the seed -- nothing would be tested"
print "  joiner now measures $now, seed is $seed_measurement"

phase "4. attempt the join -- it must refuse"
out=$(on "$JOINER" "cd ~/qadena && printf 'y\n' | ./scripts/add_full_node.sh --pioneer mismatchtest \
    --advertise-ip-address $JOINER --genesis-pioneer-first-ip-address $PRIMARY 2>&1")
rc=$?
print -r -- "$out" | grep -aE "MISMATCH|the seed at|this node was built|could not ask" | sed 's/^/    /'

# 1. it must fail
[[ $rc -ne 0 ]] || fail "add_full_node.sh returned success with a mismatched enclave"

# 2. it must name both sides.  "It failed" is not enough: the operator has to know WHICH build to
#    change, and an error that names neither is what this pre-check was written to replace.
print -r -- "$out" | grep -qa "$seed_measurement" && print -r -- "$out" | grep -qa "$now" \
    || fail "the refusal did not name both measurements ($seed_measurement and $now), so it does not tell the operator what to fix"

# 3. AND IT MUST NOT HAVE DESTROYED ANYTHING.  This is the assertion that matters: refusing after
#    wiping the node and spending a funding transfer is not refusing, it is failing late.
print -r -- "$out" | grep -qa "Removing configuration directories" \
    && fail "the node's configuration was WIPED before the refusal -- the check ran too late (or fell through)"
print -r -- "$out" | grep -qaE "minted|funded" \
    && fail "a pioneer key was minted or funded before the refusal -- the check ran too late"

keys_after=$(on "$JOINER" '~/qadena/bin/qadenad --home ~/qadena keys list --keyring-backend test 2>/dev/null | grep -c "^- name:" || echo 0' | tr -d '[:space:]')
config_after=$(on "$JOINER" '[ -f ~/qadena/config/config.toml ] && echo present || echo absent' | tr -d '[:space:]')
[[ $keys_after == $keys_before ]] || fail "key count changed ($keys_before -> $keys_after): the run minted something before refusing"
[[ $config_after == $config_before ]] || fail "config.toml went $config_before -> $config_after: the run wiped state before refusing"
print "  nothing minted, nothing wiped: $keys_after key(s), config.toml $config_after"

restore
print ""
print "PASSED: the join was refused, both measurements were named, and the joiner was left untouched."
