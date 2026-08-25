#!/bin/zsh
#
# Regression test for the SS interval key rotation grace period.
#
# THE BUG: the enclave rotates the SS interval key every 555 blocks.  A client binds a credential's
# VShare to whichever SS interval public key it reads while BUILDING the transaction; the chain and
# the enclave validate that bind at DELIVERY time against whatever key is current then.  A
# transaction that straddles a rotation was rejected with ErrInvalidVShare (qadena code 1142) -- a
# perfectly well-formed message refused over timing alone.
#
# Seen in the wild on the long-running soak: rotation at height 6105, test_credential_uniqueness.sh
# failing at 6106.  The natural window is one block in 555 (~0.18%), which is exactly why it read as
# "intermittent" and cost so much to pin down.
#
# THE FIX: IntervalPublicKeyID now records previousPubKID, and both validators accept a bind naming
# EITHER the current key or the one it replaced.  The window closes on its own at the next rotation.
#
# WHAT THIS SCRIPT COVERS
#
#   1. State shape -- after a forced rotation, previousPubKID names exactly the key that was current
#      before it.  Deterministic.  If this breaks, the grace has nothing to stand on.
#   2. The straddle itself -- credentials and a dsvs document issued while rotations are forced
#      continuously.  Before the fix this fails within a few operations; after it, everything must
#      succeed.
#
# WHAT IT DELIBERATELY DOES NOT COVER, AND WHY
#
# The bound on the window -- that a bind two rotations stale is still REFUSED -- is not testable
# here.  Reaching it needs a transaction held between build and broadcast, and `--generate-only`
# panics on this command for unrelated reasons (tx_create_credential.go, findCredentialPC is nil).
# That property is covered instead by the unit test
# TestFindVSharePubKInfoAcceptsPreviousIntervalKey/neither_key_is_in_the_bind in
# x/qadena/common/vshare_test.go.  It matters: without a bound, "accept the previous key" would
# decay into "accept any key this node has ever seen", and this script alone would not notice.
#
# Run AFTER testscripts/setup.sh -- except with --key-added-only, which exercises only the rotation
# itself and therefore needs nothing but a running debug-enclave chain.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

# --key-added-only runs ONE rotation and checks ONE thing: that it published exactly one new public
# key.  Everything else here -- the previousPubKID record and the straddle cases -- is about the
# GRACE PERIOD, needs credentials and a dsvs document, and therefore needs setup.sh to have run.
# The minimal check needs none of that, so it also skips the prerequisite guards below: demanding
# testidentitysrvprv on a chain where nothing but the rotation is being exercised would refuse to
# run for a reason that does not apply.
key_added_only=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --key-added-only) key_added_only=1; shift ;;
        --help|-h)
            echo "Usage: test_ss_key_rotation.sh [--key-added-only]"
            echo "  (no flag)          the full rotation suite: grace-period record and straddle cases"
            echo "  --key-added-only   one rotation, assert it published exactly one public key, stop"
            echo "  Both are debug-enclave only; on SGX the suite skips (see preflight)."
            exit 0 ;;
        *) echo "unknown option: $1"; echo "try: $0 --help"; exit 1 ;;
    esac
done

identityprovider="testidentitysrvprv"
dsvsprovider="testdsvssrvprv"
sponsor="create-wallet-sponsor"
pioneer="pioneer1"

run_id=$(date +%s)
suffix="${run_id: -6}"
bf="5678"
birthdate="1980-Jun-15"

fail() {
    echo "FAILED: $1"
    exit 1
}

# Keep the output.  A rejection here IS the finding, and the codespace code is the whole story --
# 1142 means the rotation grace regressed, anything else means something unrelated broke.
expect_ok() {
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "expected success: $*
       exit $rc, output:
$(echo "$out" | tail -6 | sed 's/^/         /')"
    fi
    local code
    code=$(echo "$out" | grep -oE '"?code"?:? *[0-9]+' | head -1 | grep -oE '[0-9]+$')
    if [ -n "$code" ] && [ "$code" != "0" ]; then
        if echo "$out" | grep -q "codespace qadena code 1142"; then
            fail "REJECTED WITH 1142 (Invalid VShare) -- the rotation grace period has regressed: $*
$(echo "$out" | tail -6 | sed 's/^/         /')"
        fi
        fail "expected success but the chain returned code $code: $*
$(echo "$out" | tail -6 | sed 's/^/         /')"
    fi
}

ss_pubkid() {
    qadenad_alias q qadena show-interval-public-key-id ss ss -o json 2>/dev/null \
        | sed -n 's/.*"pubKID":"\([^"]*\)".*/\1/p'
}

ss_previous_pubkid() {
    qadenad_alias q qadena show-interval-public-key-id ss ss -o json 2>/dev/null \
        | sed -n 's/.*"previousPubKID":"\([^"]*\)".*/\1/p'
}

# COUNTED WITH --count-total, never by measuring the returned array.  The default page is 100 rows
# and this chain passes that quickly; a soak node is already past 10,000 public keys.  Counting the
# array would silently stop rising at 100 and the assertion below would then compare two identical
# numbers forever, reporting "no key added" on a healthy chain and, worse, "added exactly 1" never
# again.  pagination.total is the count of the whole table regardless of the page.
ss_pubkey_count() {
    qadenad_alias q qadena list-public-key --count-total --limit 1 -o json 2>/dev/null \
        | sed -n 's/.*"total":"\([0-9]*\)".*/\1/p'
}

# Rotating is asynchronous: UpdateSSIntervalKey hands off to a goroutine that broadcasts three
# messages (enclave.go, updateSSIntervalKey), so the chain state changes some blocks later.  Polling
# for the pubKID to actually change is the difference between a test and a flake.
rotate_and_wait() {
    local before="$1"
    local waited=0
    qadenad_alias enclave update-ss-interval-key > /dev/null 2>&1 \
        || fail "couldn't force an SS interval key rotation"
    while [ $waited -lt 60 ]; do
        if [ "$(ss_pubkid)" != "$before" ]; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    fail "the SS interval key did not change within ${waited}s of a forced rotation"
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"

# The forced rotation is a debug affordance and the enclave refuses it under --realenclave, so on
# SGX this suite cannot run.  Skipping LOUDLY: a silent pass here would read as "the grace period
# works on SGX", which this run has not shown and cannot show.
if ! qadenad_alias enclave update-ss-interval-key > /dev/null 2>&1; then
    echo "SKIPPED: the enclave refused a forced key rotation."
    echo "  update-ss-interval-key is debug-only and is rejected when --realenclave is set, so this"
    echo "  suite cannot drive a rotation on SGX.  The rotation grace period is therefore UNTESTED"
    echo "  in this run.  It is covered on a debug enclave and by the unit tests in"
    echo "  x/qadena/common/vshare_test.go and x/qadena/keeper/interval_public_key_i_d_test.go."
    exit 0
fi

if [ $key_added_only -eq 0 ]; then
    qadenad_alias keys show "$identityprovider" -a --keyring-backend test > /dev/null 2>&1 \
        || fail "$identityprovider missing -- run testscripts/setup_prerequisites.sh first"
    qadenad_alias keys show "$sponsor" -a --keyring-backend test > /dev/null 2>&1 \
        || fail "$sponsor missing -- run testscripts/setup_prerequisites.sh first"
fi
echo "chain up; run id $suffix"

echo "========================="
if [ $key_added_only -eq 1 ]; then
    echo "1. a rotation publishes exactly one new key"
else
    echo "1. a rotation records the key it replaced"
fi
echo "========================="
# The grace period reads previousPubKID out of consensus state rather than reconstructing history,
# because pruning settings, uptime and state-sync method all differ between validators -- "what was
# the key N blocks ago" is not a question every node can answer identically.  So the value has to be
# in the record, and it has to be the RIGHT one.
before=$(ss_pubkid)
[ -n "$before" ] || fail "couldn't read the current SS interval pubKID"
keys_before=$(ss_pubkey_count)
[ -n "$keys_before" ] || fail "couldn't count public keys before the rotation"
echo "current  $before  ($keys_before public keys on chain)"

rotate_and_wait "$before"

after=$(ss_pubkid)
echo "rotated  $after"
[ "$after" != "$before" ] || fail "the pubKID did not change"

# THE GRACE-PERIOD RECORD IS NOT PART OF THE MINIMAL CHECK.  previousPubKID exists for the straddle
# window, which --key-added-only does not exercise; asserting it there would make the flag claim
# more than it ran.
if [ $key_added_only -eq 0 ]; then
    previous=$(ss_previous_pubkid)
    echo "previous $previous"

    [ "$previous" = "$before" ] \
        || fail "previousPubKID is \"$previous\" but the key just replaced was \"$before\".
           Without this the chain has no way to name the previous key, and the grace period
           silently degrades to no grace at all."
    echo "previousPubKID names the replaced key, as expected"
fi

# A ROTATION MUST PUBLISH EXACTLY ONE NEW PUBLIC KEY.  Rotating mints a fresh SS interval key and
# broadcasts it as one MsgPioneerAddPublicKey; the pubKID assertions above prove the POINTER moved,
# and this proves the KEY IT POINTS AT actually reached the chain.  Those are different failures: a
# rotation that advanced the id without publishing the key leaves every peer naming a key it cannot
# fetch, and the pubKID check alone would pass.
#
# EXACTLY one, not "at least one".  Too few means the key never landed.  Too many means a rotation
# minted more than it announced -- which is how a fleet ends up with keys nobody rotated to and no
# record of where they came from.  Both are worth failing on, so the count is compared, not just its
# direction.
keys_after=$(ss_pubkey_count)
[ -n "$keys_after" ] || fail "couldn't count public keys after the rotation"
added=$(( keys_after - keys_before ))
[ "$added" -eq 1 ] \
    || fail "one rotation added $added public keys ($keys_before -> $keys_after), expected exactly 1.
         The SS interval key is published as a single MsgPioneerAddPublicKey; 0 means the new key
         never reached the chain and peers will name a key they cannot fetch, more than 1 means the
         rotation minted keys it did not announce."
echo "the rotation added exactly 1 public key ($keys_before -> $keys_after)"

if [ $key_added_only -eq 1 ]; then
    # SAYING WHAT WAS NOT RUN.  A bare "PASSED" here would read as the rotation suite having passed,
    # and the grace period is the part that actually regressed in the wild.  Naming the gap is the
    # difference between a narrower run and a misleading one.
    echo ""
    echo "--key-added-only: stopping here."
    echo "  NOT RUN: the previousPubKID record, and the straddle cases that prove a transaction"
    echo "  built either side of a rotation is still accepted.  Run without the flag for those."
    exit 0
fi

echo "========================="
echo "2. transactions that straddle a rotation are accepted"
echo "========================="
# Rotations are forced continuously in the background while credentials are issued in the
# foreground.  Each transaction reads the SS key while building and has it validated a block or more
# later, so at this rotation rate a straddle is near-certain rather than a 1-in-555 chance.
#
# This is the shape the bug was first reproduced in -- it failed on the first attempt against the
# unfixed chain.
#
# The rotator tolerates individual failures so a transient one does not abort the run -- but that
# tolerance is exactly how a suite ends up passing while testing nothing.  It counts its successes
# to a file, and the key is re-read at the end, so "the rotations stopped happening" is a FAILURE
# here rather than a silent green.
echo "forcing rotations every 2s in the background"
rotate_count_file=$(mktemp)
echo 0 > "$rotate_count_file"
(
    n=0
    while true; do
        if qadenad_alias enclave update-ss-interval-key > /dev/null 2>&1; then
            n=$((n + 1))
            echo "$n" > "$rotate_count_file"
        fi
        sleep 2
    done
) &
ROTATOR=$!

before_load=$(ss_pubkid)

# Stop the rotator no matter how we leave, or it outlives the script and quietly rotates the key
# under every suite that runs after this one.
cleanup() {
    kill $ROTATOR 2>/dev/null || true
    wait $ROTATOR 2>/dev/null || true
    rm -f "$rotate_count_file" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for i in 1 2 3 4 5; do
    echo "-------------------------"
    echo "round $i: issue and claim a credential while the key rotates"
    echo "-------------------------"
    w="rot-owner-$suffix-$i"
    expect_ok qadenad_alias tx qadena create-wallet "$w" "$pioneer" "$sponsor" --yes
    expect_ok qadenad_alias tx qadena create-credential "${suffix}${i}1" "$bf" personal-info \
        "rottest" "q" "rotlast$suffix$i" "$birthdate" "PH" "PH" "F" --from "$identityprovider" --yes
    expect_ok qadenad_alias tx qadena claim-credential "${suffix}${i}1" "$bf" personal-info --from "$w" --yes
    echo "round $i ok"
done

echo "-------------------------"
echo "a dsvs document, so the second module is covered rather than assumed"
echo "-------------------------"
# x/dsvs builds the same expectation through its own append helper.  It delegates to the qadena
# keeper now, but that is precisely the sort of thing that gets re-forked later, so it is worth
# exercising rather than reasoning about.
if qadenad_alias keys show "$dsvsprovider" -a --keyring-backend test > /dev/null 2>&1; then
    # Signatories come from the same seed file test_dsvs.sh reads, so they cannot drift apart.
    # victor and kelvin specifically: test_credentials.sh mutates al's contacts and removes his
    # email credential outright, which would make signing fail here for a reason that has nothing to
    # do with key rotation.
    sig1_email=$(jq -r '.[] | select(.name=="victor") | .email' "$qadenatestdata/users.json")
    sig1_phone=$(jq -r '.[] | select(.name=="victor") | .phone' "$qadenatestdata/users.json")

    # A document is keyed by its CONTENT hash, so the run id has to be in the bytes -- reusing
    # content fails with "Hash already exists" even under a fresh document id.
    docdir=$(mktemp -d)
    doc="$docdir/rotdoc.txt"
    echo "ss key rotation regression document, run $run_id" > "$doc"

    expect_ok qadenad_alias tx dsvs create-document "rotdoc-$suffix" "ByLaws" "C3Q Technologies, Inc." \
        "$doc" "$sig1_email" "$sig1_phone" --from "$dsvsprovider" --yes
    rm -rf "$docdir"
    echo "dsvs document created while rotating"
else
    echo "SKIPPED the dsvs leg: $dsvsprovider is not provisioned in this run"
fi

echo "-------------------------"
echo "confirm the key really was rotating throughout"
echo "-------------------------"
# Without this the suite is worth very little.  Every transaction above could have been issued
# against a perfectly stable key -- if the rotator had been failing, or the enclave had quietly
# stopped accepting the command, everything would still have passed and reported green while
# exercising none of the behaviour under test.
rotations=$(cat "$rotate_count_file" 2>/dev/null || echo 0)
after_load=$(ss_pubkid)

cleanup
trap - EXIT INT TERM

echo "rotations forced during the load: $rotations"
echo "key before load: $before_load"
echo "key after load:  $after_load"

[ "$rotations" -ge 3 ] \
    || fail "only $rotations rotations were forced during the load phase.
       The transactions above therefore proved little: they may never have straddled a
       rotation at all."
[ "$after_load" != "$before_load" ] \
    || fail "the SS interval key is unchanged after $rotations forced rotations.
       Nothing above can have straddled a rotation, so this run tested nothing."
echo "the key moved while those transactions were in flight"

echo "========================="
echo "SS KEY ROTATION TESTS PASSED"
echo "========================="
