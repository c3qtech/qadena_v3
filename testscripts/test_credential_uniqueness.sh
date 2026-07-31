#!/bin/zsh
#
# Regression test for identity uniqueness across credentials.
#
# THE RULE: uniqueness is enforced at CLAIM time, not CREATE time.  The identity-hash table
# (setCredentialByHash) is only written when a credential is claimed, so an unclaimed credential is
# just a pending offer that reserves nothing.  An identity provider can therefore issue as many
# duplicate credentials as it likes -- it cannot know which offers will be taken up -- and the
# collision is caught when someone tries to take one.
#
# Three enforcement points, all exercised here:
#
#   create   no check at all
#   claim    hash already registered -> ErrCredentialExists
#            (cmd/qadenad_enclave/enclave.go, the `if credentialExists` branch)
#   update   new hash belongs to ANOTHER credential -> ErrCredentialExists; a hash pointing back
#            at the same credential is an allowed idempotent replay
#            (cmd/qadenad_enclave/enclave_update_credential.go)
#
# The comparison is an EXACT match on CreateCredentialHash, which canonicalizes the name fields
# (lowercase, trimmed, whitespace collapsed) precisely so that the match cannot be dodged by
# retyping the same name differently -- case 1d.  Diacritics are NOT folded: "Peña" and "Pena" stay
# separate identities, and x/qadena/common/credential_hash_test.go covers both directions in unit
# form.  Note the hash is computed by the CLI as well as the enclave, which recomputes and compares
# it, so this script exercises both copies agreeing.
#
# Idempotent: claiming a hash reserves it PERMANENTLY, so a fixed identity would collide with the
# previous run rather than with the thing under test.  Every identity, wallet name and claim code
# below carries a per-run id.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

identityprovider="testidentitysrvprv"
sponsor="create-wallet-sponsor"
pioneer="pioneer1"

# Per-run identifiers.  The claim-code "a" values must also be unique: a code is single use, and
# reusing one from an earlier run would fail for the wrong reason.
run_id=$(date +%s)
suffix="${run_id: -6}"          # keep names readable
bf="5678"

base_first="uniqtest"
base_middle="q"
base_last="alpha$suffix"
near_last="alpha$suffix-married"   # differs from base_last, so a different identity hash
birthdate="1980-Jun-15"

w_owner="uniq-owner-$suffix"       # claims the original identity
w_squatter="uniq-squat-$suffix"    # tries to claim the duplicate
w_case="uniq-case-$suffix"         # tries to claim the same identity in a different case
w_married="uniq-married-$suffix"   # claims the near-duplicate

# clash pair for case 3: two identities one character apart in the surname
clash_last_a="bravo$suffix"
clash_last_b="bravos$suffix"       # one insertion from clash_last_a -> a legal correction
w_clash_a="uniq-clash-a-$suffix"
w_clash_b="uniq-clash-b-$suffix"

fail() {
    echo "FAILED: $1"
    exit 1
}

expect_ok() {
    "$@" > /dev/null 2>&1 || fail "expected success: $*"
}

# expect_reject_code <expected-code> <cmd...>
#
# Asserts BOTH that the command fails and WHY.  A bare "did it fail" check is not enough here: the
# update in case 3 could plausibly be refused by the change policy (1154) instead of the collision
# guard (1115), and both cases would still pass while testing nothing about uniqueness.  Pinning the
# codespace code is what makes these regression guards rather than smoke tests.
#
#   1115  ErrCredentialExists            -- the identity hash is already registered
#   1154  ErrCredentialUpdateRejected    -- refused by the change policy
expect_reject_code() {
    local want="$1"; shift
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "expected rejection but it succeeded: $*"
    fi
    if ! echo "$out" | grep -q "codespace qadena code $want"; then
        echo "$out" | grep -oE "codespace qadena code [0-9]+: [A-Za-z ]+" | tail -1
        fail "expected qadena code $want, got the above (or no qadena error at all): $*"
    fi
    echo "rejected as expected (qadena code $want)"
}

mk_wallet() {
    expect_ok qadenad_alias tx qadena create-wallet "$1" "$pioneer" "$sponsor" --yes
}

# issue <code> <first> <middle> <last> -- an identity provider publishing an UNCLAIMED credential
issue() {
    expect_ok qadenad_alias tx qadena create-credential "$1" "$bf" personal-info \
        "$2" "$3" "$4" "$birthdate" "PH" "PH" "F" --from "$identityprovider" --yes
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
qadenad_alias keys show "$identityprovider" -a --keyring-backend test > /dev/null 2>&1 \
    || fail "$identityprovider missing -- run testscripts/setup_prerequisites.sh first"
qadenad_alias keys show "$sponsor" -a --keyring-backend test > /dev/null 2>&1 \
    || fail "$sponsor missing -- run testscripts/setup_prerequisites.sh first"
echo "chain up; run id $suffix"

echo "========================="
echo "1a. a user claims an identity"
echo "========================="
mk_wallet "$w_owner"
issue "${suffix}11" "$base_first" "$base_middle" "$base_last"
expect_ok qadenad_alias tx qadena claim-credential "${suffix}11" "$bf" personal-info --from "$w_owner" --yes
echo "$w_owner claimed \"$base_first $base_middle $base_last\""

echo "========================="
echo "1b. the IdP may issue a DUPLICATE of that identity"
echo "========================="
# Creating reserves nothing -- there is no hash check on the create path -- so this must succeed.
# If it ever starts failing, identity providers lose the ability to reissue, which breaks the
# ordinary case of a user who never claimed their first credential.
issue "${suffix}12" "$base_first" "$base_middle" "$base_last"
echo "duplicate issued, as expected"

echo "========================="
echo "1c. but nobody else may CLAIM it"
echo "========================="
# The squatting defence: an identity already registered by $w_owner cannot be acquired just
# because a second copy of it exists.
mk_wallet "$w_squatter"
expect_reject_code 1115 qadenad_alias tx qadena claim-credential "${suffix}12" "$bf" personal-info --from "$w_squatter" --yes

echo "========================="
echo "1d. nor may they claim it by changing the CASE"
echo "========================="
# CreateCredentialHash canonicalizes names (lowercase, trimmed, whitespace runs collapsed), so
# "UNIQTEST Q ALPHA" is the same identity as "uniqtest q alpha" and hits the same index entry.
# Before that canonicalization existed this claim SUCCEEDED, giving one person two identities and
# defeating case 1c with nothing more than the shift key.  Extra spacing is folded in here too, so
# one transaction covers both halves of the canonicalization.
mk_wallet "$w_case"
issue "${suffix}13" "${(U)base_first}" "${(U)base_middle}" "  ${(U)base_last}  "
expect_reject_code 1115 qadenad_alias tx qadena claim-credential "${suffix}13" "$bf" personal-info --from "$w_case" --yes

echo "========================="
echo "2. a NEAR-duplicate is a different identity and may be claimed"
echo "========================="
# The control for case 1.  Without this, case 1 would still pass if the chain refused every second
# claim -- a different and much worse bug.  Only the surname differs, so the hash differs.
issue "${suffix}21" "$base_first" "$base_middle" "$near_last"
mk_wallet "$w_married"
expect_ok qadenad_alias tx qadena claim-credential "${suffix}21" "$bf" personal-info --from "$w_married" --yes
echo "$w_married claimed \"$base_first $base_middle $near_last\" -- no clash"

echo "========================="
echo "3. a user may not UPDATE into somebody else's claimed identity"
echo "========================="
# Two identities one character apart, both claimed.
mk_wallet "$w_clash_a"
issue "${suffix}31" "$base_first" "$base_middle" "$clash_last_a"
expect_ok qadenad_alias tx qadena claim-credential "${suffix}31" "$bf" personal-info --from "$w_clash_a" --yes
echo "$w_clash_a claimed surname $clash_last_a"

mk_wallet "$w_clash_b"
issue "${suffix}32" "$base_first" "$base_middle" "$clash_last_b"
expect_ok qadenad_alias tx qadena claim-credential "${suffix}32" "$bf" personal-info --from "$w_clash_b" --yes
echo "$w_clash_b claimed surname $clash_last_b"

echo "-------------------------"
echo "$w_clash_b corrects $clash_last_b -> $clash_last_a, which $w_clash_a already holds"
echo "-------------------------"
# The correction is POLICY-LEGAL -- one hash-contributing field, a single-character edit, well
# inside the edit-distance budget -- so a rejection here can only be the collision check.  That
# separation matters: it proves the refusal is about the identity being taken, not about the shape
# of the change.
issue "${suffix}33" "$base_first" "$base_middle" "$clash_last_a"
# 1115 not 1154: the correction is policy-legal, so a policy rejection here would mean the test
# had stopped exercising the collision guard.
expect_reject_code 1115 qadenad_alias tx qadena update-credential "${suffix}33" "$bf" personal-info --from "$w_clash_b" --yes

echo "-------------------------"
echo "and the refused update left both identities intact"
echo "-------------------------"
# A rejection that half-applied would be worse than one that never ran.  Both users must still be
# able to act on their own credentials, which they could not if either row had been corrupted.
a_id=$(qadenad_alias keys show "$w_clash_a-credential" -a --keyring-backend test 2>/dev/null) \
    || fail "could not resolve $w_clash_a's credential"
b_id=$(qadenad_alias keys show "$w_clash_b-credential" -a --keyring-backend test 2>/dev/null) \
    || fail "could not resolve $w_clash_b's credential"
qadenad_alias q qadena show-credential "$a_id" personal-info > /dev/null 2>&1 \
    || fail "$w_clash_a's credential is no longer queryable"
qadenad_alias q qadena show-credential "$b_id" personal-info > /dev/null 2>&1 \
    || fail "$w_clash_b's credential is no longer queryable"
echo "both credentials still present"

echo "========================="
echo "CREDENTIAL UNIQUENESS TESTS PASSED"
echo "========================="
