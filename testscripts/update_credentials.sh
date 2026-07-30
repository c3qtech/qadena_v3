#!/bin/zsh

# Exercises MsgUpdateCredential end to end.  Run it after setup.sh, which seeds the identities in
# test_data/users.json and binds each user's phone and email in nameservice (create_user.sh does
# both, so no separate bind step is needed).  The identities this script corrects:
#
#   al   "Rodolfo Alberto" "Asuncion" "Villarica" 1970-Feb-02 M  US/PH  +63288888801
#   jill "Jill"            "Lava"     "Quimba"    1980-Jan-01 F  PH/PH  +63288888803
#   dory "Rhodora Roxas"   "Roxas"    "Villarica" 1970-Feb-03 F  PH/PH  +63288888810
#   ann  "Ann"             "A"        "Cuisia"    1970-Jan-01 F  PH/PH  +63288888802
#
# The CLI lowercases and trims the name and gender args (tx_create_credential.go), so the
# capitalization above is cosmetic.  Citizenship and Residency are NOT part of the identity hash
# (credential_policy.go) -- they are passed through unchanged so a correction does not gratuitously
# flip them.
#
# Each case is numbered to match the verification list in the plan.  Cases that must FAIL are
# checked with an inverted exit status, so a policy that silently starts accepting them breaks the
# script rather than passing quietly.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"

# setup_env.sh provides qadenad_alias as an ALIAS, but expect_ok/expect_reject below invoke their
# arguments with "$@", and command execution does not expand aliases -- every checked case would
# die with "command not found: qadenad_alias".  Shadow it with a function, which "$@" can call.
function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

# setup.sh seeds users from test_data/users.json with the identity provider below, so the
# corrections have to be issued by the same provider
identityprovider="testidentitysrvprv"

# fresh claim codes for the corrected credentials; these must not collide with the small "a" values
# in test_data/users.json or the ones in setup_mnemonic.sh, since a claim code is single-use
al_correct_a="20234"
al_correct_bf="5678"

jill_marry_a="21234"
jill_marry_bf="5678"

reject_a="22234"
reject_bf="5678"

birthdate_reject_a="23234"
birthdate_reject_bf="5678"

swap_a="24234"
swap_bf="5678"

squat_a="25234"
squat_bf="5678"

ratelimit_a="26234"
ratelimit_bf="5678"

unauth_a="27234"
unauth_bf="5678"

al_phone_a="28234"
al_phone_bf="5678"

al_email_a="29234"
al_email_bf="5678"

subcred_a="30234"
subcred_bf="5678"

# override the value from setup_mnemonic.sh so this script owns every code it burns
jill_recover_a="31234"
jill_recover_bf="5678"

# al's seeded contact values, and the new phone/email the contact cases move him to
al_old_phone="+63288888801"
al_new_phone="+63288888899"
al_old_email="alvillarica@c3qtech.com"
al_new_email="al@c3qtech.com"

fail() {
	echo "FAILED: $1"
	exit 1
}

expect_ok() {
	"$@" || fail "expected success: $*"
}

# expect_reject runs a command that MUST fail.  A success here means the chain accepted something
# the policy is supposed to refuse, which is the failure mode this script exists to catch.
expect_reject() {
	if "$@"; then
		fail "expected rejection but it succeeded: $*"
	fi
	echo "rejected as expected"
}

echo "========================="
echo "1. happy correction: al's middle name Asuncion -> Asunción (accent added)"
echo "========================="
# one hash-contributing field, within the edit-distance budget
expect_ok qadenad_alias tx qadena create-credential $al_correct_a $al_correct_bf personal-info "Rodolfo Alberto" "Asunción" "Villarica" "1970-Feb-02" "US" "PH" "M" --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $al_correct_a $al_correct_bf personal-info --from al --yes

echo "-------------------------"
echo "al's credential after the correction (expect updateGeneration 1)"
echo "-------------------------"
al_credential_id=$(qadenad_alias keys show al-credential -a --keyring-backend test 2>/dev/null)
qadenad_alias q qadena show-credential "$al_credential_id" personal-info

echo "========================="
echo "2. life event: jill Quimba -> Villarica (marriage)"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $jill_marry_a $jill_marry_bf personal-info "Jill" "Lava" "Villarica" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $jill_marry_a $jill_marry_bf personal-info --from jill --yes

echo "========================="
echo "3. rejected substitution: first + last + birthdate all change at once"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $reject_a $reject_bf personal-info "Ferdinand" "Romualdez" "Marcos" "1957-Sep-13" "US" "PH" "M" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $reject_a $reject_bf personal-info --from al --yes

echo "-------------------------"
echo "al's credential must be byte-identical to case 1 (rollback proof)"
echo "-------------------------"
qadenad_alias q qadena show-credential "$al_credential_id" personal-info

echo "========================="
echo "4. rejected birthdate substitution: 1970-Feb-02 -> 1995-Aug-13"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $birthdate_reject_a $birthdate_reject_bf personal-info "Rodolfo Alberto" "Asunción" "Villarica" "1995-Aug-13" "US" "PH" "M" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $birthdate_reject_a $birthdate_reject_bf personal-info --from al --yes

echo "========================="
echo "5. accepted month/day swap: dory 1970-Feb-03 -> 1970-Mar-02"
echo "========================="
# the ISO-versus-US entry error.  Two components move, so it only passes via the transposition
# exemption in checkBirthdateCorrection -- dory is used because her seeded Feb-03 is the only
# identity in users.json with a day and month that can actually be transposed
expect_ok qadenad_alias tx qadena create-credential $swap_a $swap_bf personal-info "Rhodora Roxas" "Roxas" "Villarica" "1970-Mar-02" "PH" "PH" "F" --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $swap_a $swap_bf personal-info --from dory --yes

echo "========================="
echo "6. key recovery with jill's OLD surname (Quimba) must still work"
echo "========================="
# the decisive test of hash aliasing: the pre-marriage identity still resolves to the same
# credential, so recovery keeps working with the information jill remembers
expect_ok qadenad_alias tx qadena create-wallet recover-jill pioneer1 --account-mnemonic="$recoverjillmnemonic" create-wallet-sponsor --yes
expect_ok qadenad_alias tx qadena create-credential $jill_recover_a $jill_recover_bf personal-info "Jill" "Lava" "Quimba" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
expect_ok qadenad_alias tx qadena claim-credential $jill_recover_a $jill_recover_bf personal-info --from recover-jill --recover-key --yes

echo "-------------------------"
echo "6a. partner approvals: jill needs all 3 of her users.json recovery partners"
echo "-------------------------"
# claim-credential --recover-key only files the request; the seed phrase is not released until
# len(recoverKey.Signatory) reaches the protect-key threshold, which is 3 for jill.
#
# sign-recover-key takes the wallet the protect-key was FILED UNDER, not the recovery wallet:
# msg_server_protect_private_key.go keys the ProtectKey by msg.Creator, and setup_user_recovery.sh
# signs protect-key with $user-eph1.  (show-recover-key below is the other way round -- it takes
# the new wallet and maps back to the original internally.)
#
# each partner is matched by tx signer address against the share list stored at protect time, so
# the --from below are not interchangeable:
#   testidentitysrvprv  resolved as a service provider  -> --is-service-provider
#   pioneer1            resolved as a pioneer           -> no flag; its share is already held by
#                                                          the pioneer enclave, it only signs
#   victor's email      resolved via nameservice to the sub-wallet that bound
#                       victortorres@c3qtech.com, which is victor-eph1 -> --is-user
jill_protect_wallet="jill-eph1"

expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from $identityprovider --is-service-provider --yes
expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from pioneer1 --yes

echo "-------------------------"
echo "2 of 3 signatories: the seed phrase must still be withheld"
echo "-------------------------"
expect_reject qadenad_alias query qadena show-recover-key recover-jill

expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from victor-eph1 --is-user --yes

echo "-------------------------"
echo "3 of 3 signatories: the seed phrase is released"
echo "-------------------------"
expect_ok qadenad_alias query qadena show-recover-key recover-jill

echo "========================="
echo "7. anti-squat: nobody may claim jill's abandoned maiden identity"
echo "========================="
expect_ok qadenad_alias tx qadena create-wallet squatter pioneer1 create-wallet-sponsor --yes
expect_ok qadenad_alias tx qadena create-credential $squat_a $squat_bf personal-info "Jill" "Lava" "Quimba" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena claim-credential $squat_a $squat_bf personal-info --from squatter --yes

echo "========================="
echo "8. unauthorized: ann may not update al's credential"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $unauth_a $unauth_bf personal-info "Rodolfo Alberta" "Asunción" "Villarica" "1970-Feb-02" "US" "PH" "M" --from $identityprovider --yes
# the CLI derives the credentialID from --from, so this is rejected in the keeper before the enclave
# is ever contacted
expect_reject qadenad_alias tx qadena update-credential $unauth_a $unauth_bf personal-info --from ann --yes

echo "========================="
echo "9. rate limit: a second hash-changing update inside the cool-down window"
echo "========================="
# update_credential_min_blocks_between_updates defaults to 10000 blocks, so al -- corrected in case
# 1 -- must be refused here
expect_ok qadenad_alias tx qadena create-credential $ratelimit_a $ratelimit_bf personal-info "Rodolfo Alberta" "Asunción" "Villarica" "1970-Feb-02" "US" "PH" "M" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $ratelimit_a $ratelimit_bf personal-info --from al --yes

echo "========================="
echo "10. contact update: al's phone number"
echo "========================="
# a contact credential has no identity hash, so any new value is accepted; the change policy has
# nothing to say about it and no alias is recorded
expect_ok qadenad_alias tx qadena create-credential $al_phone_a $al_phone_bf phone-contact-info $al_new_phone --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $al_phone_a $al_phone_bf phone-contact-info --from al --yes

echo "-------------------------"
echo "the OLD number ($al_old_phone) must still resolve to al until it is unbound"
echo "-------------------------"
qadenad_alias query nameservice list-name-binding

echo "-------------------------"
echo "unbind the old number, bind the new one (signed by al-eph2, which create_user.sh bound it from)"
echo "-------------------------"
expect_ok qadenad_alias tx nameservice unbind-credential phone-contact-info $al_old_phone --from al-eph2 --yes
expect_ok qadenad_alias tx nameservice bind-credential al phone-contact-info --from al-eph2 --yes

echo "-------------------------"
echo "the old number must be gone now, the new one present"
echo "-------------------------"
qadenad_alias query nameservice list-name-binding

echo "========================="
echo "11. unbind is owner-only: ann may not retire al's binding"
echo "========================="
# ann-eph2 exists because ann has accept-credential-types in users.json, which is what makes
# create_user.sh mint an eph2 for her
expect_reject qadenad_alias tx nameservice unbind-credential phone-contact-info $al_new_phone --from ann-eph2 --yes

echo "========================="
echo "12. contact update: al's email ($al_old_email -> $al_new_email)"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $al_email_a $al_email_bf email-contact-info $al_new_email --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $al_email_a $al_email_bf email-contact-info --from al --yes

echo "========================="
echo "13. a name sub-credential may not be updated on its own"
echo "========================="
# they only ever move together with the personal-info row they have to agree with, otherwise the
# transfer-time name proof could attest to a name that is not in the identity hash.
# ann is the subject here, not al: al is inside the case-9 cool-down window, so an al attempt would
# be refused for the rate limit and pass this case for the wrong reason
expect_ok qadenad_alias tx qadena create-credential $subcred_a $subcred_bf personal-info "Ann" "A" "Cuisia" "1970-Jan-03" "PH" "PH" "F" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $subcred_a $subcred_bf last-name-personal-info --from ann --yes

echo "========================="
echo "14. a user may remove their own contact credential, but not their identity"
echo "========================="
al_credential_id=$(qadenad_alias keys show al-credential -a --keyring-backend test 2>/dev/null)
expect_reject qadenad_alias tx qadena remove-credential "$al_credential_id" personal-info --from al --yes
expect_reject qadenad_alias tx qadena remove-credential "$al_credential_id" last-name-personal-info --from al --yes
expect_ok qadenad_alias tx qadena remove-credential "$al_credential_id" email-contact-info --from al --yes

echo "-------------------------"
echo "the removal must have propagated from the enclave to the chain"
echo "-------------------------"
expect_reject qadenad_alias q qadena show-credential "$al_credential_id" email-contact-info

echo "========================="
echo "ALL UPDATE CREDENTIAL CASES PASSED"
echo "========================="
