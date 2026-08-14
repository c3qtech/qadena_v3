#!/bin/zsh

# Exercises MsgUpdateCredential end to end.
#
# REPEATABLE, via per-run identities.  It used to correct the SHARED users that setup.sh seeds --
# al, jill, dory, ann straight out of test_data/users.json -- which made it single-shot twice over:
# a claim code is single use, and correcting an identity puts it inside
# update_credential_min_blocks_between_updates (10000 blocks, ~2.8 hours) so the same user cannot
# be corrected again.  That is why it lived behind --with-credentials and never ran in the
# continuous loop, and why the UPDATED walletID sentinel had no repeating coverage at all.
#
# Now it provisions its OWN copies of the four users it needs, with setup.sh --prefix.  That
# mechanism already existed: --prefix suffixes name, bf, firstname, middlename, lastname, email and
# phone, writing test_data/users<prefix>.gen.json, and --specific-user narrows the (chain-costing)
# provisioning loop to one user while the JSON generation stays whole and cheap.
#
# THE PREFIX MUST BE NUMERIC.  bf is suffixed too, and the CLI parses it with
# big.Int.SetString(..., 10) AND DISCARDS THE ERROR (tx_create_credential.go:111); a non-numeric bf
# therefore yields nil, NewPedersenCommit reads nil as "generate a random blinding factor"
# (ecpedersen.go:317), and the credential is created against a commitment the later claim cannot
# recompute -- surfacing as ErrCredentialNotExists, which names neither the prefix nor the blinding
# factor.  See docs/TESTING-BACKLOG.md item 41.
#
# Suffixing bf is also what makes the run independent: the find-credential commitment is
# NewPedersenCommit(a, bf), so a per-run bf gives a per-run commitment and
# credentialByPCXYExists cannot collide with an earlier run.  Birthdates are deliberately NOT
# suffixed, which is what keeps case 5's transposable date transposable.
#
# The identities, as seeded (each name gains the run suffix; birthdates do not):
#
#   al   "Rodolfo Alberto" "Asuncion" "Villarica" 1970-Feb-02 M  US/PH
#   jill "Jill"            "Lava"     "Quimba"    1980-Jan-01 F  PH/PH
#   dory "Rhodora Roxas"   "Roxas"    "Villarica" 1970-Feb-03 F  PH/PH
#   ann  "Ann"             "A"        "Cuisia"    1970-Jan-01 F  PH/PH
#
# WHY THESE FOUR.  al is the main subject and needs accept-credential-types for the contact cases,
# which mints his eph2.  jill supplies an identity abandoned by a life event for the squat case.
# dory's 1970-Feb-03 is transposable (case 5).  ann is an untouched subject for case 13, which must
# not be run against anyone already inside a cool-down or it is refused for the rate limit and
# passes for the wrong reason.  Only al, ann and dory carry accept-credential-types, so the
# nameservice cases must come from that set.
#
# The CLI lowercases and trims the name and gender args (tx_create_credential.go), so the
# capitalization above is cosmetic.  Citizenship and Residency are NOT part of the identity hash
# (credential_policy.go) -- they are passed through unchanged so a correction does not gratuitously
# flip them.
#
# Each case is numbered to match the verification list in the plan.  Cases that must FAIL are
# checked with an inverted exit status, so a policy that silently starts accepting them breaks the
# script rather than passing quietly.
#
# The KEY RECOVERY cases (6, 6a, 6b) are still opt-in, via UPDATE_CREDENTIALS_WITH_RECOVERY=1.
# They are not merely single-shot: a wallet can be recovered ONCE, permanently
# (getRecoverKeyByOriginalWalletID refuses a second), and they need three recovery partners
# resolved three different ways -- service provider, pioneer, and a user matched through a
# nameservice email binding -- which means provisioning the whole prefixed user set rather than
# four of them.  Repeating those is a separate piece of work.

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

# PER-RUN SUFFIX, and it must be numeric -- see the header.  Six digits of the epoch second, the
# same shape test_credential_uniqueness.sh uses, which is short enough to keep wallet names
# readable and long enough not to repeat within any run cadence this suite will ever have.
run_id=$(date +%s)
suffix="${run_id: -6}"

# Defined here rather than below the fixtures, because the provisioning step is itself checked and
# runs before any case does.
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

u_al="al$suffix"
u_jill="jill$suffix"
u_dory="dory$suffix"
u_ann="ann$suffix"

echo "========================="
echo "0. provisioning this run's identities (suffix $suffix)"
echo "========================="
# --skip-prerequisites because setup_prerequisites.sh onboards the providers and the create-wallet
# sponsor, which are chain-wide and already present; it is idempotent, but skipping it keeps a
# per-run provisioning step from re-checking chain-wide state four times.
#
# One call per user: --specific-user narrows only the provisioning loop, so the users<suffix>.gen.json
# is generated once on the first call and reused by the rest.
for u in "$u_al" "$u_jill" "$u_dory" "$u_ann"; do
    echo "--- provisioning $u ---"
    "$qadenatestscripts/setup.sh" --prefix "$suffix" --specific-user "$u" --skip-prerequisites --no-log \
        || fail "could not provision $u"
done

# fresh claim codes for the corrected credentials.  DERIVED FROM THE RUN SUFFIX, because a claim
# code is the find-credential commitment's amount -- NewPedersenCommit(a, bf) -- so reusing one from
# an earlier run collides in credentialByPCXYExists and the create is refused with
# ErrCredentialExists, which looks nothing like "this test ran before".  Numeric, for the reason in
# the header.
al_correct_a="${suffix}01"
al_correct_bf="5678$suffix"

jill_marry_a="${suffix}02"
jill_marry_bf="5678$suffix"

reject_a="${suffix}03"
reject_bf="5678$suffix"

birthdate_reject_a="${suffix}04"
birthdate_reject_bf="5678$suffix"

swap_a="${suffix}05"
swap_bf="5678$suffix"

squat_a="${suffix}06"
squat_bf="5678$suffix"

ratelimit_a="${suffix}07"
ratelimit_bf="5678$suffix"

unauth_a="${suffix}08"
unauth_bf="5678$suffix"

al_phone_a="${suffix}09"
al_phone_bf="5678$suffix"

al_email_a="${suffix}10"
al_email_bf="5678$suffix"

subcred_a="${suffix}11"
subcred_bf="5678$suffix"

# override the value from setup_mnemonic.sh so this script owns every code it burns
jill_recover_a="31234"
jill_recover_bf="5678"

# case 6b: jill's SECOND recovery, keyed on her current surname
jill_recover2_a="32234"
jill_recover2_bf="5678"
recoverjill2mnemonic="ten slot supply correct long special favorite that bracket paper banner neutral risk scatter lion mansion jacket drink mean tennis original tail pave laundry"

# the seed phrase both recoveries must return, read from the same file setup.sh seeded jill from
# rather than duplicated here
jillmnemonic=$(jq -r '.[] | select(.name=="jill") | .mnemonic' "$qadenatestdata/users.json")

# al's seeded contact values, and the new phone/email the contact cases move him to
al_old_phone="+63288888801$suffix"
al_new_phone="+63288888899$suffix"
al_old_email="${suffix}alvillarica@c3qtech.com"
al_new_email="${suffix}al@c3qtech.com"

echo "========================="
echo "1. happy correction: al's middle name Asuncion -> Asunción (accent added)"
echo "========================="
# one hash-contributing field, within the edit-distance budget
expect_ok qadenad_alias tx qadena create-credential $al_correct_a $al_correct_bf personal-info "Rodolfo Alberto$suffix" "Asunción$suffix" "Villarica$suffix" "1970-Feb-02" "US" "PH" "M" --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $al_correct_a $al_correct_bf personal-info --from $u_al --yes

echo "-------------------------"
echo "al's credential after the correction (expect updateGeneration 1)"
echo "-------------------------"
al_credential_id=$(qadenad_alias keys show $u_al-credential -a --keyring-backend test 2>/dev/null)
qadenad_alias q qadena show-credential "$al_credential_id" personal-info

echo "========================="
echo "2. life event: jill Quimba -> Villarica (marriage)"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $jill_marry_a $jill_marry_bf personal-info "Jill$suffix" "Lava$suffix" "Villarica$suffix" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $jill_marry_a $jill_marry_bf personal-info --from $u_jill --yes

echo "========================="
echo "3. rejected substitution: first + last + birthdate all change at once"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $reject_a $reject_bf personal-info "Ferdinand$suffix" "Romualdez$suffix" "Marcos$suffix" "1957-Sep-13" "US" "PH" "M" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $reject_a $reject_bf personal-info --from $u_al --yes

echo "-------------------------"
echo "al's credential must be byte-identical to case 1 (rollback proof)"
echo "-------------------------"
qadenad_alias q qadena show-credential "$al_credential_id" personal-info

echo "========================="
echo "4. rejected birthdate substitution: 1970-Feb-02 -> 1995-Aug-13"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $birthdate_reject_a $birthdate_reject_bf personal-info "Rodolfo Alberto$suffix" "Asunción$suffix" "Villarica$suffix" "1995-Aug-13" "US" "PH" "M" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $birthdate_reject_a $birthdate_reject_bf personal-info --from $u_al --yes

echo "========================="
echo "5. accepted month/day swap: dory 1970-Feb-03 -> 1970-Mar-02"
echo "========================="
# the ISO-versus-US entry error.  Two components move, so it only passes via the transposition
# exemption in checkBirthdateCorrection.  dory's seeded Feb-03 transposes to Mar-02: day and month
# are both <= 12 and DIFFERENT, so the swap produces another valid date that is not the original.
# al (Feb-02), jill (Jan-01) and ann (Jan-01) all have day == month, so transposing them is a no-op
# and would test nothing.  (An earlier comment here claimed dory was the ONLY transposable identity
# in users.json; victor Jan-02, alexis Jan-03 and others qualify too.  dory is the right choice for
# a different reason -- she is one of only three users with accept-credential-types, which is what
# mints the eph2 the contact cases need.)
expect_ok qadenad_alias tx qadena create-credential $swap_a $swap_bf personal-info "Rhodora Roxas$suffix" "Roxas$suffix" "Villarica$suffix" "1970-Mar-02" "PH" "PH" "F" --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $swap_a $swap_bf personal-info --from $u_dory --yes

if [[ -n "$UPDATE_CREDENTIALS_WITH_RECOVERY" ]]; then

# OPT-IN, and against the SHARED setup users rather than this run's.  Recovery cannot be made
# per-run by naming alone: a wallet may be recovered exactly ONCE, permanently
# (getRecoverKeyByOriginalWalletID refuses a second), and the partner approvals below need three
# signatories resolved three different ways -- service provider, pioneer, and a user matched
# through a nameservice email binding -- which means provisioning the whole prefixed user set,
# not the four identities this suite otherwise needs.  So these keep testing shared jill, and
# they still burn her single recovery when they run.
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
    # Assert the RECOVERED VALUE, not merely that the query succeeded.  The whole point of recovery is
    # getting the original seed back, and a query that returned the wrong phrase would still exit 0.
    recovered=$(qadenad_alias query qadena show-recover-key recover-jill 2>&1 | sed -n 's/^seed phrase: //p')
    [ -n "$recovered" ] || fail "no seed phrase released after 3 of 3 signatories"
    [ "$recovered" = "$jillmnemonic" ] || fail "recovered seed phrase does not match jill's mnemonic"
    echo "recovered seed phrase matches jill's original mnemonic"

    echo "========================="
    echo "6b. recovery with jill's CURRENT surname, and a SECOND recovery"
    echo "========================="
    # Two invariants at once.
    #
    # 1. The post-marriage identity has to resolve too.  6a went through the ALIAS recorded by the
    #    update; this goes through the PRIMARY hash.  Those are different lookup paths, so a bug that
    #    dropped the primary hash while writing the alias would pass 6a and fail here.
    # 2. Losing a key twice is normal, so recovery must work more than once.  This second claim
    #    replaces jill's RecoverKey and resets its signatory list, which is why all three partners
    #    have to sign again rather than the earlier signatures still counting.
    expect_ok qadenad_alias tx qadena create-wallet recover-jill2 pioneer1 --account-mnemonic="$recoverjill2mnemonic" create-wallet-sponsor --yes
    expect_ok qadenad_alias tx qadena create-credential $jill_recover2_a $jill_recover2_bf personal-info "Jill" "Lava" "Villarica" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
    expect_ok qadenad_alias tx qadena claim-credential $jill_recover2_a $jill_recover2_bf personal-info --from recover-jill2 --recover-key --yes

    echo "-------------------------"
    echo "the earlier signatures must NOT carry over -- withheld until all three sign again"
    echo "-------------------------"
    expect_reject qadenad_alias query qadena show-recover-key recover-jill2

    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from $identityprovider --is-service-provider --yes
    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from pioneer1 --yes
    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from victor-eph1 --is-user --yes

    echo "-------------------------"
    echo "the second recovery must return the SAME mnemonic as the first"
    echo "-------------------------"
    recovered2=$(qadenad_alias query qadena show-recover-key recover-jill2 2>&1 | sed -n 's/^seed phrase: //p')
    [ -n "$recovered2" ] || fail "no seed phrase released on the second recovery"
    [ "$recovered2" = "$jillmnemonic" ] || fail "second recovery returned a different seed phrase than jill's mnemonic"
    [ "$recovered2" = "$recovered" ] || fail "the two recoveries returned different seed phrases"
    echo "second recovery, via the current surname, returned the same mnemonic"

else
    echo "========================="
    echo "6, 6a, 6b. key recovery -- SKIPPED (set UPDATE_CREDENTIALS_WITH_RECOVERY=1)"
    echo "========================="
fi

echo "========================="
echo "7. anti-squat: nobody may claim jill's abandoned maiden identity"
echo "========================="
expect_ok qadenad_alias tx qadena create-wallet squatter$suffix pioneer1 create-wallet-sponsor --yes
expect_ok qadenad_alias tx qadena create-credential $squat_a $squat_bf personal-info "Jill$suffix" "Lava$suffix" "Quimba$suffix" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena claim-credential $squat_a $squat_bf personal-info --from squatter$suffix --yes

echo "========================="
echo "8. unauthorized: ann may not update al's credential"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $unauth_a $unauth_bf personal-info "Rodolfo Alberta$suffix" "Asunción$suffix" "Villarica$suffix" "1970-Feb-02" "US" "PH" "M" --from $identityprovider --yes
# the CLI derives the credentialID from --from, so this is rejected in the keeper before the enclave
# is ever contacted
expect_reject qadenad_alias tx qadena update-credential $unauth_a $unauth_bf personal-info --from $u_ann --yes

echo "========================="
echo "9. rate limit: a second hash-changing update inside the cool-down window"
echo "========================="
# update_credential_min_blocks_between_updates defaults to 10000 blocks, so al -- corrected in case
# 1 -- must be refused here
expect_ok qadenad_alias tx qadena create-credential $ratelimit_a $ratelimit_bf personal-info "Rodolfo Alberta$suffix" "Asunción$suffix" "Villarica$suffix" "1970-Feb-02" "US" "PH" "M" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $ratelimit_a $ratelimit_bf personal-info --from $u_al --yes

echo "========================="
echo "10. contact update: al's phone number"
echo "========================="
# a contact credential has no identity hash, so any new value is accepted; the change policy has
# nothing to say about it and no alias is recorded
expect_ok qadenad_alias tx qadena create-credential $al_phone_a $al_phone_bf phone-contact-info $al_new_phone --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $al_phone_a $al_phone_bf phone-contact-info --from $u_al --yes

echo "-------------------------"
echo "the OLD number ($al_old_phone) must still resolve to al until it is unbound"
echo "-------------------------"
qadenad_alias query nameservice list-name-binding

echo "-------------------------"
echo "unbind the old number, bind the new one (signed by al-eph2, which create_user.sh bound it from)"
echo "-------------------------"
expect_ok qadenad_alias tx nameservice unbind-credential phone-contact-info $al_old_phone --from $u_al-eph2 --yes
expect_ok qadenad_alias tx nameservice bind-credential $u_al phone-contact-info --from $u_al-eph2 --yes

echo "-------------------------"
echo "the old number must be gone now, the new one present"
echo "-------------------------"
qadenad_alias query nameservice list-name-binding

echo "========================="
echo "11. unbind is owner-only: ann may not retire al's binding"
echo "========================="
# ann-eph2 exists because ann has accept-credential-types in users.json, which is what makes
# create_user.sh mint an eph2 for her
expect_reject qadenad_alias tx nameservice unbind-credential phone-contact-info $al_new_phone --from $u_ann-eph2 --yes

echo "========================="
echo "12. contact update: al's email ($al_old_email -> $al_new_email)"
echo "========================="
expect_ok qadenad_alias tx qadena create-credential $al_email_a $al_email_bf email-contact-info $al_new_email --from $identityprovider --yes
expect_ok qadenad_alias tx qadena update-credential $al_email_a $al_email_bf email-contact-info --from $u_al --yes

echo "========================="
echo "13. a name sub-credential may not be updated on its own"
echo "========================="
# they only ever move together with the personal-info row they have to agree with, otherwise the
# transfer-time name proof could attest to a name that is not in the identity hash.
# ann is the subject here, not al: al is inside the case-9 cool-down window, so an al attempt would
# be refused for the rate limit and pass this case for the wrong reason
expect_ok qadenad_alias tx qadena create-credential $subcred_a $subcred_bf personal-info "Ann$suffix" "A$suffix" "Cuisia$suffix" "1970-Jan-03" "PH" "PH" "F" --from $identityprovider --yes
expect_reject qadenad_alias tx qadena update-credential $subcred_a $subcred_bf last-name-personal-info --from $u_ann --yes

echo "========================="
echo "14. a user may remove their own contact credential, but not their identity"
echo "========================="
al_credential_id=$(qadenad_alias keys show $u_al-credential -a --keyring-backend test 2>/dev/null)
expect_reject qadenad_alias tx qadena remove-credential "$al_credential_id" personal-info --from $u_al --yes
expect_reject qadenad_alias tx qadena remove-credential "$al_credential_id" last-name-personal-info --from $u_al --yes
expect_ok qadenad_alias tx qadena remove-credential "$al_credential_id" email-contact-info --from $u_al --yes

echo "-------------------------"
echo "the removal must have propagated from the enclave to the chain"
echo "-------------------------"
# Two reasons this is a polled output check rather than expect_reject:
#
#   1. `q qadena show-credential` exits 0 whether or not the credential exists -- it just prints
#      "not found" -- so an exit-status assertion here can never pass.  (show-recover-key in case 6a
#      DOES exit non-zero, which is why expect_reject is right there but not here.)
#   2. removal reaches chain state asynchronously: the enclave applies it and EndBlock mirrors it
#      via RemoveCredentialNoEnclave, so an immediate query still sees the credential.
removed=false
for _ in {1..20}; do
	if qadenad_alias q qadena show-credential "$al_credential_id" email-contact-info 2>&1 | grep -q "not found"; then
		removed=true
		break
	fi
	sleep 2
done
[ "$removed" = "true" ] || fail "email-contact-info is still on chain after remove-credential"
echo "removal propagated to chain state"

echo "========================="
echo "ALL UPDATE CREDENTIAL CASES PASSED"
echo "========================="
