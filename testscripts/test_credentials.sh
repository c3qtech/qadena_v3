#!/bin/zsh

# Exercises MsgUpdateCredential end to end.
#
# REPEATABLE, via per-run identities.  It used to correct the SHARED users that setup.sh seeds --
# al, jill, dory, ann straight out of test_data/users.json -- which made it single-shot twice over:
# a claim code is single use, and correcting an identity puts it inside
# update_credential_min_blocks_between_updates (10000 blocks, ~2.8 hours) so the same user cannot
# be corrected again.  That is why it lived behind a regression.sh opt-in flag and never ran in the
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
# The KEY RECOVERY cases (6, 6a, 6b) RUN BY DEFAULT, against THIS RUN'S jill like every other case.
# Set TEST_CREDENTIALS_SKIP_RECOVERY=1 to leave them out -- an escape hatch, not a gate: they cost
# one protect-key and a handful of transactions, so the reason to skip them is a chain that cannot
# afford the traffic, not a correctness constraint.  regression.sh reaches this through its ordinary
# --skip recovery.
#
# THEY WERE OPT-IN UNTIL THE PER-RUN MOVE, and the opt-in was load-bearing then: against the shared
# jill a wallet's protect-key could be filed once and her claim codes burned once, so a second run
# had nothing left to recover.  Per-run jill files a per-run protect-key with per-run recovery
# wallets, mnemonics and claim codes, so nothing carries between runs and the cases repeat.  That is
# the whole reason the flag could go: what it was protecting no longer exists.
#
# They used to run against the shared jill, justified by two claims.  One was simply wrong: a wallet
# can be recovered more than once -- case 6b is itself a second recovery, and asserts that the
# earlier signatures do not carry over.  The other was a real constraint read one step too far: the
# three partners must be resolvable three different ways (service provider, pioneer, and a user
# matched through a nameservice email binding), which was taken to mean the whole prefixed user set
# had to be provisioned.  It does not.  PARTNERS ONLY SIGN, and setup.sh's --prefix generator copies
# .recovery verbatim, so a per-run user already names the SHARED partners.
#
# The actual blocker was neither: setup.sh --specific-user used to `exit 0` before its recovery
# section, so a prefixed user was provisioned but never got a protect-key.  With that fixed, these
# cases cost one protect-key.
#
# Running them against the shared jill is what silently broke them.  The marriage in case 2 renames
# PER-RUN jill, so 6b asked to recover SHARED jill through a married name she had never been given,
# and failed; while case 6 kept passing for the wrong reason, because shared jill was never married
# and "her old surname" was simply her only one -- so the alias lookup it exists to test was never
# tested at all.

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
#
# ASK THE CHAIN, NOT THE EXIT CODE.  This used to be `if "$@"; then fail`, which is only right when
# the rejection happens at CheckTx.  When the chain is busy the transaction is admitted to a BLOCK
# and refused during execution -- broadcast succeeded, so `tx` exits ZERO and this reported a
# correctly-refused transaction as accepted.  It failed this suite 19 times in 27 continuous cycles
# while the chain rejected every single one.  tx_reject_code reads the delivered result.
expect_reject() {
	local code
	code=$(tx_reject_code "$@")
	if [ -z "$code" ] || [ "$code" = "0" ]; then
		fail "expected rejection but the chain ACCEPTED it: $*"
	fi
	echo "rejected as expected (qadena code $code)"
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

# Claim codes for the two recoveries.  PER-RUN like every other code in this file: a claim code is
# the find-credential commitment's amount, so a fixed one collides in credentialByPCXYExists on the
# second run and the create is refused with ErrCredentialExists.
jill_recover_a="${suffix}12"
jill_recover_bf="5678$suffix"

# case 6b: jill's SECOND recovery, keyed on her current surname
jill_recover2_a="${suffix}13"
jill_recover2_bf="5678$suffix"

# The wallets the recoveries land in, and the seed phrase they must return.
#
# ALL PER-RUN, which is the point of this block.  These cases used to run against the SHARED jill
# that setup.sh seeds, because setup.sh --specific-user skipped recovery provisioning entirely and a
# prefixed user therefore never got a protect-key.  With that skip removed, per-run jill has her own
# protect-key -- filed with the SAME shared partners, because the generator copies .recovery verbatim
# and partners only sign -- so the recovery cases can finally test the identity this run actually
# married.
#
# That drift is what broke case 6b: the marriage in case 2 renamed PER-RUN jill, while 6b asked to
# recover SHARED jill through a married name nobody had ever given her.  It also left case 6 passing
# for the wrong reason -- shared jill was never married, so "her old surname" was simply her only
# surname, and the alias lookup it claims to exercise was never exercised at all.
recover_jill_wallet="recover-jill$suffix"
recover_jill2_wallet="recover-jill2$suffix"
recoverjillmnemonic=$(qadenad_alias keys mnemonic --keyring-backend test)
recoverjill2mnemonic=$(qadenad_alias keys mnemonic --keyring-backend test)

# jill's protect-key is filed under her eph1, by msg.Creator -- see the note in case 6a.
jill_protect_wallet="$u_jill-eph1"

# The seed phrase both recoveries must return: PER-RUN jill's, from the generated file setup.sh
# seeded her from.  setup.sh mints a fresh mnemonic per prefixed user, so this cannot be read from
# the shared users.json.
jillmnemonic=$(jq -r --arg n "$u_jill" '.[] | select(.name==$n) | .mnemonic' "$qadenatestdata/users${suffix}.gen.json")

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

# The old spelling is still honoured.  This script was update_credentials.sh, and the variable was
# named after it; someone with the old name in a shell history or a CI job would otherwise find the
# recovery cases quietly running again rather than being skipped, which is the wrong direction for
# an escape hatch to fail in.
: ${TEST_CREDENTIALS_SKIP_RECOVERY:=$UPDATE_CREDENTIALS_SKIP_RECOVERY}

# WHAT THE GUARDIAN IDENTITY-ASSERTION GATE DOES TO THESE CASES.
#
# The recovery cases below are signed by three partners, and TWO of them are INSTITUTIONAL:
# $identityprovider (resolved as a service provider) and pioneer1 (resolved as a pioneer).  Only
# victor-eph1, matched as a raw bech32 address, is an individual.  That classification is what
# sign_recover_key_guardian_assertion_mode acts on, so this suite's behaviour depends on the param
# and the cases have to be chosen from it rather than assumed:
#
#   0 off      nothing looks at the assertion; these cases run exactly as they always did.
#   1 audit    the enclave resolves and compares, LOGS a mismatch, and still accepts.  These
#              signatures carry no assertion, so each institutional one logs
#              "guardian-assertion: MISMATCH" and is accepted.  The suite must still pass --
#              that is the whole point of the state, and it is the value config/config.yml
#              currently ships for the devnet.
#   2 enforce  an institutional signature with no assertion is REFUSED.  Two of the three
#              partners cannot sign, the threshold is never met, and no seed phrase is released.
#
# AT ENFORCE THESE CASES ARE SKIPPED, NOT FAILED, and not quietly.  Completing them needs the
# guardian to send the identity hash it verified, which is produced by the app-server half of this
# change -- and computing it here is not a shortcut worth taking: the hash must be byte-identical to
# the one issuance produced, and a test that derives it independently would prove only that the test
# agrees with itself.  `sign-recover-key --guardian-credential-hash <hex>` is the flag to use once a
# real producer exists.
#
# The gate's own behaviour in all three modes is covered where it can be asserted precisely:
# cmd/qadenad_enclave/enclave_guardian_assertion_test.go drives the real SignRecoverKey handler
# across every param state, both guardian classes, and matching/mismatched/absent assertions.
# BASELINE THE ENCLAVE'S ASSERTION COUNTER BEFORE ANY SIGNATURE, so the checks below can measure
# what THIS run produced.  The log file is per-day and cumulative, so an absolute count says nothing
# on a chain that has already run today -- only the delta does.  Read before the mode branch because
# BOTH branches need it: audit asserts the gate spoke, enforce asserts the refusals came from it.
enclave_log=$(ls -t "$QADENAHOME/logs"/qadena-*.log 2>/dev/null | head -1)
# -a because the log carries ANSI colour and the occasional binary byte, which otherwise makes grep
# report "Binary file matches" and print no count at all.
assertion_lines_before=0
if [[ -n "$enclave_log" ]]; then
    assertion_lines_before=$(grep -ac "guardian-assertion: MISMATCH" "$enclave_log" 2>/dev/null)
    [[ -n "$assertion_lines_before" ]] || assertion_lines_before=0
fi

guardian_assertion_mode=$(qadenad_alias query qadena params --output json 2>/dev/null \
    | jq -r '.params.sign_recover_key_guardian_assertion_mode // 0')
[[ -n "$guardian_assertion_mode" ]] || guardian_assertion_mode=0
echo "guardian identity-assertion mode: $guardian_assertion_mode"

if [[ "$guardian_assertion_mode" -ge 2 && -z "$TEST_CREDENTIALS_SKIP_RECOVERY" ]]; then
    echo "========================="
    echo "6e. ENFORCE: an institutional guardian with no identity assertion is REFUSED"
    echo "========================="
    # THE SECURITY PROPERTY, ON A REAL CHAIN.  Everything else in this suite tests that recovery
    # WORKS; this tests that it stops working for the case the gate exists to stop.
    #
    # The full happy path cannot run at enforce, and deliberately is not faked: completing it needs
    # the guardian to send the identity hash it verified, produced by the app-server half.  A test
    # that derived that hash itself would prove only that the test agrees with itself -- the whole
    # value of the check is that the hash was computed independently, at issuance, by different
    # code.  So what is asserted here is the half that needs no producer, which happens to be the
    # half that matters:
    #
    #   * an institutional signature carrying NO assertion is REFUSED
    #   * an INDIVIDUAL signature is still ACCEPTED -- the exemption has to hold precisely where
    #     enforcement is on, or enforcing would break recovery for family and friends, the class
    #     this control was never aimed at
    #   * the seed phrase stays WITHHELD, because the threshold can no longer be met
    #
    # AN ENFORCE-SPECIFIC BASELINE.  assertion_lines_before counts MISMATCH lines in EVERY mode,
    # so subtracting it from a mode=enforce count would go NEGATIVE on any log that already holds
    # audit lines -- which is every chain that ran this suite before the mode was raised.  Count the
    # same pattern that is checked later, and count it here, before a single signature is sent.
    enforce_before=0
    if [[ -n "$enclave_log" ]]; then
        enforce_before=$(grep -ac "guardian-assertion: MISMATCH mode=enforce" "$enclave_log" 2>/dev/null)
        [[ -n "$enforce_before" ]] || enforce_before=0
    fi

    # Same setup as case 6, against this run's jill.
    expect_ok qadenad_alias tx qadena create-wallet $recover_jill_wallet pioneer1 --account-mnemonic="$recoverjillmnemonic" create-wallet-sponsor --yes
    expect_ok qadenad_alias tx qadena create-credential $jill_recover_a $jill_recover_bf personal-info "Jill$suffix" "Lava$suffix" "Quimba$suffix" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
    expect_ok qadenad_alias tx qadena claim-credential $jill_recover_a $jill_recover_bf personal-info --from $recover_jill_wallet --recover-key --yes

    echo "-------------------------"
    echo "the service-provider guardian is refused"
    echo "-------------------------"
    expect_reject qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from $identityprovider --is-service-provider --yes

    echo "-------------------------"
    echo "the PIONEER guardian is refused too -- institutional is not only --is-service-provider"
    echo "-------------------------"
    # pioneer1 resolves through PioneerNodeType, which puts it in the same class.  Asserted
    # separately because it is the classification most likely to be misread: nothing on the command
    # line marks pioneer1 as institutional.
    expect_reject qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from pioneer1 --yes

    echo "-------------------------"
    echo "the INDIVIDUAL guardian is still accepted"
    echo "-------------------------"
    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from victor-eph1 --is-user --yes

    echo "-------------------------"
    echo "the seed phrase stays withheld: 1 of 3, and the other two cannot sign"
    echo "-------------------------"
    expect_reject qadenad_alias query qadena show-recover-key $recover_jill_wallet

    echo "-------------------------"
    echo "and the refusals were the GATE, not something else"
    echo "-------------------------"
    # A signature can be refused for plenty of reasons that have nothing to do with this change --
    # a missing recover key, a guardian that is not a partner, an already-signed record.  Without
    # this the two expect_reject calls above would pass just as well against a chain where recovery
    # was broken outright, which would read as the gate working while it did nothing.
    if [[ -z "$enclave_log" ]]; then
        echo "  no enclave log under $QADENAHOME/logs -- cannot confirm the reason, not failing"
    else
        enforce_lines=$(grep -ac "guardian-assertion: MISMATCH mode=enforce" "$enclave_log" 2>/dev/null)
        [[ -n "$enforce_lines" ]] || enforce_lines=0
        enforce_delta=$(( enforce_lines - enforce_before ))
        [[ "$enforce_delta" -ge 2 ]] || fail "the two institutional signatures were refused, but the enclave
  logged only $enforce_delta guardian-assertion MISMATCH line(s) at mode=enforce (expected at least 2).
  They were rejected for some OTHER reason, so this case is not testing the gate."
        echo "  confirmed: $enforce_delta refusal(s) attributed to the identity assertion gate"
    fi

    echo "========================="
    echo "6f. the rest of the recovery flow is NOT run at enforce"
    echo "========================="
    echo "  Cases 6, 6a and 6b need all three partners to sign, and two of them cannot without an"
    echo "  identity hash from the app-server half.  Pass one with"
    echo "  sign-recover-key --guardian-credential-hash <hex> once that exists."
    echo "  The accept-a-correct-assertion path is covered meanwhile by"
    echo "  cmd/qadenad_enclave/enclave_guardian_assertion_test.go, which drives the real handler."
    TEST_CREDENTIALS_SKIP_RECOVERY=1
fi

if [[ -z "$TEST_CREDENTIALS_SKIP_RECOVERY" ]]; then

# ON BY DEFAULT, and against THIS RUN'S jill -- see the header for why these used to use the shared
# one, what that cost, and why they are no longer opt-in.  The partners stay shared on purpose: they
# only sign, and the generator copies .recovery verbatim, so per-run jill's protect-key already
# names them.
    echo "========================="
    echo "6. key recovery with jill's OLD surname (Quimba) must still work"
    echo "========================="
    # THE DECISIVE TEST OF HASH ALIASING, and only now that it runs against the jill case 2 actually
    # married: her pre-marriage identity is a genuine ALIAS on her credential, so recovery keeps
    # working with the information she remembers rather than the name she now has.
    #
    # Against the shared jill this passed while testing nothing -- she was never married, so Quimba
    # was simply her only surname and the lookup never went through an alias at all.
    expect_ok qadenad_alias tx qadena create-wallet $recover_jill_wallet pioneer1 --account-mnemonic="$recoverjillmnemonic" create-wallet-sponsor --yes
    expect_ok qadenad_alias tx qadena create-credential $jill_recover_a $jill_recover_bf personal-info "Jill$suffix" "Lava$suffix" "Quimba$suffix" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
    expect_ok qadenad_alias tx qadena claim-credential $jill_recover_a $jill_recover_bf personal-info --from $recover_jill_wallet --recover-key --yes

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
    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from $identityprovider --is-service-provider --yes
    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from pioneer1 --yes

    echo "-------------------------"
    echo "2 of 3 signatories: the seed phrase must still be withheld"
    echo "-------------------------"
    expect_reject qadenad_alias query qadena show-recover-key $recover_jill_wallet

    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from victor-eph1 --is-user --yes

    echo "-------------------------"
    echo "3 of 3 signatories: the seed phrase is released"
    echo "-------------------------"
    # Assert the RECOVERED VALUE, not merely that the query succeeded.  The whole point of recovery is
    # getting the original seed back, and a query that returned the wrong phrase would still exit 0.
    recovered=$(qadenad_alias query qadena show-recover-key $recover_jill_wallet 2>&1 | sed -n 's/^seed phrase: //p')
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
    expect_ok qadenad_alias tx qadena create-wallet $recover_jill2_wallet pioneer1 --account-mnemonic="$recoverjill2mnemonic" create-wallet-sponsor --yes
    expect_ok qadenad_alias tx qadena create-credential $jill_recover2_a $jill_recover2_bf personal-info "Jill$suffix" "Lava$suffix" "Villarica$suffix" "1980-Jan-01" "PH" "PH" "F" --from $identityprovider --yes
    expect_ok qadenad_alias tx qadena claim-credential $jill_recover2_a $jill_recover2_bf personal-info --from $recover_jill2_wallet --recover-key --yes

    echo "-------------------------"
    echo "the earlier signatures must NOT carry over -- withheld until all three sign again"
    echo "-------------------------"
    expect_reject qadenad_alias query qadena show-recover-key $recover_jill2_wallet

    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from $identityprovider --is-service-provider --yes
    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from pioneer1 --yes
    expect_ok qadenad_alias tx qadena sign-recover-key $jill_protect_wallet --from victor-eph1 --is-user --yes

    echo "-------------------------"
    echo "the second recovery must return the SAME mnemonic as the first"
    echo "-------------------------"
    recovered2=$(qadenad_alias query qadena show-recover-key $recover_jill2_wallet 2>&1 | sed -n 's/^seed phrase: //p')
    [ -n "$recovered2" ] || fail "no seed phrase released on the second recovery"
    [ "$recovered2" = "$jillmnemonic" ] || fail "second recovery returned a different seed phrase than jill's mnemonic"
    [ "$recovered2" = "$recovered" ] || fail "the two recoveries returned different seed phrases"
    echo "second recovery, via the current surname, returned the same mnemonic"

    # WHAT THE GATE DID, MEASURED -- for BOTH states this script can reach.
    #
    # At mode 1 the recovery cases pass in exactly the same way they pass at mode 0: every signature
    # is accepted either way, so nothing in this script's exit codes distinguishes a working audit
    # from a gate that is silently inert.  The only observable difference is in the enclave log.
    #
    # So both directions are asserted, and each catches the opposite failure:
    #
    #   mode 0  the gate must have logged NOTHING.  A non-zero delta means it is evaluating
    #           assertions on a chain that never asked it to -- which at best wastes work and at
    #           worst starts refusing signatures the operator did not opt into.
    #   mode 1  the gate must have logged at least the TWO institutional signatures per recovery
    #           ($identityprovider as a service provider, pioneer1 as a pioneer), neither of which
    #           carries an assertion.  A zero delta means the gate is inert -- the params never
    #           reached the enclave, or the class test stopped matching service providers -- and
    #           raising the mode to 2 later would silently protect nothing.
    #
    # Mode 2 is not reachable here: the cases are skipped above, because they cannot complete
    # without a producer for the identity hash.
    echo "========================="
    echo "6c. what the guardian assertion gate did during these recoveries"
    echo "========================="
    if [[ -z "$enclave_log" ]]; then
        echo "  no enclave log under $QADENAHOME/logs -- cannot measure, not failing"
    else
        assertion_lines_after=$(grep -ac "guardian-assertion: MISMATCH" "$enclave_log" 2>/dev/null)
        [[ -n "$assertion_lines_after" ]] || assertion_lines_after=0
        delta=$(( assertion_lines_after - assertion_lines_before ))
        echo "  mode $guardian_assertion_mode: $delta MISMATCH line(s) logged by these recoveries"

        if [[ "$guardian_assertion_mode" -eq 0 ]]; then
            [[ "$delta" -eq 0 ]] || fail "the chain is at mode 0 (off) but the enclave logged $delta
  guardian-assertion MISMATCH line(s).  Off must mean the assertion is not looked at AT ALL, so the
  gate is running when nothing asked it to."
            echo "  correct: the gate is off and stayed silent"
        else
            [[ "$delta" -ge 2 ]] || fail "the chain is at audit mode but these recoveries produced only
  $delta guardian-assertion MISMATCH line(s), expected at least 2.  Every institutional signature
  above carried no identity assertion, so each should have been flagged and still accepted.  Too few
  means the gate is inert -- most likely the params never reached the enclave, or the
  service-provider/pioneer class test stopped matching.  Raising the mode to 2 in that state would
  silently protect nothing."
            echo "  correct: institutional signatures were flagged and still accepted"

            # And the individual guardian must NOT have been flagged.  Holding a family member to an
            # assertion they cannot compute would break recovery for the class this control was
            # never aimed at, and that failure would otherwise surface only at mode 2.
            exempt=$(grep -ac "is an individual guardian, exempt" "$enclave_log" 2>/dev/null)
            [[ -n "$exempt" ]] || exempt=0
            [[ "$exempt" -ge 1 ]] || fail "no individual guardian was recorded as exempt.  victor-eph1
  signs as a raw bech32 address and must never be asked for an assertion in any mode."
            echo "  correct: the individual guardian was exempted"
        fi
    fi

else
    echo "========================="
    echo "6, 6a, 6b. key recovery -- SKIPPED (TEST_CREDENTIALS_SKIP_RECOVERY is set)"
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
