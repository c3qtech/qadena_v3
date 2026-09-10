#!/bin/zsh

set -e


# get script dir
SCRIPT_DIR="${0:A:h}"
# This script's own directory, captured BEFORE setup_env.sh is sourced: that file sets
# SCRIPT_DIR="${0:A:h}" at its own top level, so afterwards SCRIPT_DIR points at scripts/.
# $_DEPLOY_HERE is not assigned anywhere else.
_DEPLOY_HERE="${0:A:h}"

# CAPTURE BEFORE SOURCING, AND DEFAULT TO `file`.
#
# setup_env.sh sets QADENA_KEYRING_BACKEND=test for the devnet harness, and this script sources
# it -- so a later ${QADENA_KEYRING_BACKEND:-file} would always see "test" and the intended
# default would be dead code.  The foundation scripts already capture it this way; the SEC steps
# did not, which is why step_1's own comment claimed it "defaults to file" while it did not.
#
# `file` IS THE RIGHT DEFAULT HERE.  These keys are the deployment: secidentitysrvprv signs
# credential issuance as SEC's identity provider, and sec-veritas-admin carries authz to issue fee
# grants as the foundation.  A `test` keyring is JWE-wrapped under a passphrase built into the
# SDK, so it opens with no prompt -- read access to the directory is read access to the keys.
# The unattended harnesses (setup_veritas/enf/ekycph) export `test` explicitly, which is the
# correct way to opt out: stated, not inherited.
_kb_caller="${QADENA_KEYRING_BACKEND:-}"


source "$SCRIPT_DIR/../scripts/setup_env.sh"

# WHICH DEPLOYMENT THIS IS -- pre-scanned, because $VERITAS_SEC_HOME is defaulted from it below and
# QADENA_KEYRING_DIR is derived from that.  Must match the --deployment step_1 ran with: these read
# the variables.json step_1 wrote, and reading the wrong home is how a run reports a clean chain
# while operating on another deployment's keys.
DEPLOYMENT="${DEPLOYMENT:-veritas}"
_dep_i=1
while (( _dep_i <= $# )); do
    [[ "${@[$_dep_i]}" == "--deployment" ]] && DEPLOYMENT="${@[$((_dep_i+1))]:?--deployment needs a name}"
    _dep_i=$(( _dep_i + 1 ))
done
source "$_DEPLOY_HERE/../foundation_scripts/deployment_profile.sh"
deployment_profile_load "$DEPLOYMENT" || exit 1
export QADENA_KEYRING_BACKEND="${_kb_caller:-file}"

# Minimal argument handling: the chain's location is a per-run fact and belongs on the command
# line, not in ambient environment.  The flag exports QADENA_NODE so every child script and
# qadenad_alias call inherits it; the chain-id is then derived from that node by setup_env.
while [ $# -gt 0 ]; do
    case "$1" in
        --node) export QADENA_NODE="$2"; shift 2 ;;
        --keyring-passfile) export QADENA_KEYRING_PASSFILE="$2"; shift 2 ;;
        --sec-home) export VERITAS_SEC_HOME="$2"; shift 2 ;;
        --deployment) shift 2 ;;   # pre-scanned at the top; consumed so it is not "unknown"
        *) echo "unknown option: $1"
           echo "usage: $0 [--deployment <name>] [--node <rpc>] [--sec-home <dir>] [--keyring-passfile <file>]"
           echo "  --deployment  $(deployment_profile_list); default $DEPLOY_NAME.  MUST match step_1's."
           exit 1 ;;
    esac
done

# UNLOCK ONCE, HERE.  qadena_keyring_unlock has existed in setup_env.sh since the file backend was
# added and was never called from anywhere -- so with backend=file, QADENA_KEYRING_PASS stayed
# empty, qadenad_alias took its no-passphrase branch, and qadenad blocked reading stdin with the
# prompt swallowed by whatever call site had captured its output.  That is a hang with no message
# and no prompt (measured 2026-09-07 on step_2).  Called after argument parsing so
# --keyring-passfile is already in effect.
qadena_keyring_unlock

# THE KEYRING IS THE NODE'S, AND SO IS ITS BACKEND.  These steps do not choose one.
#
# An earlier version defaulted them to `file`.  That was wrong for a reason worth recording: the
# keys these steps need are not all theirs.  Every create-wallet needs `$pioneer` -- the validator
# key -- which lives in the NODE's keyring-test, the one config/client.toml names and the one the
# node itself reads.  Defaulting to `file` created a SECOND, empty keyring beside it, prompted for
# a passphrase to open it, and would then have failed looking for a key that was never in it.
#
# Encrypting SEC's keys is still the right end state, but it needs a keyring of its own -- the way
# derive_launch_keys.sh uses --home ~/launch/coord -- plus a way to reach the pioneer from there.
# That is a design change, not a default.  Until then: export QADENA_KEYRING_BACKEND=file only if
# you have arranged both.


# read variables from json file

# SEC'S OWN DIRECTORY, THE WAY THE LAUNCH FLOW HAS ONE.
#
# Until now step_1 wrote variables.json and mnemonics.json into whatever the CURRENT DIRECTORY
# happened to be, and steps 2 and 3 read them the same way -- so the run only worked if every step
# was invoked from the same cwd, and nothing said which.  step_3's pool file went somewhere else
# again (veritas_scripts/).  One directory, named, with the same shape as ~/launch:
#
#   $VERITAS_SEC_HOME/
#       variables.json        the run's configuration -- names, counts, amounts, fund mode
#       mnemonics.json        THE KEYS.  Plaintext, 600, because steps 2 and 3 read it.
#       pool_addresses.json   written by step_3, handed to the foundation
#
# 700 on the directory and 600 on the file are the only protection mnemonics.json has.  It is the
# one artifact here whose loss is unrecoverable and whose disclosure is total: back it up off this
# machine, and delete it when the deployment is established.
: ${VERITAS_SEC_HOME:="$DEPLOY_SEC_HOME"}

# SEC'S KEYS LIVE WITH SEC'S FILES.
#
# Steps 1, 2 and 3 are all run by SEC, and every key they create is SEC's: the admin key, the two
# service providers, the create-wallet sponsor, the DSVS user.  None of them belongs to the node,
# and putting them in the node's keyring means `init.sh`'s `rm -rf $QADENAHOME` destroys the
# deployment's identities -- the same trap the launch flow avoids by keeping its keyring in
# ~/launch/coord rather than in the node home.
#
# --home still points at the node (config, and the RPC it talks to); only the KEYRING moves.
# Exported so the provider scripts these steps call inherit it without each needing a flag.
#
# The pioneer is NOT an obstacle: `create-wallet` takes a home-pioneer-ID string
# (x/qadena/client/cli/tx_create_wallet.go:160, argHomePioneerID), not a key name, so nothing here
# needs the validator's key to be in the same keyring.
export QADENA_KEYRING_DIR="$VERITAS_SEC_HOME/keyring"
mkdir -p "$QADENA_KEYRING_DIR" 2>/dev/null; chmod 700 "$QADENA_KEYRING_DIR" 2>/dev/null

# WARN ABOUT A SPLIT DEPLOYMENT, which is what the ordering bug above used to produce.
#
# step_1 fixed QADENA_KEYRING_DIR from the DEFAULT home before parsing --sec-home, so a run with
# --sec-home wrote keys to ~/sec-veritas and mnemonics to the requested directory.  Nothing said
# so: the admin key was created and its address printed, and the failure surfaced two steps later
# as "key with address <sponsor> not found" while signing as the foundation.  The ordering is
# fixed, but a directory left behind by an earlier run still looks like a working deployment.
if [[ "$VERITAS_SEC_HOME" != "$DEPLOY_SEC_HOME" ]] \
   && ls "$DEPLOY_SEC_HOME"/keyring/keyring-*/*.info > /dev/null 2>&1; then
    echo ""
    echo "NOTE: $DEPLOY_SEC_HOME also holds keys, and this run uses $VERITAS_SEC_HOME."
    echo "  A version of step_1 before 2026-09-08 wrote keys to the default home while writing"
    echo "  mnemonics to --sec-home, splitting a deployment across both.  If this run cannot find"
    echo "  a key it expects, look there:"
    echo "      ls $DEPLOY_SEC_HOME/keyring/keyring-file/"
    echo "  and either move them across or start clean.  Nothing is read from there automatically."
    echo ""
fi

# READ FROM SEC'S DIRECTORY, AND SAY SO WHEN IT IS NOT THERE.  A missing variables.json used to
# surface as jq errors and empty variables, which then flowed into transactions as blanks.
# mnemonics.json is no longer written -- step_1 seals directly -- so require only
# variables.json here and let sec_mnemonic() report a missing mnemonic in either form.
for _f in variables.json; do
    [ -r "$VERITAS_SEC_HOME/$_f" ] || {
        echo "$VERITAS_SEC_HOME/$_f is missing -- run step_1.sh first,"
        echo "or point at the right directory:  --sec-home <dir>"
        exit 1; }
done

provideramount=$(jq -r .provideramount "$VERITAS_SEC_HOME/variables.json")
signeramount=$(jq -r .signeramount "$VERITAS_SEC_HOME/variables.json")
createwalletsponsoramount=$(jq -r .createwalletsponsoramount "$VERITAS_SEC_HOME/variables.json")
pioneer=$(jq -r .pioneer "$VERITAS_SEC_HOME/variables.json")
count=$(jq -r .count "$VERITAS_SEC_HOME/variables.json")
treasuryname=$(jq -r .treasuryname "$VERITAS_SEC_HOME/variables.json")
identityprovidername=$(jq -r .identityprovidername "$VERITAS_SEC_HOME/variables.json")
dsvsprovidername=$(jq -r .dsvsprovidername "$VERITAS_SEC_HOME/variables.json")

echo "treasuryname: $treasuryname"
echo "provideramount: $provideramount"
echo "signeramount: $signeramount"
echo "createwalletsponsoramount: $createwalletsponsoramount"
echo "pioneer: $pioneer"
echo "count: $count"

# read mnemonics from json file
identityprovidermnemonic=$(sec_mnemonic "$VERITAS_SEC_HOME" identityprovidermnemonic)
dsvsprovidermnemonic=$(sec_mnemonic "$VERITAS_SEC_HOME" dsvsprovidermnemonic)

# NOT THE MNEMONICS THEMSELVES.  These two seed phrases derive every provider wallet on the
# chain; printing them put them in the scrollback of every run.  A word count is enough to confirm
# they were read from mnemonics.json and are the right shape.
echo "identityprovidermnemonic: <redacted, $(print -r -- "$identityprovidermnemonic" | wc -w | tr -d ' ') words>"
echo "dsvsprovidermnemonic: <redacted, $(print -r -- "$dsvsprovidermnemonic" | wc -w | tr -d ' ') words>"



# TOLL-FREE.  In feegrant mode there is NO SEC treasury: sec-treasury is never funded, so the wait
# below would spin for ever on a condition this mode deliberately never creates.
#
# The fix is to REPOINT $treasuryname at the foundation account rather than to skip the wait -- the
# foundation IS funded, so the check still runs and still means something.  Skipping it would have
# removed the one guard that catches "the deployment forgot to fund the payer".
#
# It is repointed rather than dropped because create-wallet takes it as the SPONSOR -- a message
# field, not a fee, so it cannot be fee-granted.  The foundation plays that role too, which is what
# makes sec-treasury unnecessary rather than merely unfunded.
                                   # disagreement between the two means step_2 waits forever for
                                   # funds in a treasury the sponsored flow never fills.
# THE RENAMED ACCOUNT.  The foundation sponsors more than one programme out of bucket 10 -- its
# notes list "SEC PH VERITAS 60M; future MOUs; OTC swap reserve" -- so the sponsor accounts carry
# the programme in their names.  A default of `foundation-appsvr` now points at an account that
# does not exist, and step_2 would wait forever for funds in it.
: ${VERITAS_FOUNDATION_APPSVR:=foundation-veritas-appsvr}
feegrant_args=()
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    echo "toll-free: $VERITAS_FOUNDATION_APPSVR sponsors and grants; $treasuryname is not used"
    # RESOLVE THE SPONSOR TO AN ADDRESS, HERE, ONCE -- SEC's keyring does not hold it.
    #
    # The foundation account lives in QFI's coordinator keyring; after the keyring split SEC's box
    # has no entry for the NAME, so every place that passed it to a query or a sponsor argument
    # spun on "unknown address" forever (the funds-wait loop did exactly that).  On a SEC box the
    # variable holds the ADDRESS -- printed by QFI's prepare stage -- and a name is accepted only
    # where a keyring can actually resolve it (the single-operator harness).
    # THE FILE IS THE RUN'S TRUTH.  step_1 recorded the handoff address in variables.json when it
    # was given --appsvr; that value wins.  When the file has none (the single-keyring harness,
    # which passes no --appsvr), the exported VERITAS_FOUNDATION_APPSVR fills in, and the name
    # default after that.  The resolved value is exported so create_user and the provider scripts
    # inherit one consistent answer.
    _file_appsvr=$(jq -r '.appsvraddr // empty' "$VERITAS_SEC_HOME/variables.json" 2>/dev/null || true)
    [ -n "$_file_appsvr" ] && VERITAS_FOUNDATION_APPSVR="$_file_appsvr"
    export VERITAS_FOUNDATION_APPSVR
    case "$VERITAS_FOUNDATION_APPSVR" in
        qadena1*) sponsor_addr="$VERITAS_FOUNDATION_APPSVR" ;;
        *)
            sponsor_addr=$(qadenad_alias keys show "$VERITAS_FOUNDATION_APPSVR" --address 2>/dev/null | tr -d '\r')
            [ -n "$sponsor_addr" ] || {
                echo "cannot resolve '$VERITAS_FOUNDATION_APPSVR' -- not an address, and not in this keyring."
                echo "On the $DEPLOY_DISPLAY machine export the ADDRESS QFI handed over:"
                echo "    export VERITAS_FOUNDATION_APPSVR=qadena1..."
                exit 1
            } ;;
    esac
    treasuryname="$sponsor_addr"

    # THE DELEGATED SIGNER, SELF-DETECTED.  The admin's key NAME is in variables.json (step_1
    # wrote it), so nobody has to export VERITAS_SEC_ADMIN -- but the name alone is not enough:
    # using it is only correct if QFI has actually granted the authz, and the harness never does.
    # So: explicit env still wins; otherwise use the recorded admin IF AND ONLY IF the chain shows
    # an authz grant from the sponsor to it.  Delegation-if-delegated, direct-sign otherwise --
    # the run adapts to what is true on chain instead of what someone remembered to export.
    if [ -z "${VERITAS_SEC_ADMIN:-}" ]; then
        # SAY WHICH CONDITION FAILED.  This had ONE message for four different causes -- no
        # adminname recorded, no local key, an unreachable chain, or a genuinely absent grant --
        # and then fell back to direct signing, which needs the FOUNDATION's key.  On a split
        # keyring that key is not here, so the run continued and died much later with
        # "key with address <sponsor> not found", naming the granter rather than the delegation
        # that should have avoided needing it.  Measured 2026-09-08 on the staging chain, where
        # the three authz grants were present the whole time.
        _adm=$(jq -r '.adminname // empty' "$VERITAS_SEC_HOME/variables.json" 2>/dev/null || true)
        if [ -z "$_adm" ]; then
            echo "no adminname in $VERITAS_SEC_HOME/variables.json -- signing directly (harness mode)"
        else
            _adm_addr=$(qadenad_alias keys show "$_adm" --address 2>/dev/null || true)
            if [ -z "$_adm_addr" ]; then
                echo "WARNING: '$_adm' is recorded but NOT in this keyring -- cannot use the delegation."
                echo "  Signing will fall back to the foundation's own key, which the $DEPLOY_DISPLAY box does not have."
                echo "  Is VERITAS_SEC_HOME ($VERITAS_SEC_HOME) the home step_1 wrote?"
            else
                _gr=$(qadenad_alias query authz grants "$sponsor_addr" "$_adm_addr" --output json 2>&1 || true)
                case "$_gr" in
                    *"no route to host"*|*"connection refused"*|*"post failed"*)
                        echo "WARNING: cannot reach the chain to check the delegation -- NOT falling back"
                        echo "  silently.  Fix --node and re-run."
                        exit 1 ;;
                esac
                if print -r -- "$_gr" | jq -e '(.grants|length) > 0' >/dev/null 2>&1; then
                    export VERITAS_SEC_ADMIN="$_adm"
                    echo "delegated signing: $_adm ($_adm_addr) -- authz from $sponsor_addr verified on chain"
                else
                    echo "WARNING: '$_adm' ($_adm_addr) holds NO authz from $sponsor_addr."
                    echo "  Has the foundation run sec_veritas_after_step_1.sh against THIS chain?"
                    echo "  Signing will fall back to the foundation's own key, which the $DEPLOY_DISPLAY box does not have."
                fi
            fi
        fi
    else
        export VERITAS_SEC_ADMIN
    fi
    feegrant_args=(--fee-granter "$sponsor_addr")
fi

# wait until there are funds in $treasuryname
echo "Waiting for funds in $treasuryname"
while [ "$(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount // empty")" = "" ] || [ "$(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount")" = "null" ] || [ "$(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount")" = "0" ]; do
    sleep 1
echo "Checking again:  Waiting for funds in $treasuryname"
done

echo "Funds in $treasuryname: $(qadenad_alias query bank balances $treasuryname --output json | jq -r ".balances[0].amount")"

# setup identity provider
echo "-------------------------"
echo "Setting up $identityprovidername provider"
echo "-------------------------"

$qadenaproviderscripts/setup_provider_base.sh $identityprovidername identity --pioneer $pioneer --treasury $treasuryname --provider-mnemonic $identityprovidermnemonic --provider-amount $provideramount --count $count "${feegrant_args[@]}"

# load proposal id from identity.proposal_id
identityproposal_id=$(cat $qadenaproviderscripts/proposals/$identityprovidername.proposal_id)

# NOT waited to VOTING_PERIOD in sponsored mode: with no SEC deposit the proposal sits in
# DEPOSIT_PERIOD until QFI deposits -- blocking here would deadlock SEC (waiting for a status
# only QFI can cause) against QFI (waiting for the ids this step has not yet printed).
if [ "${VERITAS_FUND_MODE:-}" != "foundation-sponsored" ]; then
    $qadenaproviderscripts/query_service_provider_proposal.sh $identityproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"
fi


# setup dsvs provider
echo "-------------------------"
echo "Setting up  $dsvsprovidername provider"
echo "-------------------------"

$qadenaproviderscripts/setup_provider_base.sh $dsvsprovidername dsvs --pioneer $pioneer --treasury $treasuryname --provider-mnemonic $dsvsprovidermnemonic --provider-amount $provideramount --count $count "${feegrant_args[@]}"

# load proposal id from dsvssrvprv.proposal_id
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/$dsvsprovidername.proposal_id)

if [ "${VERITAS_FUND_MODE:-}" != "foundation-sponsored" ]; then
    $qadenaproviderscripts/query_service_provider_proposal.sh $dsvsproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"
fi

echo "Send the following information to QFI"
echo "$identityprovidername proposal_id: $identityproposal_id"
echo "$dsvsprovidername proposal_id: $dsvsproposal_id"
echo ""
echo "QFI votes with:  foundation_scripts/sec_veritas_after_step_2.sh $identityproposal_id $dsvsproposal_id${QADENA_NODE:+ --node $QADENA_NODE} ..."
echo "Wait for both to reach PASSED, then run $veritasscripts/step_3.sh"
