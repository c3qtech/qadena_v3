#!/bin/zsh

set -e


# get script dir
SCRIPT_DIR="${0:A:h}"


source "$SCRIPT_DIR/../scripts/setup_env.sh"

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
: ${VERITAS_SEC_HOME:="$HOME/sec-veritas"}

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

# READ FROM SEC'S DIRECTORY, AND SAY SO WHEN IT IS NOT THERE.  A missing variables.json used to
# surface as jq errors and empty variables, which then flowed into transactions as blanks.
for _f in variables.json mnemonics.json; do
    [ -r "$VERITAS_SEC_HOME/$_f" ] || {
        echo "$VERITAS_SEC_HOME/$_f is missing -- run step_1.sh first,"
        echo "or point at the right directory:  export VERITAS_SEC_HOME=<dir>"
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
identityprovidermnemonic=$(jq -r .identityprovidermnemonic "$VERITAS_SEC_HOME/mnemonics.json")
dsvsprovidermnemonic=$(jq -r .dsvsprovidermnemonic "$VERITAS_SEC_HOME/mnemonics.json")

echo "identityprovidermnemonic: $identityprovidermnemonic"
echo "dsvsprovidermnemonic: $dsvsprovidermnemonic"



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
: ${VERITAS_FOUNDATION_APPSVR:=foundation-appsvr}
feegrant_args=()
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    echo "toll-free: $VERITAS_FOUNDATION_APPSVR sponsors and grants; sec-treasury is not used"
    treasuryname="$VERITAS_FOUNDATION_APPSVR"
    feegrant_args=(--fee-granter "$VERITAS_FOUNDATION_APPSVR")
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

$qadenaproviderscripts/query_service_provider_proposal.sh $identityproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"


# setup dsvs provider
echo "-------------------------"
echo "Setting up  $dsvsprovidername provider"
echo "-------------------------"

$qadenaproviderscripts/setup_provider_base.sh $dsvsprovidername dsvs --pioneer $pioneer --treasury $treasuryname --provider-mnemonic $dsvsprovidermnemonic --provider-amount $provideramount --count $count "${feegrant_args[@]}"

# load proposal id from dsvssrvprv.proposal_id
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/$dsvsprovidername.proposal_id)

$qadenaproviderscripts/query_service_provider_proposal.sh $dsvsproposal_id --wait --status "PROPOSAL_STATUS_VOTING_PERIOD"

echo "Send the following information to QFI"
echo "$identityprovidername proposal_id: $identityproposal_id"
echo "$dsvsprovidername proposal_id: $dsvsproposal_id"

echo "QFI will inform you when the providers are approved."
echo "Once approved, run $veritasscripts/step_3.sh"


