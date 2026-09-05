#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# FUNDING MODE.
#
#   feegrant (default) -- the Qadena foundation pays these wallets' fees by fee grant. Nothing is
#                         transferred, so there is no SEC treasury to hold, no AML whitelist needed
#                         to move it, and the sponsorship is revocable, expiring and spend-limited.
#   banksend           -- the original behaviour: sec-treasury transfers tokens to every wallet.
#
# Set VERITAS_FUND_MODE=banksend to restore the old path.
: ${VERITAS_FOUNDATION_APPSVR:=foundation-appsvr}

# Every message a VERITAS provider/signer wallet broadcasts, from the trace of the app-server's
# GenerateOrBroadcastTxCLISync call sites. A type missing here fails closed at the operation that
# needs it, so this list and the app-server's allowlist must move together.
VERITAS_APPSVR_MSGS="/qadena.dsvs.MsgCreateDocument,/qadena.dsvs.MsgRemoveDocument,/qadena.dsvs.MsgSignDocument,/qadena.qadena.MsgCreateCredential,/qadena.qadena.MsgRemoveCredential,/qadena.qadena.MsgSignRecoverPrivateKey,/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet,/cosmos.feegrant.v1beta1.MsgGrantAllowance"

# fund_wallet <address> -- give this wallet the means to transact, however this deployment does it.
fund_wallet() {
    local qadena_addr="$1"
    if [ "$VERITAS_FUND_MODE" = "banksend" ]; then
        echo "Sending $per_account_amount to $qadena_addr from $treasuryname" >&2
        qadenad_alias tx bank send $treasuryname $qadena_addr $per_account_amount \
            --from $treasuryname --yes --output json \
            --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment
        return
    fi
    # Toll-free: a GRANT, not a transfer. Routed through grant_as_foundation so it is signed by
    # SEC's admin key as a MsgExec when VERITAS_SEC_ADMIN is set -- step_3 is SEC's step and must not
    # require a foundation key. Progress goes to STDERR: the caller captures stdout as JSON, and a
    # stray echo there corrupts it and kills jq with "Invalid numeric literal".
    local granter
    granter=$(qadenad_alias keys show "$VERITAS_FOUNDATION_APPSVR" --address 2>/dev/null)
    [ -n "$granter" ] || granter="$VERITAS_FOUNDATION_APPSVR"
    echo "Granting fees to $qadena_addr from $VERITAS_FOUNDATION_APPSVR" >&2
    grant_as_foundation "$granter" "$qadena_addr" "$VERITAS_APPSVR_MSGS" \
        || echo "  WARNING: grant failed for $qadena_addr" >&2
    echo '{"code":0,"txhash":"","note":"feegrant"}'
}

# read variables from json file
provideramount=$(jq -r .provideramount variables.json)
signeramount=$(jq -r .signeramount variables.json)
createwalletsponsoramount=$(jq -r .createwalletsponsoramount variables.json)
pioneer=$(jq -r .pioneer variables.json)
count=$(jq -r .count variables.json)
identityprovidername=$(jq -r .identityprovidername variables.json)
dsvsprovidername=$(jq -r .dsvsprovidername variables.json)
createwalletsponsorname=$(jq -r .createwalletsponsorname variables.json)
dsvsname=$(jq -r .dsvsname variables.json)
email=$(jq -r .email variables.json)
avalue=$(jq -r .avalue variables.json)
phone=$(jq -r .phone variables.json)
firstname=$(jq -r .firstname variables.json)
birthdate=$(jq -r .birthdate variables.json)
treasuryname=$(jq -r .treasuryname variables.json)

# TOLL-FREE: the SPONSOR must be an account that EXISTS ON CHAIN.  create-wallet takes it as a
# message field (and has grantFee() pay from it), so it cannot be fee-granted and it cannot be
# sec-treasury -- in this mode sec-treasury is never funded, so it has no account at all and
# create-wallet fails with "account ... not found" / "Couldn't grant fee".  The foundation account
# is funded and is already the payer for SEC's operational wallets, so it plays the sponsor role.
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    echo "toll-free: $VERITAS_FOUNDATION_APPSVR sponsors wallet creation; sec-treasury is not used"
    treasuryname="$VERITAS_FOUNDATION_APPSVR"
fi




# read mnemonics from json file
createwalletsponsormnemonic=$(jq -r .createwalletsponsormnemonic mnemonics.json)
signermnemonic=$(jq -r .signermnemonic mnemonics.json)

# read proposal id from identityprovidername.proposal_id
identityproposal_id=$(cat $qadenaproviderscripts/proposals/$identityprovidername.proposal_id)
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/$dsvsprovidername.proposal_id)
echo "Waiting for approval of providers"

$qadenaproviderscripts/query_service_provider_proposal.sh $identityproposal_id --wait
$qadenaproviderscripts/query_service_provider_proposal.sh $dsvsproposal_id --wait

echo "Providers approved"


########################################################
# Create wallet sponsor
########################################################

name="$createwalletsponsorname"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$createwalletsponsormnemonic
a="$avalue"
bf="5678"
middlename=""
lastname="Create Wallet Sponsor"
gender="M"
citizenship="PH"
residency="PH"
identityprovider="$identityprovidername"
dsvsserviceprovider=""
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$count"

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${createwalletsponsoramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${createwalletsponsoramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$createwalletsponsoramount
fi

echo "create-user.sh" $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
result=$(fund_wallet "$qadena_addr")
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
    exit 1
fi

# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
    result=$(fund_wallet "$qadena_addr")
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
    echo "Result: $result"
    if [ $(echo $result | jq -r .code) -ne 0 ]; then
        echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
        exit 1
    fi
done


name="$dsvsname"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$signermnemonic
# add 1 to avalue
avalue=$((avalue + 1))
a="$avalue"
bf="5678"
middlename=""
gender="F"
citizenship="PH"
residency="PH"
dsvsserviceprovider="$dsvsprovidername"
identityprovider="$identityprovidername"
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$count"

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${signeramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${signeramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$signeramount
fi

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"
qadena_addr=$(qadenad_alias keys show $name --address)
echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
result=$(fund_wallet "$qadena_addr")
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
echo "Result: $result"
if [ $(echo $result | jq -r .code) -ne 0 ]; then
    echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
    exit 1
fi
# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
    result=$(fund_wallet "$qadena_addr")
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
    echo "Result: $result"
    if [ $(echo $result | jq -r .code) -ne 0 ]; then
        echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
        exit 1
    fi
done

$qadenatestscripts/extract_ephem_keys.sh --provider $identityprovidername# --count $count --include-base-provider --include-base-provider-credential
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsprovidername# --count $count --include-base-provider
$qadenatestscripts/extract_ephem_keys.sh --provider $createwalletsponsorname# --count $count --include-base-provider
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsname# --count $count
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsname#-credential --count $count





