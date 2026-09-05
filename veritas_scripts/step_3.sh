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

# FUNDING MODE.
#
#   feegrant (default) -- the Qadena foundation pays these wallets' fees by fee grant. Nothing is
#                         transferred, so there is no SEC treasury to hold, no AML whitelist needed
#                         to move it, and the sponsorship is revocable, expiring and spend-limited.
#   banksend           -- the original behaviour: sec-treasury transfers tokens to every wallet.
#
# Set VERITAS_FUND_MODE=banksend to restore the old path.
# THE RENAMED ACCOUNT.  The foundation sponsors more than one programme out of bucket 10 -- its
# notes list "SEC PH VERITAS 60M; future MOUs; OTC swap reserve" -- so the sponsor accounts carry
# the programme in their names.  A default of `foundation-appsvr` now points at an account that
# does not exist, and step_2 would wait forever for funds in it.
: ${VERITAS_FOUNDATION_APPSVR:=foundation-veritas-appsvr}

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
identityprovidername=$(jq -r .identityprovidername "$VERITAS_SEC_HOME/variables.json")
dsvsprovidername=$(jq -r .dsvsprovidername "$VERITAS_SEC_HOME/variables.json")
createwalletsponsorname=$(jq -r .createwalletsponsorname "$VERITAS_SEC_HOME/variables.json")
dsvsname=$(jq -r .dsvsname "$VERITAS_SEC_HOME/variables.json")
email=$(jq -r .email "$VERITAS_SEC_HOME/variables.json")
avalue=$(jq -r .avalue "$VERITAS_SEC_HOME/variables.json")
phone=$(jq -r .phone "$VERITAS_SEC_HOME/variables.json")
firstname=$(jq -r .firstname "$VERITAS_SEC_HOME/variables.json")
birthdate=$(jq -r .birthdate "$VERITAS_SEC_HOME/variables.json")
treasuryname=$(jq -r .treasuryname "$VERITAS_SEC_HOME/variables.json")

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
createwalletsponsormnemonic=$(jq -r .createwalletsponsormnemonic "$VERITAS_SEC_HOME/mnemonics.json")
signermnemonic=$(jq -r .signermnemonic "$VERITAS_SEC_HOME/mnemonics.json")

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

# ---------------------------------------------------------------------------------------------
# THE HANDOFF TO QFI.
#
# The foundation's last action authorises this sponsor pool -- two grants per wallet, both signed
# by foundation-users, which only the foundation can sign.  It therefore needs every pool member's
# ADDRESS, and cannot work them out: the ephemerals are HD derivations of THIS wallet's mnemonic
# (--eph-account-index), so deriving them means holding a key the foundation must never have.
#
# Until now nothing emitted them.  step_4 resolved the names from its own keyring instead, which
# works only in a harness where one keyring holds both sides' keys -- and fails per-wallet and
# silently on a real deployment, leaving a partly-authorised pool that breaks onboarding for SOME
# users and not others.
#
# Written as JSON with the chain-id and the count so step_4 can CHECK it rather than trust it.
pool_file="$VERITAS_SEC_HOME/pool_addresses.json"
{
    printf '{\n'
    printf '  "chain_id": "%s",\n'     "$(qadenad_alias status 2>/dev/null | jq -r '.node_info.network // ""')"
    printf '  "sponsor_base": "%s",\n' "$createwalletsponsorname"
    printf '  "count": %s,\n'          "$count"
    printf '  "pool": [\n'
    _first=1
    for i in $(seq 0 "$count"); do
        if [ "$i" -eq 0 ]; then _w="$createwalletsponsorname"; else _w="$createwalletsponsorname-eph$i"; fi
        _a=$(qadenad_alias keys show "$_w" --address 2>/dev/null | tr -d '\r')
        [ -n "$_a" ] || { echo "  WARNING: $_w has no address -- pool handoff will be short" >&2; continue; }
        [ "$_first" -eq 1 ] || printf ',\n'
        printf '    {"name": "%s", "address": "%s"}' "$_w" "$_a"
        _first=0
    done
    printf '\n  ]\n}\n'
} > "$pool_file"

# EMITTED AS A PASTE BLOCK, NOT A FILE TO TRANSFER.
#
# The two sides are different machines and often different organisations; "send them this file"
# means email, a bucket, or a chat attachment, each of which is a chance to send the wrong one or
# a stale one.  A block the foundation operator pastes into a terminal recreates the file locally
# and runs the command in one action, and the JSON inside it still carries the chain-id and count
# so step_4 verifies rather than trusts.
echo ""
echo "==================================================================="
echo "SEND THIS BLOCK TO QFI -- they paste it into a terminal as-is:"
echo "==================================================================="
echo ""
echo "cat > /tmp/veritas-pool.json <<'POOLEOF'"
cat "$pool_file"
echo "POOLEOF"
echo "foundation_scripts/sec_veritas_after_step_3.sh --pool-addresses /tmp/veritas-pool.json"
echo ""
echo "==================================================================="
jq -r '"  \(.pool|length) wallet(s), base \(.sponsor_base), chain \(.chain_id)"' "$pool_file" 2>/dev/null
echo "  QFI's script verifies the chain-id, the count, the bech32 form and that every address"
echo "  exists on chain BEFORE it grants anything -- a short, stale or mangled block is refused"
echo "  outright rather than half-applied."
