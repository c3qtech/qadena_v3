#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

# Handle positional and named params separately
unset providername
unset serviceProviderType

# Empty means the ORIGINAL behaviour: fund each wallet by bank send from $treasury.  Set by
# --fee-granter to switch to toll-free, where the wallets are granted fees and hold nothing.
feegranter=""

# The message types a VERITAS provider/signer wallet broadcasts.  MUST stay in step with the same
# list in veritas_scripts/step_3.sh and with the app-server's allowlist -- a type missing from any
# one of the three fails closed at the operation that needs it, not at grant time.
VERITAS_APPSVR_MSGS="/qadena.dsvs.MsgCreateDocument,/qadena.dsvs.MsgRemoveDocument,/qadena.dsvs.MsgSignDocument,/qadena.qadena.MsgCreateCredential,/qadena.qadena.MsgRemoveCredential,/qadena.qadena.MsgSignRecoverPrivateKey,/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet,/cosmos.feegrant.v1beta1.MsgGrantAllowance"

# fund_wallet <address> -- give this wallet the means to transact, however this deployment does it.
# Emits the tx JSON on stdout either way, so both callers keep their existing code/hash checks.
fund_wallet() {
    local qadena_addr="$1"
    if [ -z "$feegranter" ]; then
        echo "Sending $per_account_amount to $qadena_addr from treasury $treasury" >&2
        qadenad_alias tx bank send $treasury $qadena_addr $per_account_amount \
            --from $treasury --yes --output json \
            --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment
        return
    fi
    # WIDEN THE GRANT create-wallet ALREADY MADE.  tx_create_wallet.go's grantFee() has the sponsor
    # fee-grant every new wallet, but only for /qadena.qadena.MsgAddPublicKey and MsgCreateWallet --
    # enough to bootstrap a wallet, nowhere near enough for a provider that must write documents,
    # issue credentials and sign.  A grantee holds at most ONE allowance per granter, so a second
    # grant does not stack: it fails with "fee allowance already exists".  Revoke, then re-grant the
    # wider set, which is a superset of the two above and so loses nothing.
    # THROUGH grant_as_foundation, NOT --from $feegranter DIRECTLY.  The granter is the
    # foundation sponsor, and on a SEC machine its key is not here -- this used to sign the
    # revoke and re-grant directly as the foundation, which is a foundation signature demanded
    # of SEC's keyring: the same defect step_3's fund_wallet had before it was rerouted.  With
    # VERITAS_SEC_ADMIN set, the inner messages are built --generate-only (no key needed) and
    # exec'd under the admin's authz; grant_as_foundation also does revoke-first and waits, so
    # the "already exists" race the sleep 3 papered over is handled there.
    echo "Widening the sponsor's fee grant for $qadena_addr from $feegranter (toll-free: no tokens moved)" >&2
    grant_as_foundation "$feegranter" "$qadena_addr" "$VERITAS_APPSVR_MSGS" \
        || { echo "  WARNING: could not widen the grant for $qadena_addr" >&2; echo '{"code":1,"txhash":"","note":"widen-failed"}'; return 1; }
    # THE CALLER READS STDOUT AS A TX RESULT.  The old direct-signing code's last line was the
    # grant broadcast, whose JSON became fund_wallet's return value; grant_as_foundation does its
    # own waiting and prints nothing to stdout, so without this sentinel the caller saw an empty
    # result and died on "txhash not found".  Same convention as step_3's fund_wallet.
    echo '{"code":0,"txhash":"","note":"feegrant"}'
}


# Extract both positional parameters first
pos_args=()
for arg in "$@"; do
    if [[ ! $arg =~ ^-- ]]; then
        pos_args+=("$arg")
    fi
done

# Set variables from positional parameters
if [[ ${#pos_args[@]} -gt 0 ]]; then
    providername="${pos_args[1]}"
fi

if [[ ${#pos_args[@]} -gt 1 ]]; then
    serviceProviderType="${pos_args[2]}"
fi

# Process named options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer)
            pioneer="$2"
            shift 2
            ;;
        --treasury)
            treasury="$2"
            shift 2
            ;;
        --provider-mnemonic)
            providermnemonic="$2"
            shift 2
            ;;
        --provider-amount)
            provideramount="$2"
            shift 2
            ;;
        # TOLL-FREE.  When set, the provider and its eph wallets are given a FEE GRANT instead of
        # tokens, so they never hold a balance and no AML-scanned transfer is made on their behalf.
        # $provideramount is then unused -- that is the point, not an oversight.
        --fee-granter)
            feegranter="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 <providername> <serviceProviderType> (e.g. identity, finance) [--pioneer <pioneer>] [--treasury <treasury>] [--provider-mnemonic <providermnemonic>] [--provider-amount <provideramount>] [--count <count>]"
            exit 0
            ;;
        --*) # Handle unknown options
            echo "Unknown option: $1"
            shift 1
            ;;
        *) # Skip positional parameters (already handled above)
            shift 1
            ;;
    esac
done

# Debug info
echo "providername: $providername"
echo "serviceProviderType: $serviceProviderType"
echo "pioneer: $pioneer"
echo "treasury: $treasury"
echo "provideramount: $provideramount"
echo "count: $count"
# Don't print the mnemonic for security reasons


if [ -z "$providername" ] || [ -z "$serviceProviderType" ] || [ -z "$pioneer" ] || [ -z "$treasury" ] || [ -z "$provideramount" ] || [ -z "$count" ]; then
    echo "Usage: $0 <providername> <serviceProviderType> (e.g. identity, finance) [--pioneer <pioneer>] [--treasury <treasury>] [--provider-mnemonic <providermnemonic>] [--provider-amount <provideramount>] [--count <count>]"
    exit 1
fi

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${provideramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${provideramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$provideramount
fi

echo "-------------------------"
echo "$providername Create wallet"
echo "-------------------------"
# IDEMPOTENT: a wallet that exists (locally AND therefore on chain -- the keyring entry is
# written by the same run that broadcast it) cannot be re-created; CreatePublicKey aborts on the
# local key and MsgCreateWallet would refuse the on-chain one.  Skipping is what lets a run that
# died mid-provider -- a failed widen, a network drop -- be resumed by just running it again.
if qadenad_alias keys show $providername --address > /dev/null 2>&1; then
    echo "$providername wallet already exists -- skipping create-wallet"
else
    qadenad_alias tx qadena create-wallet $providername $pioneer $treasury --account-mnemonic="$providermnemonic"  --yes
fi
qadena_addr=$(qadenad_alias keys show $providername --address)
result=$(fund_wallet "$qadena_addr")
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# check if code is 0
# `// -1` so an EMPTY result -- a tx that never broadcast -- fails here with a message instead of
# `[: unknown condition: -ne` followed by a wait loop on an empty hash (measured 2026-09-06).
if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
    echo "Error: broadcast failed or returned nothing: $(echo $result | jq -r '.raw_log // .message // "no output"')"
    exit 1
fi
# wait for result -- unless the sentinel above already did (feegrant path has no hash to wait on)
if [ -n "$tx_hash" ]; then
    qadenad_alias query wait-tx $tx_hash --timeout 30s
fi

if [ $count -gt 0 ]; then
    for i in $(seq 1 $count); do
        echo "-------------------------"
        echo "$providername Create wallet eph$i"
        echo "-------------------------"
        if qadenad_alias keys show $providername-eph$i --address > /dev/null 2>&1; then
            echo "$providername-eph$i already exists -- skipping create-wallet"
        else
            qadenad_alias tx qadena create-wallet $providername-eph$i $pioneer $treasury --link-to-real-wallet $providername --account-mnemonic="$providermnemonic" --eph-account-index "$i" --yes
        fi
        # transfer funds to eph wallet
        qadena_addr=$(qadenad_alias keys show $providername-eph$i --address)
        result=$(fund_wallet "$qadena_addr")
        echo "Result: $result"
        # get tx hash
        tx_hash=$(echo $result | jq -r .txhash)
        echo "tx hash: $tx_hash"
        # check if code is 0 (`// -1`: an empty result must FAIL, not crash the [ test)
        if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
            echo "Error: $(echo $result | jq -r '.raw_log // .message // "no output"')"
            exit 1
        fi
        # wait for result -- the feegrant sentinel carries no hash
        if [ -n "$tx_hash" ]; then
            qadenad_alias query wait-tx $tx_hash --timeout 30s
        fi
    done
fi

$qadenaproviderscripts/submit_service_provider_proposal.sh $treasury $providername add_service_provider_proposal $serviceProviderType $pioneer



