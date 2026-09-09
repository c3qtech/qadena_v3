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
# THE UNION OF BOTH WIDE SETS, DELIBERATELY.
#
# Two "wide" allowances used to exist: this operational set, and create_user's USER_MSGS (claims,
# credential updates, signatory registration, binds, ProtectPrivateKey).  A grantee holds ONE
# allowance per granter, and step_3's widen ran LAST -- so the end state silently dropped every
# claim/rotation/bind message, and the bring-up's own claims passed only because they executed
# between the two grants.  An ordering dependency invisible from the final state.
#
# MsgRevokeAllowance joins MsgGrantAllowance because the server always does revoke-then-grant
# (api/handlers/fee_grant.go:224-232) -- allowances do not layer, so a re-grant must revoke
# first.  Permitting the grant but not the revoke allows half of a pair that is only ever
# used together: with FoundationUsersAddress blank, wrapForGranter returns the BARE message
# and the pool wallet signs a raw revoke this allowance would refuse.  Verified in the
# app-server source 2026-09-06.
#
# The app-server itself never needs the dropped messages (verified against its code, 2026-09-06),
# so nothing broke in steady state -- but any re-run, repair or partial recovery would hit the
# narrowed set with no diagnosis.  The union costs nothing and removes the dependency.
VERITAS_APPSVR_MSGS="/qadena.dsvs.MsgCreateDocument,/qadena.dsvs.MsgRemoveDocument,/qadena.dsvs.MsgSignDocument,/qadena.dsvs.MsgRegisterAuthorizedSignatory,/qadena.qadena.MsgCreateCredential,/qadena.qadena.MsgRemoveCredential,/qadena.qadena.MsgClaimCredential,/qadena.qadena.MsgUpdateCredential,/qadena.qadena.MsgClaimUpdatedCredential,/qadena.qadena.MsgProtectPrivateKey,/qadena.qadena.MsgSignRecoverPrivateKey,/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet,/qadena.nameservice.MsgBindCredential,/qadena.nameservice.MsgUnbindCredential,/cosmos.feegrant.v1beta1.MsgGrantAllowance,/cosmos.feegrant.v1beta1.MsgRevokeAllowance"


# provider_address <mnemonic> [eph-index] -- the wallet address this provider WILL have.
#
# NOT `keys show`.  The address has to be knowable when the local key is ABSENT, which is exactly
# the state a failed create-wallet leaves behind -- its cleanup removes the key it wrote.  Asking
# the keyring then returns nothing, wallet_on_chain is handed an empty address, and the script
# concludes "no wallet on chain" for a wallet that exists and re-creates it.  That loop is
# unbreakable by re-running: every attempt dies on "Public key already exists" (2026-09-07).
#
# The address is a pure function of the mnemonic and the index, so derive it offline with the same
# code create-wallet uses (GetEphAccountAddress, via `debug derive-wallet-address`).
provider_address() {
    local _m="$1" _i="${2:-0}"
    print -r -- "$_m" | "${qadenabin:-$HOME/qadena/bin}/qadenad" debug derive-wallet-address "$_i" 2>/dev/null | tail -1
}

# wallet_on_chain <address> -- echoes the walletID if the chain has a wallet there, else nothing.
#
# TWO WRONG VERSIONS PRECEDED THIS ONE, BOTH SILENT:
#
#   `show-wallet | jq -r .wallet.walletID`  -- show-wallet prints progress lines BEFORE the JSON
#       ("Valid bech32 address...", "getWallet <addr>", "Wallet") and emits the object BARE, not
#       under a `.wallet` key.  jq therefore returned empty for wallets that plainly existed, so
#       the predicate said "no wallet on chain" for EVERY address.  On 2026-09-07 that made this
#       script delete a registered provider's local keys; the retry then failed with "Public key
#       already exists" and only the deterministic re-derivation saved them.
#
#   `list-wallet | jq select(.walletID==$a)`  -- correct on a small chain and wrong on a real one:
#       it fetches EVERY wallet to answer about one, and the response paginates, so past the page
#       limit an existing wallet reads as absent.  Same false "no wallet" as above, arriving only
#       once the deployment has grown.
#
# So: ask about the one address, and parse from the first line that begins a JSON object.
wallet_on_chain() {
    [ -n "${1:-}" ] || return 0
    local _out
    _out=$(qadenad_alias query qadena show-wallet "$1" --output json 2>&1 || true)
    # A QUERY THAT COULD NOT BE ANSWERED IS NOT A "NO".  The caller DELETES LOCAL KEYS on an empty
    # result, so an unreachable node, a wrong --node, or a mid-run RPC hiccup would destroy the
    # keys of wallets that exist.  Distinguish the three outcomes explicitly:
    #   walletID on stdout, rc 0  -> exists
    #   nothing on stdout, rc 0   -> definitively absent
    #   rc 2                      -> UNKNOWN; the caller must not act
    case "$_out" in
        *"no route to host"*|*"connection refused"*|*"context deadline exceeded"*|*"post failed"*|*"error: rpc"*)
            return 2 ;;
    esac
    print -r -- "$_out" | sed -n '/^{/,$p' | jq -r '.walletID // empty' 2>/dev/null || true
    return 0
}

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
# IDEMPOTENT, BUT KEYED ON THE CHAIN -- NOT ON THE KEYRING.
#
# This used to skip whenever a LOCAL key existed, on the premise that "the keyring entry is
# written by the same run that broadcast it".  That premise is false in the one case that matters:
# create-wallet writes the local key FIRST and broadcasts after, so a failed broadcast leaves a key
# with no wallet -- and every later run then skips it, forever.  The deployment can never recover
# by re-running, which is exactly what idempotence was supposed to buy.
#
# Measured 2026-09-07 on the fleet: 33 keys in the keyring, ZERO wallets on chain, both providers
# holding an IntervalPublicKeyID from a passed proposal and no public keys at all.  The app-server
# failed at a query long before any fee was involved, and the verifier was green because a fee
# grant can be issued to an address that does not exist.
#
# So: ask the chain.  A local key with no wallet must RE-RUN create-wallet, not skip it.
# Derived, not read from the keyring -- see provider_address() for why.
_paddr=$(provider_address "$providermnemonic" 0)
_onchain=$(wallet_on_chain "$_paddr") || {
    echo "cannot determine whether $providername exists on chain -- the node did not answer."
    echo "  Refusing to continue: the next step would DELETE this key and re-create the wallet."
    echo "  Check --node and try again."
    exit 1
}
if [ -n "$_onchain" ]; then
    echo "$providername wallet already exists ON CHAIN -- skipping create-wallet"
    # SELF-HEAL THE LOCAL KEY.  create-wallet is what writes it, so skipping create-wallet on a
    # wallet that already exists leaves a keyring with no key for it -- and the very next line,
    # `keys show $providername --address`, fails with
    #     is not a valid name or address: decoding bech32 failed: invalid separator index -1
    # because qadenad falls back to parsing the NAME as an address.  That message names neither
    # the keyring nor the missing key.
    #
    # It happens whenever the chain outlives the keyring: a deleted key, a wiped ~/sec-<name>, or
    # a deployment moved from keyring-test to keyring-file.  The mnemonic is right here and the
    # derivation is deterministic, so recovering costs nothing and cannot produce a different
    # address.  create_user.sh has done this for user wallets since 2026-09-07.
    if ! qadenad_alias keys show "$providername" --address > /dev/null 2>&1; then
        echo "  no local key for $providername -- recovering it from the mnemonic"
        { echo "$providermnemonic"
          [ -z "${QADENA_KEYRING_PASS:-}" ] || { echo "$QADENA_KEYRING_PASS"; echo "$QADENA_KEYRING_PASS"; }
        # --account 0 is the TRANSACTION wallet, the same derivation create_user.sh recovers with
        # and the one provider_address() computes.  A hand-built --hd-path would be a second place
        # to get the coin type wrong; the address check below would catch it, but not before
        # writing a key.
        } | qadenad_alias_raw keys add "$providername" --recover --account 0 > /dev/null 2>&1 \
          || { echo "  FAILED to recover $providername from its mnemonic"; exit 1; }
        _rec=$(qadenad_alias keys show "$providername" --address 2>/dev/null)
        if [ "$_rec" != "$_paddr" ]; then
            echo "  RECOVERED THE WRONG ADDRESS for $providername:"
            echo "    on chain: $_paddr"
            echo "    recovered: ${_rec:-<none>}"
            echo "  Refusing to continue -- this key would sign as somebody else."
            exit 1
        fi
        echo "  recovered $providername -> $_rec"
    fi
else
    if qadenad_alias keys show $providername --address > /dev/null 2>&1; then
        # The local key is a corpse from a failed broadcast.  create-wallet's CreatePublicKey
        # aborts on an existing local key, so it has to go before the retry can work.
        echo "$providername has a local key but NO wallet on chain -- a previous create-wallet"
        echo "  failed after writing the key.  Removing it and retrying."
        qadenad_alias keys delete $providername --yes > /dev/null 2>&1 || true
        qadenad_alias keys delete $providername-credential --yes > /dev/null 2>&1 || true
    fi
    # STATUS CHECKED.  Unchecked, a failure here is invisible: the script carries on to fund and
    # grant an address that will never be a wallet, and every downstream step "succeeds".
    if ! qadenad_alias tx qadena create-wallet $providername $pioneer $treasury --account-mnemonic="$providermnemonic" --yes; then
        echo "FAILED: create-wallet for $providername -- stopping rather than granting to a"
        echo "  non-existent wallet.  Fix the cause and re-run; this step is resumable."
        exit 1
    fi
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
        # SAME PREDICATE AS THE MAIN WALLET ABOVE, AND FOR THE SAME REASON.  A keyring-keyed skip
        # here left every ephemeral uncreated on the fleet while the main wallets succeeded: 2
        # wallets on chain, 33 keys locally, and no way to recover by re-running (2026-09-07).
        _eph_addr=$(qadenad_alias keys show $providername-eph$i --address 2>/dev/null || true)
        _eph_onchain=""
        if true; then
            _eph_onchain=$(wallet_on_chain "$(provider_address "$providermnemonic" "$i")") || {
                echo "cannot determine whether $providername-eph$i exists on chain -- node did not answer."
                echo "  Refusing to continue rather than deleting a key on a failed query."
                exit 1
            }
        fi
        if [ -n "$_eph_onchain" ]; then
            echo "$providername-eph$i already exists ON CHAIN -- skipping create-wallet"
            # SAME SELF-HEAL AS THE MAIN WALLET ABOVE.  Skipping create-wallet skips the only thing
            # that writes the local key, so `keys show $providername-eph$i` a few lines down fails
            # with "decoding bech32 failed" -- qadenad parsing the NAME as an address.
            #
            # --index $i is the EPHEMERAL index: the wallet is account 0 at address index i, which
            # is what provider_address() derives and what --eph-account-index creates.  The address
            # is checked against the chain's before the key is used.
            if [ -z "$_eph_addr" ]; then
                echo "  no local key for $providername-eph$i -- recovering it from the mnemonic"
                { echo "$providermnemonic"
                  [ -z "${QADENA_KEYRING_PASS:-}" ] || { echo "$QADENA_KEYRING_PASS"; echo "$QADENA_KEYRING_PASS"; }
                } | qadenad_alias_raw keys add "$providername-eph$i" --recover --account 0 --index "$i" > /dev/null 2>&1 \
                  || { echo "  FAILED to recover $providername-eph$i from its mnemonic"; exit 1; }
                _erec=$(qadenad_alias keys show "$providername-eph$i" --address 2>/dev/null)
                _ewant=$(provider_address "$providermnemonic" "$i")
                if [ "$_erec" != "$_ewant" ]; then
                    echo "  RECOVERED THE WRONG ADDRESS for $providername-eph$i:"
                    echo "    expected:  $_ewant"
                    echo "    recovered: ${_erec:-<none>}"
                    echo "  Refusing to continue -- this key would sign as somebody else."
                    exit 1
                fi
                echo "  recovered $providername-eph$i -> $_erec"
            fi
        else
            if [ -n "$_eph_addr" ]; then
                echo "$providername-eph$i has a local key but NO wallet on chain -- removing and retrying"
                qadenad_alias keys delete $providername-eph$i --yes > /dev/null 2>&1 || true
                qadenad_alias keys delete $providername-eph$i-credential --yes > /dev/null 2>&1 || true
            fi
            if ! qadenad_alias tx qadena create-wallet $providername-eph$i $pioneer $treasury --link-to-real-wallet $providername --account-mnemonic="$providermnemonic" --eph-account-index "$i" --yes; then
                echo "FAILED: create-wallet for $providername-eph$i -- stopping"
                exit 1
            fi
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



