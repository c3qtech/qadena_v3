#!/bin/zsh
#
# RUN BY THE QADENA FOUNDATION, after SEC's step_1 and before SEC's step_2.
#
# This REPLACES the old "QFI grants the necessary amount to sec-treasury" handoff. Nothing is
# transferred any more: SEC holds no tokens at all. What it receives instead is a revocable
# permission to spend the foundation's money on fees, and nothing else.
#
#   step_1  SEC        creates its keys, reports its admin address
#   HERE    FOUNDATION authorises that address to issue fee grants on the foundation's behalf
#   step_2  SEC        creates its providers, reports the two proposal ids
#   *       FOUNDATION approves the proposals
#   step_3  SEC        creates its wallets and users -- granting each one AS the foundation
#   *       FOUNDATION veritas_sec_authorise_pool.sh -- the app-server's sponsor pool
#
# WHY IT IS NEEDED. A fee grant is signed by its GRANTER. step_3 has to grant every wallet it
# creates -- a wallet holds nothing on a toll-free chain, and cannot even claim its own credential
# without one -- so without this, step_3 would need a foundation private key on a SEC machine.
#
# WHAT SEC CAN DO WITH IT: send /cosmos.feegrant.v1beta1.MsgGrantAllowance as the foundation, and
# have the foundation pay for those MsgExec transactions. GenericAuthorization cannot cap the amount
# or restrict the recipient, so this is a real trust grant -- bounded by its expiry, by the spend
# limits SEC puts on the grants it issues, and by the foundation's ability to revoke it instantly.
#
# Usage:
#   veritas_sec_delegate_grant_authority.sh --sec-admin <address-from-step_1> [--foundation-appsvr <key>]
#                               [--expiration <unix-seconds>]

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

sec_admin=""
foundation_appsvr="${VERITAS_FOUNDATION_APPSVR:-foundation-appsvr}"
expiration=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sec-admin)         sec_admin="$2"; shift 2 ;;
        --foundation-appsvr) foundation_appsvr="$2"; shift 2 ;;
        --expiration)        expiration="$2"; shift 2 ;;
        --help) echo "Usage: $0 --sec-admin <address> [--foundation-appsvr <key>] [--expiration <unix>]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[ -n "$sec_admin" ] || { echo "--sec-admin is required (the address step_1 printed)"; exit 1; }
fa_addr=$(qadenad_alias keys show "$foundation_appsvr" -a 2>/dev/null) \
    || { echo "$foundation_appsvr not in this keyring -- this script is run by the FOUNDATION"; exit 1; }

# An expiry is the main safety valve on an authorisation this broad. Default one year: long enough
# not to strand a deployment, short enough that a forgotten grant does not live forever.
[ -n "$expiration" ] || expiration=$(( $(date +%s) + 31536000 ))

gasflags=(--gas-prices "$minimum_gas_prices" --gas "$gas_auto" --gas-adjustment "$gas_adjustment")

send_and_wait() {   # send_and_wait <label> <tx args...>
    local label="$1"; shift
    local out hash code
    out=$(qadenad_alias "$@" --from "$foundation_appsvr" --yes --output json "${gasflags[@]}" 2>&1) \
        || { echo "  FAILED: $label did not broadcast: $(echo "$out" | tail -1)"; return 1; }
    hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
    [ -n "$hash" ] || { echo "  FAILED: $label produced no txhash"; return 1; }
    qadenad_alias query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
    code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
    [ "$code" = "0" ] || { echo "  FAILED: $label on chain (code $code)"; return 1; }
    echo "  ok: $label"
    return 0
}

echo "-------------------------"
echo "Authorising SEC to issue fee grants as $foundation_appsvr"
echo "-------------------------"
echo "SEC admin address: $sec_admin"
echo "expires:           $(date -r "$expiration" 2>/dev/null || echo "$expiration")"

send_and_wait "authz (MsgGrantAllowance)" tx authz grant "$sec_admin" generic \
    --msg-type /cosmos.feegrant.v1beta1.MsgGrantAllowance --expiration "$expiration"

# Without this, SEC pays for its own MsgExec transactions -- and SEC has no tokens, which is the
# whole point. This one allowance is what keeps its balance at zero.
send_and_wait "feegrant (MsgExec)" tx feegrant grant "$fa_addr" "$sec_admin" \
    --allowed-messages /cosmos.authz.v1beta1.MsgExec

echo ""
echo "Tell SEC to run step_2, then step_3, with:"
echo "    export VERITAS_SEC_ADMIN=<the key name for $sec_admin>"
echo ""
echo "To withdraw this at any time:"
echo "    qadenad tx authz revoke $sec_admin /cosmos.feegrant.v1beta1.MsgGrantAllowance --from $foundation_appsvr"
