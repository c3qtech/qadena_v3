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
#   *       FOUNDATION sec_veritas_after_step_3.sh -- the app-server's sponsor pool
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
#   sec_veritas_after_step_1.sh --sec-admin <address-from-step_1> [--foundation-appsvr <key>]
#                               [--expiration <unix-seconds>]

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

sec_admin=""
COORD_HOME=""
# FILE, NOT test.  These scripts operate on the COORDINATOR keyring, which derive_launch_keys.sh
# creates with --keyring-backend file -- encrypted.  `test` is an UNENCRYPTED keyring, and pointing
# foundation tooling at one by default is wrong twice: it is the wrong keyring (the buckets are not
# in it, so every lookup fails with "no key"), and an unencrypted default has no business anywhere
# near launch custody.  Pass --keyring-backend test explicitly for a devnet.
BACKEND="${QADENA_KEYRING_BACKEND:-file}"
KEYRING_PASSFILE=""
foundation_appsvr="${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}"
expiration=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sec-admin)         sec_admin="$2"; shift 2 ;;
        --foundation-appsvr) foundation_appsvr="$2"; shift 2 ;;
        --expiration)        expiration="$2"; shift 2 ;;
        --coord-home)        COORD_HOME="$2"; shift 2 ;;
        --keyring-backend)   BACKEND="$2"; shift 2 ;;
        --keyring-passfile)  KEYRING_PASSFILE="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 --sec-admin <address> [options]"
            echo ""
            echo "  --sec-admin <address>    REQUIRED.  SEC's ADMIN address -- the key that will sign"
            echo "                           authz MsgExec, and that holds ZERO tokens by design."
            echo "                           step_1.sh prints it.  NOT the sec-treasury address."
            echo "  --foundation-appsvr <k>  the granting account, default $foundation_appsvr"
            echo "  --expiration <unix>      when the authorisation lapses, default now + 1 year"
            echo "  --coord-home <dir>       keyring holding the foundation account --"
            echo "                           derive_launch_keys.sh --home.  The node's keyring does"
            echo "                           NOT hold it."
            echo "  --keyring-backend <b>    default $BACKEND (encrypted); 'test' for a devnet keyring"
            echo "  --keyring-passfile <f>   read the keyring passphrase from a file"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[ -n "$sec_admin" ] || {
    echo "--sec-admin is required."
    echo "It is SEC's ADMIN address -- the zero-balance key that signs authz MsgExec, which"
    echo "step_1.sh prints.  It is NOT sec-treasury: steps 2 and 3 do not use that account."
    exit 1; }
case "$sec_admin" in
    qadena1*) ;;
    *) echo "--sec-admin '$sec_admin' is not a qadena address"; exit 1 ;;
esac

# THE FOUNDATION ACCOUNT IS NOT IN THE NODE'S KEYRING, AND SHOULD NOT BE.  derive_launch_keys.sh
# and sec_veritas_before_step_1.sh mint it into a COORDINATOR home, deliberately separate from $QADENAHOME,
# which init.sh does `rm -rf` on.  Signing therefore needs that keyring while the broadcast needs
# the node -- and --keyring-backend is not valid on `query`, so the two cannot share one wrapper.
QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
NODE_HOME="${QADENAHOME:-$HOME/qadena}"
NODE="${QADENA_NODE:-tcp://localhost:26657}"
[ -n "$COORD_HOME" ] || COORD_HOME="$NODE_HOME"

KRPASS=""
if [ "$BACKEND" = "file" ]; then
    if [ -n "$KEYRING_PASSFILE" ]; then
        KRPASS=$(head -1 "$KEYRING_PASSFILE")
    else
        printf "Coordinator keyring passphrase (%s, hidden): " "$COORD_HOME" >&2
        read -s KRPASS; echo "" >&2
    fi
fi
# Fed PER CALL, not piped into the script: one invocation makes several qadenad calls and a pipe
# is drained by the first, leaving the rest to read EOF -- which the backend counts as a failed
# attempt and locks after three.
qk() {
    if [ -n "$KRPASS" ]; then
        { printf '%s\n' "$KRPASS"; printf '%s\n' "$KRPASS"; } \
            | "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    else
        "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    fi
}
qq() { "$QBIN" --home "$NODE_HOME" "$@" --node "$NODE"; }
fa_addr=$(qk keys show "$foundation_appsvr" -a 2>/dev/null | tr -d '\r')
[ -n "$fa_addr" ] || {
    echo "no key '$foundation_appsvr' in the keyring at $COORD_HOME (backend $BACKEND)"
    echo "  This script is run by the FOUNDATION, and the foundation accounts live in the"
    echo "  COORDINATOR keyring -- pass --coord-home <dir>, the same --home you gave"
    echo "  derive_launch_keys.sh / sec_veritas_before_step_1.sh."
    exit 1; }

# An expiry is the main safety valve on an authorisation this broad. Default one year: long enough
# not to strand a deployment, short enough that a forgotten grant does not live forever.
[ -n "$expiration" ] || expiration=$(( $(date +%s) + 31536000 ))

gasflags=(--gas-prices "$minimum_gas_prices" --gas "$gas_auto" --gas-adjustment "$gas_adjustment")

send_and_wait() {   # send_and_wait <label> <tx args...>
    local label="$1"; shift
    local out hash code
    out=$(qk "$@" --from "$foundation_appsvr" --node "$NODE" --yes --output json "${gasflags[@]}" 2>&1) \
        || { echo "  FAILED: $label did not broadcast: $(echo "$out" | tail -1)"; return 1; }
    hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
    [ -n "$hash" ] || { echo "  FAILED: $label produced no txhash"; return 1; }
    qq query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
    code=$(qq query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
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
