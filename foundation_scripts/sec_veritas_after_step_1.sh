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

# CAPTURE BEFORE SOURCING.  setup_env.sh defaults QADENA_KEYRING_BACKEND to `test` for the
# harness, and this script sources it first -- so ${QADENA_KEYRING_BACKEND:-file} always saw
# "test" and the intended file default was dead code (measured 2026-09-06).  Foundation tooling
# operates on the ENCRYPTED coordinator keyring; only an explicit caller choice says otherwise.
_kb_caller="${QADENA_KEYRING_BACKEND:-}"
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

sec_admin=""
PREGRANT=""
COORD_HOME=""
# FILE, NOT test.  These scripts operate on the COORDINATOR keyring, which derive_launch_keys.sh
# creates with --keyring-backend file -- encrypted.  `test` is an UNENCRYPTED keyring, and pointing
# foundation tooling at one by default is wrong twice: it is the wrong keyring (the buckets are not
# in it, so every lookup fails with "no key"), and an unencrypted default has no business anywhere
# near launch custody.  Pass --keyring-backend test explicitly for a devnet.
BACKEND="${_kb_caller:-file}"
KEYRING_PASSFILE=""
foundation_appsvr="${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}"
expiration=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sec-admin)         sec_admin="$2"; shift 2 ;;
        --foundation-appsvr) foundation_appsvr="$2"; shift 2 ;;
        --expiration)        expiration="$2"; shift 2 ;;
        --pregrant)          PREGRANT="$2"; shift 2 ;;
        --node)              NODE="$2"; export QADENA_NODE="$2"; shift 2 ;;
        --coord-home)        COORD_HOME="$2"; shift 2 ;;
        --keyring-backend)   BACKEND="$2"; shift 2 ;;
        --keyring-passfile)  KEYRING_PASSFILE="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 --sec-admin <address> [options]"
            echo ""
            echo "  --pregrant <file>        the paste block step_1 emitted: the admin address plus"
            echo "                           EVERY wallet the bring-up will create (4 families x"
            echo "                           count+1).  Each gets a narrow fee allowance signed here,"
            echo "                           so no SEC step ever needs a foundation key."
            echo "  --sec-admin <address>    SEC's ADMIN address -- the key that will sign"
            echo "                           authz MsgExec, and that holds ZERO tokens by design."
            echo "                           step_1.sh prints it.  NOT the sec-treasury address."
            echo "  --foundation-appsvr <k>  the granting account, default $foundation_appsvr"
            echo "  --expiration <unix>      when the authorisation lapses, default now + 1 year"
            echo "  --coord-home <dir>       keyring holding the foundation account --"
            echo "  --node <rpc>                the chain RPC; the chain-id is derived from it"
            echo "                           derive_launch_keys.sh --home.  The node's keyring does"
            echo "                           NOT hold it."
            echo "  --keyring-backend <b>    default $BACKEND (encrypted); 'test' for a devnet keyring"
            echo "  --keyring-passfile <f>   read the keyring passphrase from a file"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# The pregrant file carries the admin address, so --sec-admin may be omitted when it is given.
if [ -z "$sec_admin" ] && [ -n "$PREGRANT" ] && [ -r "$PREGRANT" ]; then
    sec_admin=$(jq -r '.sec_admin // empty' "$PREGRANT" 2>/dev/null)
fi
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
NODE="${NODE:-${QADENA_NODE:-tcp://localhost:26657}}"
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

# THE CHAIN-ID IS SIGNED, AND THE COORDINATOR HOME DOES NOT KNOW IT.  A signature binds the
# chain-id; the tx client fills it from client.toml of whatever --home it was given, and the
# COORDINATOR home's client.toml says chain-id = "" (observed).  Signing with that and
# broadcasting to qadena_4824-1 is an invalid signature -- which this chain reports, via cosmos/
# evm's EIP-712 fallback, as a recovered amino panic with a goroutine dump (see app/ante/ante.go).
# Resolve it from the node once and pass it explicitly on every tx.
CHAIN="${QADENA_CHAIN_ID:-$(qq status 2>/dev/null | jq -r '.node_info.network // empty')}"
[ -n "$CHAIN" ] || { echo "cannot determine the chain-id; set QADENA_CHAIN_ID"; exit 1; }
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
    out=$(qk "$@" --from "$foundation_appsvr" --node "$NODE" --chain-id "$CHAIN" --yes --output json "${gasflags[@]}" 2>&1) \
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

# REVOKE AUTHORITY TOO.  GenericAuthorization is one message type per grant, and widening an
# allowance is revoke-then-grant: a grantee holds at most ONE allowance per granter, so the
# narrow bootstrap grant must be revoked before the wide one lands.  With only MsgGrantAllowance
# delegated, the delegated revoke failed SILENTLY (grant_as_foundation fire-and-forgets it) and
# every widen died on "fee allowance already exists" -- unmeasurable before pre-granting, because
# the old inline flow rarely had an existing allowance to displace.  Measured 2026-09-06.
send_and_wait "authz (MsgRevokeAllowance)" tx authz grant "$sec_admin" generic \
    --msg-type /cosmos.feegrant.v1beta1.MsgRevokeAllowance --expiration "$expiration"

# AND PROPOSAL SUBMISSION.  Registering a service provider is a governance proposal, and the
# chain demands a MINIMUM INITIAL DEPOSIT from the PROPOSER (x/gov deposit.go: "was (), need
# 12500000000000000000000aqdn") -- real tokens, which no fee grant can carry and SEC holds none
# of by design.  So the proposer must be the foundation, and SEC submits AS the foundation under
# this authz: inner MsgSubmitProposal with the sponsor as proposer (its balance pays the initial
# deposit), exec signed by the admin.  Same shape as every other delegated act in this flow.
send_and_wait "authz (MsgSubmitProposal)" tx authz grant "$sec_admin" generic \
    --msg-type /cosmos.gov.v1.MsgSubmitProposal --expiration "$expiration"

# Without this, SEC pays for its own MsgExec transactions -- and SEC has no tokens, which is the
# whole point. This one allowance is what keeps its balance at zero.
# IDEMPOTENT, unlike the authz grant above.  authz re-granting OVERWRITES; feegrant re-granting
# REFUSES ("fee allowance already exists"), so a re-run -- the normal recovery after a partial
# pregrant phase below -- died here on its own earlier success.  Skip when present.
if qq query feegrant grant "$fa_addr" "$sec_admin" --output json >/dev/null 2>&1; then
    echo "  ok: feegrant (MsgExec) already present -- skipped"
else
    send_and_wait "feegrant (MsgExec)" tx feegrant grant "$fa_addr" "$sec_admin" \
        --allowed-messages /cosmos.authz.v1beta1.MsgExec
fi

echo ""
echo "==================================================================="
echo "TELL SEC TO RUN, exactly:"
echo ""
echo "    veritas_scripts/step_2.sh${QADENA_NODE:+ --node $QADENA_NODE}"
echo ""
echo "No exports needed: step_2 reads the admin name from variables.json and USES the"
echo "delegation only after verifying this grant on chain.  step_3 the same, after the"
echo "proposals pass."
echo "==================================================================="
echo ""
echo "To withdraw this at any time:"
echo "    qadenad tx authz revoke $sec_admin /cosmos.feegrant.v1beta1.MsgGrantAllowance --from $foundation_appsvr"

# ---------------------------------------------------------------------------------------------
# PRE-GRANT PHASE: one narrow allowance per upcoming wallet, signed by the sponsor AT HOME.
#
# Chain rules pin the bootstrap grant to the foundation -- MsgGrantAllowance is signed by its
# granter and the granter's balance pays (grants do not chain) -- but nothing pins WHEN.  A grant
# is keyed on the grantee ADDRESS; SEC derived every upcoming wallet's address offline in step_1;
# so the foundation signs all of them here, before anything exists, and create-wallet later finds
# each allowance on chain and skips its own inline grantFee.  This is what removes the last
# foundation private key from SEC's box.
#
# The allowance is deliberately NARROW -- MsgAddPublicKey + MsgCreateWallet, mirroring the inline
# grantFee it replaces.  step_2/step_3 widen each wallet afterwards through the admin's delegated
# authz (grant_as_foundation, revoke-first).
if [ -n "$PREGRANT" ]; then
    [ -r "$PREGRANT" ] || { echo "cannot read $PREGRANT"; exit 1; }
    jq -e . "$PREGRANT" >/dev/null 2>&1 || { echo "$PREGRANT is not valid JSON"; exit 1; }

    _fchain=$(jq -r '.chain_id // ""' "$PREGRANT")
    if [ -n "$_fchain" ] && [ -n "$CHAIN" ] && [ "$_fchain" != "$CHAIN" ]; then
        echo "REFUSING: $PREGRANT was generated on chain '$_fchain', this node is '$CHAIN'."
        exit 1
    fi
    _count=$(jq -r '.count // empty' "$PREGRANT")
    _n=$(jq -r '.wallets | length' "$PREGRANT")
    # 4 user families (2 providers, sponsor, dsvs user), each main + eph1..count.
    if [ -n "$_count" ] && [ "$_n" -ne $(( 4 * (_count + 1) )) ]; then
        echo "REFUSING: count=$_count implies $(( 4 * (_count + 1) )) wallets; file lists $_n."
        echo "  step_1 warns and continues when a derivation fails; this is that gap."
        exit 1
    fi

    W_NAMES=(); W_ADDRS=()
    while IFS="$(printf '\t')" read -r _nm _ad; do
        case "$_ad" in
            qadena1*) ;;
            *) echo "REFUSING: '$_nm' has address '$_ad', not a qadena address"; exit 1 ;;
        esac
        for _seen in "${W_ADDRS[@]}"; do
            [ "$_seen" = "$_ad" ] && { echo "REFUSING: $_ad appears twice"; exit 1; }
        done
        W_NAMES+=("$_nm"); W_ADDRS+=("$_ad")
    done < <(jq -r '.wallets[] | "\(.name)\t\(.address)"' "$PREGRANT")
    [ ${#W_ADDRS[@]} -gt 0 ] || { echo "REFUSING: $PREGRANT lists no wallets"; exit 1; }

    # Only these two messages: everything a wallet needs to come into existence, nothing more.
    NARROW="/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet"

    echo ""
    echo "--- pre-granting ${#W_ADDRS[@]} wallet(s) from $foundation_appsvr ($fa_addr)"
    granted=0; skipped=0; failed=0
    i=1
    while [ $i -le ${#W_ADDRS[@]} ]; do
        _nm="${W_NAMES[$i]}"; _ad="${W_ADDRS[$i]}"
        # Idempotent: an existing allowance is a re-run or an already-created wallet; skipping is
        # right either way, which is what makes a partial failure safe to just re-run.
        if qq query feegrant grant "$fa_addr" "$_ad" --output json >/dev/null 2>&1; then
            skipped=$(( skipped + 1 ))
        elif send_and_wait "pregrant $_nm" tx feegrant grant "$fa_addr" "$_ad" \
                --allowed-messages "$NARROW"; then
            granted=$(( granted + 1 ))
        else
            failed=$(( failed + 1 ))
        fi
        i=$(( i + 1 ))
    done

    echo ""
    echo "pre-grant done: $granted granted, $skipped already present, $failed failed"

    # RETAIN WHAT WE SIGNED.  These addresses are the EXPECTED set: without a copy, later
    # verification can only enumerate what exists on chain, which by construction cannot notice a
    # wallet that was never granted at all.  The foundation authorised these -- it should be able
    # to check its own work without asking SEC for the file back.
    if [ -n "$COORD_HOME" ] && [ -d "$COORD_HOME" ]; then
        cp "$PREGRANT" "$COORD_HOME/veritas-pregrant.json" 2>/dev/null \
            && chmod 600 "$COORD_HOME/veritas-pregrant.json" 2>/dev/null \
            && echo "retained the expected wallet set in $COORD_HOME/veritas-pregrant.json"
    fi
    if [ "$failed" -gt 0 ]; then
        echo ""
        echo "PARTIAL: $failed wallet(s) have no allowance.  step_2/step_3 will fail on exactly"
        echo "those and no others.  Re-run this command; existing grants are skipped."
        exit 1
    fi
fi
