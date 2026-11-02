#!/bin/zsh
#
# FOUNDATION SIDE.  Pre-grant one eKYC PH partner's wallets, after their step_1.
#
#   foundation_scripts/ekycph_partner_after_step_1.sh --pregrant <file> [options]
#
# WHY IT IS NEEDED.  A fee allowance is signed by its GRANTER and the granter's balance pays;
# grants do not chain.  So the partner's first transaction -- create-wallet -- already needs an
# allowance only the foundation can sign.  The partner derived every address it will ever hold in
# step_1, offline, with the same code create-wallet uses, so all of them can be granted here,
# before anything exists.  That is what removes the last foundation key from the partner's box.
#
# WHY THIS IS NOT A WRAPPER ON sec_veritas_after_step_1.sh, which does the same pre-granting.
# That script's first half AUTHORISES its deployment's admin to issue fee grants AS the foundation
# -- generic authz on MsgGrantAllowance, which (its own comment says) "cannot bound the amount or
# restrict the recipient".  SEC needs it because step_3 grants ~124 downstream wallets.  A PARTNER
# IS A THIRD-PARTY BUSINESS AND NEEDS NONE OF IT: it creates its own wallet and its ephemerals,
# every one of them covered by the pre-grants below, and the registration proposal is submitted by
# the foundation in ekycph_partner_after_step_2.sh.  Reaching that end state by passing a flag to
# the SEC script would make a trust grant the default and its absence an option; here there is
# nothing to switch off.  The shared part is the idempotent loop below, which is 30 lines.
#
# Options:
#   --pregrant <file>        the paste block the partner's step_1 emitted: every wallet the
#                            partner will create (count+1).  Each gets a narrow allowance --
#                            MsgAddPublicKey + MsgCreateWallet, nothing more.
#   --foundation-appsvr <k>  the granting account (default: ekycph's, from the profile)
#   --coord-home <dir>       keyring holding that account -- derive_launch_keys.sh --home.
#                            The node's keyring does NOT hold it.
#   --node <rpc>             the chain RPC; the chain-id is derived from it
#   --keyring-backend <b>    default file (encrypted); 'test' for a devnet keyring
#   --keyring-passfile <f>   read the keyring passphrase from a file

set -e

HERE="${0:A:h}"
PROG="${QADENA_PROG:-ekycph_partner_after_step_1.sh}"

# CAPTURE BEFORE SOURCING.  setup_env.sh sets QADENA_KEYRING_BACKEND=test for the devnet harness,
# so a later ${QADENA_KEYRING_BACKEND:-file} would always see "test" and the intended default
# would be dead code.
_kb_caller="${QADENA_KEYRING_BACKEND:-}"

SCRIPT_DIR="$HERE"
source "$HERE/../scripts/setup_env.sh"

source "$HERE/deployment_profile.sh"
deployment_profile_load "ekycph" || exit 1

PREGRANT=""
COORD_HOME=""
# FILE, NOT test.  These scripts operate on the COORDINATOR keyring, which derive_launch_keys.sh
# creates encrypted.  `test` is unencrypted and has no business near launch custody.
BACKEND="${_kb_caller:-file}"
KEYRING_PASSFILE=""
foundation_appsvr="$DEPLOY_APPSVR"
NODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pregrant)          PREGRANT="$2"; shift 2 ;;
        --foundation-appsvr) foundation_appsvr="$2"; shift 2 ;;
        --node)              NODE="$2"; export QADENA_NODE="$2"; shift 2 ;;
        --coord-home)        COORD_HOME="$2"; shift 2 ;;
        --keyring-backend)   BACKEND="$2"; shift 2 ;;
        --keyring-passfile)  KEYRING_PASSFILE="$2"; shift 2 ;;
        --help)
            awk 'NR<3{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

[ -n "$PREGRANT" ] || {
    echo "--pregrant <file> is required: the block the partner's step_1 printed." >&2
    exit 1; }
[ -r "$PREGRANT" ] || { echo "cannot read $PREGRANT" >&2; exit 1; }
jq -e . "$PREGRANT" >/dev/null 2>&1 || { echo "$PREGRANT is not valid JSON" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
# WHAT CAN BE CHECKED WITHOUT A KEY, CHECKED BEFORE ASKING FOR ONE.  The passphrase prompt is
# below; an operator handed a malformed block should learn that now, not after typing it.
# ---------------------------------------------------------------------------------------------
partner=$(jq -r '.partner // empty' "$PREGRANT")
[ -n "$partner" ] || { echo "REFUSING: $PREGRANT names no partner" >&2; exit 1; }

# ONE FAMILY -- the partner itself -- plus $count ephemerals.  The VERITAS block carries 4
# families (two providers, the create-wallet sponsor, the DSVS user); `families` is in the file so
# the arithmetic is the partner's own statement of what it derived, not an assumption here.
_count=$(jq -r '.count // empty' "$PREGRANT")
_families=$(jq -r '.families // 1' "$PREGRANT")
_n=$(jq -r '.wallets | length' "$PREGRANT")
if [ -n "$_count" ] && [ "$_n" -ne $(( _families * (_count + 1) )) ]; then
    echo "REFUSING: families=$_families count=$_count implies $(( _families * (_count + 1) )) wallets; file lists $_n." >&2
    echo "  step_1 warns and continues when a derivation fails; this is that gap." >&2
    exit 1
fi

W_NAMES=(); W_ADDRS=()
while IFS="$(printf '\t')" read -r _nm _ad; do
    case "$_ad" in
        qadena1*) ;;
        *) echo "REFUSING: '$_nm' has address '$_ad', not a qadena address" >&2; exit 1 ;;
    esac
    for _seen in "${W_ADDRS[@]}"; do
        [ "$_seen" = "$_ad" ] && { echo "REFUSING: $_ad appears twice" >&2; exit 1; }
    done
    W_NAMES+=("$_nm"); W_ADDRS+=("$_ad")
done < <(jq -r '.wallets[] | "\(.name)\t\(.address)"' "$PREGRANT")
[ ${#W_ADDRS[@]} -gt 0 ] || { echo "REFUSING: $PREGRANT lists no wallets" >&2; exit 1; }

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
NODE_HOME="${QADENAHOME:-$HOME/qadena}"
NODE="${NODE:-${QADENA_NODE:-tcp://localhost:26657}}"
[ -n "$COORD_HOME" ] || COORD_HOME="$NODE_HOME"

KRPASS=""
if [ "$BACKEND" = "file" ]; then
    if [ -n "$KEYRING_PASSFILE" ]; then
        KRPASS=$(head -1 "$KEYRING_PASSFILE")
    elif [ -n "${QADENA_KEYRING_PASS:-}" ]; then
        # Already unlocked by the caller: the devnet runners export QADENA_KEYRING_PASS for every
        # child, so prompting here would stall an unattended run for a passphrase already held.
        KRPASS="$QADENA_KEYRING_PASS"
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
# coordinator home's client.toml says chain-id = "".  Signing with that and broadcasting is an
# invalid signature, reported on this chain as a recovered amino panic with a goroutine dump.
CHAIN="${QADENA_CHAIN_ID:-$(qq status 2>/dev/null | sed -n '/^{/,$p' | jq -r '.node_info.network // empty')}"
[ -n "$CHAIN" ] || { echo "cannot determine the chain-id; set QADENA_CHAIN_ID" >&2; exit 1; }

# ONE CALL, AND THE ERROR IS READ.  A mistyped passphrase and an absent key both leave
# $fa_addr empty, and "no key '<name>' in the keyring" then sends an operator who merely
# mistyped off to hunt for the wrong --coord-home.  Asking twice is not the fix either:
# each attempt counts against the backend's three.
_kout=$(qk keys show "$foundation_appsvr" -a 2>&1) || true
fa_addr=$(print -r -- "$_kout" | tr -d '\r' | grep '^qadena1' | head -1)
[ -n "$fa_addr" ] || {
    case "$_kout" in
        *"incorrect passphrase"*|*"too many failed passphrase attempts"*)
            echo "WRONG PASSPHRASE for the keyring at $COORD_HOME." >&2
            echo "  The key may well be there; what was supplied does not open it." >&2
            echo "  Nothing has been signed or broadcast." >&2
            exit 1 ;;
    esac
    echo "no key '$foundation_appsvr' in the keyring at $COORD_HOME (backend $BACKEND)" >&2
    echo "  This script is run by the FOUNDATION, and the foundation accounts live in the" >&2
    echo "  COORDINATOR keyring -- pass --coord-home <dir>, the same --home you gave" >&2
    echo "  derive_launch_keys.sh / ekycph_before_step_1.sh." >&2
    exit 1; }
unset _kout

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

# ---------------------------------------------------------------------------------------------
# THE REST OF THE VALIDATION -- the parts that need the chain-id and the granting key.
# ---------------------------------------------------------------------------------------------
_fchain=$(jq -r '.chain_id // ""' "$PREGRANT")
if [ -n "$_fchain" ] && [ "$_fchain" != "$CHAIN" ]; then
    echo "REFUSING: $PREGRANT was generated on chain '$_fchain', this node is '$CHAIN'." >&2
    exit 1
fi

# THE SPONSOR THE PARTNER WILL NAME.  create-wallet takes the sponsor as a message field, and the
# allowance is keyed on (granter, grantee) -- so a partner that names a different account than the
# one granting here finds no allowance and cannot create a wallet at all.  The partner recorded
# which account it was told to use; if that is not this one, say so now rather than after signing
# count+1 grants that will never be found.
_fsponsor=$(jq -r '.sponsor // ""' "$PREGRANT")
if [ -n "$_fsponsor" ] && [ "$_fsponsor" != "$fa_addr" ]; then
    echo "REFUSING: the partner was given sponsor '$_fsponsor'," >&2
    echo "          but $foundation_appsvr is '$fa_addr'." >&2
    echo "          Grants signed here would be keyed to an account step_2 never names." >&2
    exit 1
fi

# Only these two messages: everything a wallet needs to come into existence, nothing more.
# The partner widens nothing afterwards -- it pays its own credential fees out of its own balance,
# because PrepareIdentityServiceProviderClientContextForPartner is one of only two
# Prepare*ClientContext functions in the app server that does not call withAppsvrFeeGranter.
NARROW="/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet"

echo "==================================================================="
echo "FOUNDATION: pre-granting for partner '$partner'"
echo "  granter : $foundation_appsvr ($fa_addr)"
echo "  chain   : $CHAIN"
echo "  wallets : ${#W_ADDRS[@]}"
echo "==================================================================="

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

# RETAIN WHAT WE SIGNED.  These addresses are the EXPECTED set: without a copy, later verification
# can only enumerate what exists on chain, which by construction cannot notice a wallet that was
# never granted at all.
if [ -n "$COORD_HOME" ] && [ -d "$COORD_HOME" ]; then
    cp "$PREGRANT" "$COORD_HOME/ekycph-partner-$partner-pregrant.json" 2>/dev/null \
        && chmod 600 "$COORD_HOME/ekycph-partner-$partner-pregrant.json" 2>/dev/null \
        && echo "retained the expected wallet set in $COORD_HOME/ekycph-partner-$partner-pregrant.json"
fi

if [ "$failed" -gt 0 ]; then
    echo ""
    echo "PARTIAL: $failed wallet(s) have no allowance.  step_2 will fail on exactly those and" >&2
    echo "no others.  Re-run this command; existing grants are skipped." >&2
    exit 1
fi

echo ""
echo "==================================================================="
echo "TELL THE PARTNER TO RUN, exactly:"
echo ""
echo "    ekycph_partner_scripts/step_2.sh $partner${QADENA_NODE:+ --node $QADENA_NODE}"
echo ""
echo "It creates the wallets against these grants and prints the registration"
echo "request for ekycph_partner_after_step_2.sh."
echo "==================================================================="
