#!/bin/zsh
#
# STEP 4 -- RUN BY THE QADENA FOUNDATION, NOT BY SEC.
#
# The last of the foundation's actions in the VERITAS bring-up. Steps 1, 2 and 3 are SEC's, and the
# foundation acts between and after them:
#
#   step_1  SEC        creates its keys, reports its admin address
#   *       FOUNDATION authorises that address to issue fee grants on the foundation's behalf
#   step_2  SEC        creates its providers, reports the two proposal ids
#   *       FOUNDATION approves the proposals
#   step_3  SEC        creates its wallets and users
#   *       FOUNDATION sec_veritas_after_step_3.sh -- the APP-SERVER's sponsor pool
#
# WHY THIS CANNOT BE PART OF step_3. Every grant here is signed by the GRANTER -- the foundation --
# and authz cannot be sub-delegated, so SEC cannot issue these on the foundation's behalf even with
# the step_1 authorisation. Running it inside step_3 would put a foundation private key on a SEC
# machine, which is the separation the whole three-step structure exists to preserve.
#
# WHAT IT GRANTS, per sponsor wallet in the app-server's pool:
#   authz    -- may send MsgGrantAllowance as foundation-users, so the server can issue a citizen's
#               allowance drawn on the foundation rather than on a wallet of its own
#   feegrant -- the foundation pays for those MsgExec transactions, so the server needs no balance
#
# Neither is money. Both are revocable with a single transaction.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

# FILE, NOT test.  The foundation accounts live in the COORDINATOR keyring that
# derive_launch_keys.sh / sec_veritas_before_step_1.sh created -- encrypted, and never the node's, which
# init.sh does `rm -rf` on.  An unencrypted default has no business near launch custody.
POOL_FILE=""
COORD_HOME=""
BACKEND="${QADENA_KEYRING_BACKEND:-file}"
KEYRING_PASSFILE=""

foundation_users="${VERITAS_FOUNDATION_USERS:-foundation-veritas-users}"
foundation_appsvr="${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}"
sponsor_base="${VERITAS_SPONSOR_BASE:-sec-create-wallet-sponsor}"
count=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pool-addresses)    POOL_FILE="$2"; shift 2 ;;
        --coord-home)        COORD_HOME="$2"; shift 2 ;;
        --keyring-backend)   BACKEND="$2"; shift 2 ;;
        --keyring-passfile)  KEYRING_PASSFILE="$2"; shift 2 ;;
        --foundation-users)  foundation_users="$2"; shift 2 ;;
        --foundation-appsvr) foundation_appsvr="$2"; shift 2 ;;
        --sponsor-base)      sponsor_base="$2"; shift 2 ;;
        --count)             count="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "  Authorises the app-server's sponsor pool: TWO transactions per wallet"
            echo "  (authz MsgGrantAllowance + feegrant MsgExec), so --count 30 sends 62."
            echo ""
            echo "  --foundation-users <k>   granting account, default $foundation_users"
            echo "  --foundation-appsvr <k>  default $foundation_appsvr"
            echo "  --pool-addresses <file>  pool_addresses.json from SEC's step_3.  PREFERRED:"
            echo "                           the foundation does not hold SEC's wallet keys, so"
            echo "                           resolving names from a local keyring only works in a"
            echo "                           harness.  The file is CHECKED before anything is sent."
            echo "  --sponsor-base <name>    pool base name; -eph1..-ephN are derived from it"
            echo "  --count <n>              ephemeral wallets in the pool; match SEC's step_1"
            echo "  --coord-home <dir>       keyring holding the foundation accounts --"
            echo "                           derive_launch_keys.sh --home.  Not the node's."
            echo "  --keyring-backend <b>    default $BACKEND (encrypted); 'test' for a devnet"
            echo "  --keyring-passfile <f>   read the keyring passphrase from a file"
            echo ""
            echo "  Pool members may be given as ADDRESSES.  In a real deployment they are SEC's"
            echo "  wallets and the foundation does not hold their keys -- names that cannot be"
            echo "  resolved are skipped and counted in the coverage warning."
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# COUNT COMES FROM THE POOL FILE WHEN THERE IS ONE, AND `variables.json` IS NOT A SOURCE HERE.
#
# variables.json is written by step_1 on SEC's machine and does not exist on the foundation's.
# The old form was `count=$(jq -r .count "$veritasscripts/variables.json" 2>/dev/null)` -- and
# under `set -e` a failing command substitution ENDS THE SCRIPT, silently, before a single line of
# output.  So this could never have run outside the harness, and the symptom was no error at all.
#
# `|| true` keeps set -e out of it; the pool file, when given, overrides this anyway.
if [ -z "$count" ]; then
    count=$(jq -r '.count // empty' "$veritasscripts/variables.json" 2>/dev/null || true)
    [ -n "$count" ] && [ "$count" != "null" ] || count=30
fi

# Signing needs the coordinator keyring; broadcasting and querying need the node.  They cannot
# share one wrapper: --keyring-backend is rejected outright by `query`.
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
# PER CALL.  This script makes 2 transactions per wallet -- 62 at --count 30 -- and a passphrase
# piped into the script as a whole is drained by the first qadenad, leaving the rest to read EOF,
# which the backend counts as a failed attempt and locks after three.
qk() {
    if [ -n "$KRPASS" ]; then
        { printf '%s\n' "$KRPASS"; printf '%s\n' "$KRPASS"; } \
            | "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    else
        "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    fi
}
qq() { "$QBIN" --home "$NODE_HOME" "$@" --node "$NODE"; }

# THE FILE IS CHECKED, NOT TRUSTED.
#
# Every failure this guards against is silent and per-wallet: the app-server picks an arbitrary
# pool member per request, so a short, stale or corrupted list produces onboarding that works for
# some citizens and not others -- the hardest possible shape to diagnose from a support ticket.
# Refuse up front instead, before a single grant is sent.
POOL_NAMES=(); POOL_ADDRS=()
if [ -n "$POOL_FILE" ]; then
    [ -r "$POOL_FILE" ] || { echo "cannot read $POOL_FILE"; exit 1; }
    jq -e . "$POOL_FILE" >/dev/null 2>&1 || { echo "$POOL_FILE is not valid JSON"; exit 1; }

    _fchain=$(jq -r '.chain_id // ""' "$POOL_FILE")
    _here=$(qq status 2>/dev/null | jq -r '.node_info.network // ""')
    if [ -n "$_fchain" ] && [ -n "$_here" ] && [ "$_fchain" != "$_here" ]; then
        echo "REFUSING: $POOL_FILE was generated on chain '$_fchain', this node is '$_here'."
        echo "  A pool file from another chain names addresses that mean nothing here."
        exit 1
    fi

    _declared=$(jq -r '.count // empty' "$POOL_FILE")
    _n=$(jq -r '.pool | length' "$POOL_FILE")
    if [ -n "$_declared" ] && [ "$_n" -ne $((_declared + 1)) ]; then
        echo "REFUSING: $POOL_FILE declares count=$_declared (so $((_declared + 1)) wallets) but lists $_n."
        echo "  step_3 warns and continues when a wallet has no address; this is that gap."
        exit 1
    fi

    while IFS=$'\t' read -r _nm _ad; do
        case "$_ad" in
            qadena1*) ;;
            *) echo "REFUSING: '$_nm' has address '$_ad', which is not a qadena address"; exit 1 ;;
        esac
        for _seen in "${POOL_ADDRS[@]}"; do
            [ "$_seen" = "$_ad" ] && { echo "REFUSING: $_ad appears twice in $POOL_FILE"; exit 1; }
        done
        POOL_NAMES+=("$_nm"); POOL_ADDRS+=("$_ad")
    done < <(jq -r '.pool[] | "\(.name)\t\(.address)"' "$POOL_FILE")

    [ ${#POOL_ADDRS[@]} -gt 0 ] || { echo "REFUSING: $POOL_FILE lists no wallets"; exit 1; }

    # EXISTS ON CHAIN.  A wallet step_3 never actually created, or an address mangled in transit,
    # is caught here rather than as a grant to nobody.
    _missing=0
    for _ad in "${POOL_ADDRS[@]}"; do
        qq query auth account "$_ad" >/dev/null 2>&1 || { echo "  NOT ON CHAIN: $_ad"; _missing=$((_missing+1)); }
    done
    [ "$_missing" -eq 0 ] || {
        echo "REFUSING: $_missing of ${#POOL_ADDRS[@]} pool addresses have no account on this chain."
        echo "  Either step_3 did not finish, or the file does not match this chain's state."
        exit 1; }

    count=$((${#POOL_ADDRS[@]} - 1))
    echo "  pool file verified: ${#POOL_ADDRS[@]} wallets, chain $_here, all present on chain"
fi

fu_addr=$(qk keys show "$foundation_users" -a 2>/dev/null) \
    || { echo "$foundation_users not in this keyring -- this script is run by the FOUNDATION, not by SEC"; exit 1; }
fa_addr=$(qk keys show "$foundation_appsvr" -a 2>/dev/null) \
    || { echo "$foundation_appsvr not in this keyring -- this script is run by the FOUNDATION, not by SEC"; exit 1; }

echo "-------------------------"
echo "Step 4: authorising the app-server to grant as $foundation_users"
echo "-------------------------"
echo "sponsor pool: $sponsor_base plus $count ephemeral wallets"

# WAIT FOR EACH TRANSACTION. They are all signed by the same account, so firing them in a loop
# without waiting means most are rejected for a sequence mismatch. An earlier version suppressed the
# output and left only 6 of 31 wallets authorised -- and because the app-server dequeues an arbitrary
# pool member per request, partial coverage fails INTERMITTENTLY, which is far harder to diagnose
# than failing outright.
grant_and_wait() {   # grant_and_wait <label> <wallet> <tx args...>
    local label="$1" w="$2"; shift 2
    local out hash code
    out=$(qk "$@" --from "$foundation_users" --node "$NODE" --yes --output json \
          --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment 2>&1) || {
        echo "  WARNING: $label for $w did not broadcast: $(echo "$out" | tail -1)"; return 1; }
    hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
    [ -n "$hash" ] || { echo "  WARNING: $label for $w produced no txhash"; return 1; }
    qq query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
    code=$(qq query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
    [ "$code" = "0" ] || { echo "  WARNING: $label for $w failed on chain (code $code)"; return 1; }
    return 0
}

authorised=0
incomplete=0
for i in $(seq 0 "$count"); do
    if [ ${#POOL_ADDRS[@]} -gt 0 ]; then
        w="${POOL_NAMES[$((i+1))]}"; w_addr="${POOL_ADDRS[$((i+1))]}"
    else
    if [ "$i" -eq 0 ]; then w="$sponsor_base"; else w="$sponsor_base-eph$i"; fi
    # THESE ARE SEC'S WALLETS, NOT THE FOUNDATION'S -- AND THAT IS A GAP.
    #
    # step_3.sh creates the sponsor pool on SEC's machine, in SEC's keyring.  This script runs on
    # the FOUNDATION's machine, which has no reason to hold those keys and in a real deployment
    # will not.  The devnet harness only gets away with it because it holds every key in one
    # keyring.  The proper fix is for SEC to hand over the pool ADDRESSES and for this to take a
    # --pool-addresses <file>; until then a name that cannot be resolved is skipped, and the
    # coverage warning at the end is what tells you it happened.
    case "$w" in
        qadena1*) w_addr="$w" ;;
        *)        w_addr=$(qk keys show "$w" -a 2>/dev/null | tr -d '\r') ;;
    esac
    [ -n "$w_addr" ] || { echo "  SKIPPED $w -- not resolvable in $COORD_HOME"; incomplete=$((incomplete+1)); continue; }
    fi
    ok=1
    grant_and_wait "authz" "$w" tx authz grant "$w_addr" generic \
        --msg-type /cosmos.feegrant.v1beta1.MsgGrantAllowance || ok=0
    grant_and_wait "feegrant" "$w" tx feegrant grant "$fu_addr" "$w_addr" \
        --allowed-messages /cosmos.authz.v1beta1.MsgExec || ok=0
    if [ "$ok" -eq 1 ]; then authorised=$((authorised+1)); echo "  authorised $w"
    else incomplete=$((incomplete+1)); echo "  INCOMPLETE: $w"; fi
done

echo ""
echo "authorised $authorised wallet(s); $incomplete incomplete"
if [ "$incomplete" -gt 0 ]; then
    echo ""
    echo "WARNING: partial coverage. The app-server picks an arbitrary pool member per request, so"
    echo "onboarding will fail for SOME users and not others. Re-run this step before going live."
fi
echo ""
echo "-------------------------"
echo "Send the following to SEC, for the app-server configuration"
echo "-------------------------"
echo "    QADENA_FOUNDATION_USERS_ADDRESS=$fu_addr"
echo "    QADENA_FOUNDATION_APPSVR_ADDRESS=$fa_addr"
echo ""
echo "Neither SEC's citizen sponsors nor its own operational wallets hold tokens -- they hold fee"
echo "grants from these two accounts. A grant is only used when the transaction NAMES it, so without"
echo "both settings the app-server fails with \"spendable balance 0aqdn\" rather than degrading."
