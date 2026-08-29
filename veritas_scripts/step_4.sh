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
#   step_4  FOUNDATION authorises the APP-SERVER's sponsor pool, and returns the two addresses
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

foundation_users="${VERITAS_FOUNDATION_USERS:-foundation-users}"
foundation_appsvr="${VERITAS_FOUNDATION_APPSVR:-foundation-appsvr}"
sponsor_base="${VERITAS_SPONSOR_BASE:-sec-create-wallet-sponsor}"
count=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --foundation-users)  foundation_users="$2"; shift 2 ;;
        --foundation-appsvr) foundation_appsvr="$2"; shift 2 ;;
        --sponsor-base)      sponsor_base="$2"; shift 2 ;;
        --count)             count="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [--foundation-users <key>] [--foundation-appsvr <key>] [--sponsor-base <name>] [--count <n>]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$count" ]; then
    count=$(jq -r .count "$veritasscripts/variables.json" 2>/dev/null)
    [ -n "$count" ] && [ "$count" != "null" ] || count=30
fi

fu_addr=$(qadenad_alias keys show "$foundation_users" -a 2>/dev/null) \
    || { echo "$foundation_users not in this keyring -- step_4 is run by the FOUNDATION, not by SEC"; exit 1; }
fa_addr=$(qadenad_alias keys show "$foundation_appsvr" -a 2>/dev/null) \
    || { echo "$foundation_appsvr not in this keyring -- step_4 is run by the FOUNDATION, not by SEC"; exit 1; }

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
    out=$(qadenad_alias "$@" --from "$foundation_users" --yes --output json \
          --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment 2>&1) || {
        echo "  WARNING: $label for $w did not broadcast: $(echo "$out" | tail -1)"; return 1; }
    hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
    [ -n "$hash" ] || { echo "  WARNING: $label for $w produced no txhash"; return 1; }
    qadenad_alias query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
    code=$(qadenad_alias query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
    [ "$code" = "0" ] || { echo "  WARNING: $label for $w failed on chain (code $code)"; return 1; }
    return 0
}

authorised=0
incomplete=0
for i in $(seq 0 "$count"); do
    if [ "$i" -eq 0 ]; then w="$sponsor_base"; else w="$sponsor_base-eph$i"; fi
    w_addr=$(qadenad_alias keys show "$w" -a 2>/dev/null) || continue
    [ -n "$w_addr" ] || continue
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
