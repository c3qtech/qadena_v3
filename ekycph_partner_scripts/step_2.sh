#!/bin/zsh
#
# PARTNER SIDE, step 2 of 3.  Create the wallets, then emit the registration request.
#
#   ekycph_partner_scripts/step_2.sh <partner-name> [--home DIR] [--node RPC]
#
# RUN THIS ONLY AFTER THE FOUNDATION HAS PRE-GRANTED.  Every wallet below is paid for by a fee
# allowance the foundation signed against its address in advance; without that, the first
# create-wallet refuses with "no fee allowance ... sponsor's key is not in this keyring" -- which
# is the separation working as designed, one step early.  This script checks the allowance for the
# main wallet before it tries, so the refusal names the cause.
#
# WHAT IT HANDS OVER.  A MsgAddServiceProvider proposal needs four things: nodeID, pubKID,
# serviceProviderType and homePioneerID -- and pubKID IS the wallet's bech32 address
# (provider_scripts/submit_service_provider_proposal.sh:66 sets it from `keys show`).  All four
# are plain text, so the foundation can submit the proposal without ever holding this partner's
# key.  That is what keeps the registration on the foundation's side of the line while the key
# stays on this one.
#
# Re-running is safe: the CHAIN is asked whether each wallet exists before it is created.

set -e

SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"
export QADENA_KEYRING_BACKEND
export QADENA_LAUNCH_ROOT="${QADENA_LAUNCH_ROOT:-$HOME/qadena-dev-launch}"

unset partner home
while [[ $# -gt 0 ]]; do
    case "$1" in
        --home) home="$2"; shift 2 ;;
        --node) export QADENA_NODE="$2"; shift 2 ;;
        --help)
            awk 'NR<3{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
            exit 0
            ;;
        --*) echo "Unknown option: $1" >&2; exit 1 ;;
        *)   [ -z "${partner:-}" ] && partner="$1"; shift 1 ;;
    esac
done

[ -n "${partner:-}" ] || { echo "Usage: $0 <partner-name> [--home DIR] [--node RPC]" >&2; exit 1; }
: ${home:="$QADENA_LAUNCH_ROOT/ekycph_partners/$partner"}

_vars="$home/variables.json"
[ -r "$_vars" ] || {
    echo "no $_vars -- step_1 has not run for '$partner'." >&2
    echo "  (or it wrote elsewhere: pass the same --home step_1 was given)" >&2
    exit 1; }

pioneer=$(jq -r '.pioneer' "$_vars")
sponsor=$(jq -r '.sponsor' "$_vars")
count=$(jq -r '.count' "$_vars")
chain_id=$(jq -r '.chain_id // ""' "$_vars")

# THE MNEMONIC IS NEEDED FOR EVERY create-wallet, INCLUDING THE EPHEMERALS.  create-wallet derives
# the account from --account-mnemonic, so an empty value does not fail -- it derives a DIFFERENT
# wallet, linked to the right real one, that the partner can never sign for.
[ -r "$home/$partner.mnemonic" ] || {
    echo "no $home/$partner.mnemonic -- step_1 did not complete." >&2; exit 1; }
mnemonic=$(head -1 "$home/$partner.mnemonic")

# THE CHAIN THE BLOCK WAS BUILT FOR.  step_1 stamped it; a partner pointed at a different node
# between the two steps would create wallets on a chain whose foundation granted nothing.
_now=$(qadenad_alias status 2>/dev/null | sed -n '/^{/,$p' | jq -r '.node_info.network // ""')
if [ -n "$chain_id" ] && [ -n "$_now" ] && [ "$chain_id" != "$_now" ]; then
    echo "REFUSING: step_1 ran on chain '$chain_id', this node is '$_now'." >&2
    exit 1
fi

# UNLOCK ONCE, HERE.  create-wallet writes a key and signs; on a current devnet the keyring is the
# encrypted `file` backend.  AFTER the argument loop, so --help never prompts.
qadena_keyring_unlock

echo "============================================================"
echo "PARTNER step_2          : $partner"
echo "foundation sponsor      : $sponsor"
echo "pioneer                 : $pioneer"
echo "ephemeral wallets       : $count"
echo "============================================================"

derive_addr() {   # derive_addr <mnemonic> <index>
    print -r -- "$1" | "${qadenabin:-$HOME/qadena/bin}/qadenad" \
        debug derive-wallet-address "$2" 2>/dev/null | tail -1
}

# wallet_on_chain <address> -- echoes the walletID if the chain has a wallet there, else nothing.
# Lifted verbatim in shape from provider_scripts/setup_provider_base.sh, including why:
#   `show-wallet | jq .wallet.walletID` -- show-wallet prints progress lines BEFORE the JSON and
#       emits the object BARE, so that returns empty for wallets that plainly exist;
#   `list-wallet | jq select(...)`      -- paginates, so past the page limit an existing wallet
#       reads as absent.
# And a query that could not be ANSWERED is not a "no": rc 2 means the caller must not act.
wallet_on_chain() {
    [ -n "${1:-}" ] || return 0
    local _out
    _out=$(qadenad_alias query qadena show-wallet "$1" --output json 2>&1 || true)
    case "$_out" in
        *"no route to host"*|*"connection refused"*|*"context deadline exceeded"*|*"post failed"*|*"error: rpc"*)
            return 2 ;;
    esac
    print -r -- "$_out" | sed -n '/^{/,$p' | jq -r '.walletID // empty' 2>/dev/null || true
    return 0
}

partner_addr=$(derive_addr "$mnemonic" 0)
[ -n "$partner_addr" ] || { echo "FAILED: could not derive $partner's address" >&2; exit 1; }
echo "address                 : $partner_addr"

# ------------------------------------------------------------------------------------------
# THE ALLOWANCE, CHECKED BEFORE THE FIRST TRANSACTION.  Without it create-wallet tries to issue
# the grant inline, signed by the sponsor -- whose key is deliberately not on this machine -- and
# fails naming the keyring rather than the missing handover.
# ------------------------------------------------------------------------------------------
if ! qadenad_alias query feegrant grant "$sponsor" "$partner_addr" --output json >/dev/null 2>&1; then
    _existing=$(wallet_on_chain "$partner_addr") || true
    if [ -n "$_existing" ]; then
        echo "--- no allowance for $partner_addr, but the wallet already exists on chain."
        echo "    create-wallet is done; the grant was consumed or revoked.  Continuing."
    else
        echo "FAILED: $sponsor has granted no fee allowance to $partner_addr." >&2
        echo "        The foundation has not run ekycph_partner_after_step_1.sh for this" >&2
        echo "        partner, or ran it against a different sponsor account." >&2
        echo "        Nothing has been created -- re-run this step after they have." >&2
        exit 1
    fi
fi

# ------------------------------------------------------------------------------------------
# 1. The wallet.
# ------------------------------------------------------------------------------------------
# THE CHAIN IS THE AUTHORITY, NOT THE KEYRING.  create-wallet writes the local key FIRST and
# broadcasts after, so a failed broadcast leaves a key with no wallet behind it -- and skipping
# on "the key is here" would then skip the only thing that creates the wallet.
_wid=$(wallet_on_chain "$partner_addr") || {
    echo "FAILED: could not reach the chain to ask about $partner_addr" >&2; exit 1; }
if [ -n "$_wid" ]; then
    echo "--- $partner already has a wallet on chain, skipping create-wallet"
else
    echo "-------------------------"
    echo "$partner: create wallet"
    echo "-------------------------"
    # THE SPONSOR IS AN ADDRESS, NOT A KEYRING NAME.  It is a message field, not a fee, so it
    # cannot itself be fee-granted -- and the foundation's account is not in this keyring, so a
    # name would resolve to nothing.  It must be the SAME account that signed the allowance above.
    qadenad_alias tx qadena create-wallet "$partner" "$pioneer" "$sponsor" \
        --account-mnemonic="$mnemonic" --yes
fi

# THE -credential KEY MUST EXIST, AND ONLY create-wallet MAKES IT.
#
# create-wallet derives TWO keys from the one mnemonic: the transaction key at account index 0 and
# <name>-credential at index 1 (CredentialWalletType, x/qadena/types/keys.go).  A provider that
# acquired its identity any other way has only the first, and the gap is invisible until it is
# named as a key-recovery partner, where sign-recover-key's --is-service-provider branch cannot
# sign for it.
#
# This is not hypothetical.  coopnet / maya / coinsph / unionbank were genesis-declared providers
# until eb35ee11 (2026-07-30) removed every service provider from genesis for exactly this reason;
# testscripts/setup_prerequisites.sh:428 asserts the same thing for the providers it onboards.
if ! qadenad_alias keys show "$partner-credential" >/dev/null 2>&1; then
    echo "FAILED: $partner-credential was not derived -- create-wallet did not complete." >&2
    echo "        A wallet without its credential key cannot act as a key-recovery partner." >&2
    exit 1
fi
echo "    credential key: $partner-credential present"

# ------------------------------------------------------------------------------------------
# 2. Ephemeral wallets, the same shape a user gets (setup_wallets.sh: <name> plus <name>-eph1).
#    The partner role itself signs from the base wallet, so these are for parity with a user
#    rather than a requirement -- step_1 --count 0 skips them.
# ------------------------------------------------------------------------------------------
for i in $(seq 1 "$count"); do
    _eph=$(derive_addr "$mnemonic" "$i")
    [ -n "$_eph" ] || { echo "FAILED: could not derive $partner-eph$i" >&2; exit 1; }
    _wid=$(wallet_on_chain "$_eph") || {
        echo "FAILED: could not reach the chain to ask about $_eph" >&2; exit 1; }
    if [ -n "$_wid" ]; then
        echo "--- $partner-eph$i already has a wallet on chain, skipping"
        continue
    fi
    echo "-------------------------"
    echo "$partner: create wallet eph$i"
    echo "-------------------------"
    qadenad_alias tx qadena create-wallet "$partner-eph$i" "$pioneer" "$sponsor" \
        --link-to-real-wallet "$partner" --account-mnemonic="$mnemonic" \
        --eph-account-index "$i" --yes
done

# ------------------------------------------------------------------------------------------
# 3. The registration request -- four plain-text fields, and no key.
# ------------------------------------------------------------------------------------------
request_file="$home/proposal_request.json"
jq -n --arg partner "$partner" --arg addr "$partner_addr" --arg pioneer "$pioneer" \
      --arg chain "${_now:-$chain_id}" \
   '{nodeID:$partner, pubKID:$addr, serviceProviderType:"identity",
     homePioneerID:$pioneer, chain_id:$chain}' > "$request_file"
chmod 600 "$request_file"

echo ""
echo "==================================================================="
echo "SEND THIS BLOCK TO THE FOUNDATION.  The heredoc pastes as-is;"
echo "the last line is theirs to fill in:"
echo "==================================================================="
echo ""
echo "cat > /tmp/$partner-request.json <<'REQUESTEOF'"
cat "$request_file"
echo "REQUESTEOF"
echo "foundation_scripts/ekycph_partner_after_step_2.sh \\"
echo "    --request /tmp/$partner-request.json${QADENA_NODE:+ --node $QADENA_NODE} \\"
echo "    --coord-home <the foundation's coordinator dir> --keyring-passfile <its passphrase file>"
echo ""
echo "==================================================================="
echo ""
echo "They submit the proposal, deposit and vote.  Once it reaches PASSED and eKYC PH has"
echo "issued the contact credentials, run step_3:"
echo "    ekycph_partner_scripts/step_3.sh $partner"
