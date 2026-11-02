#!/bin/zsh
#
# FOUNDATION SIDE.  Submit the partner's MsgAddServiceProvider proposal, after their step_2.
#
#   foundation_scripts/ekycph_partner_after_step_2.sh --request <file> [options]
#
# WHY THE FOUNDATION SUBMITS AND NOT THE PARTNER.  The chain demands a MINIMUM INITIAL DEPOSIT
# from the PROPOSER -- real tokens, which no fee grant can carry.  SEC solves this by holding
# delegated authz to submit AS the foundation; a third-party partner is not given that, so the
# foundation simply submits on its behalf.  It can, because a service-provider proposal is four
# plain-text fields and `pubKID` IS the partner's bech32 address: no key of the partner's is
# needed here, and none is present.
#
# THIS SCRIPT ONLY SUBMITS.  Reaching the expedited threshold and voting needs liquid AND bonded
# tokens from the `foundation` bucket, which is a multisig ceremony -- the one
# foundation_scripts/ekycph_after_step_2.sh already implements.  The command to run is printed at
# the end with the proposal id filled in.
#
# Options:
#   --request <file>         the block the partner's step_2 printed: nodeID, pubKID,
#                            serviceProviderType, homePioneerID, chain_id.
#   --foundation-appsvr <k>  the proposing account, whose balance pays the initial deposit
#                            (default: ekycph's, from the profile)
#   --coord-home <dir>       keyring holding that account
#   --node <rpc>             the chain RPC; the chain-id is derived from it
#   --keyring-backend <b>    default file (encrypted); 'test' for a devnet keyring
#   --keyring-passfile <f>   read the keyring passphrase from a file

set -e

HERE="${0:A:h}"
PROG="${QADENA_PROG:-ekycph_partner_after_step_2.sh}"

_kb_caller="${QADENA_KEYRING_BACKEND:-}"

SCRIPT_DIR="$HERE"
source "$HERE/../scripts/setup_env.sh"

source "$HERE/deployment_profile.sh"
deployment_profile_load "ekycph" || exit 1

REQUEST=""
COORD_HOME=""
BACKEND="${_kb_caller:-file}"
KEYRING_PASSFILE=""
foundation_appsvr="$DEPLOY_APPSVR"
NODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --request)           REQUEST="$2"; shift 2 ;;
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

[ -n "$REQUEST" ] || {
    echo "--request <file> is required: the block the partner's step_2 printed." >&2
    exit 1; }
[ -r "$REQUEST" ] || { echo "cannot read $REQUEST" >&2; exit 1; }
jq -e . "$REQUEST" >/dev/null 2>&1 || { echo "$REQUEST is not valid JSON" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
# VALIDATE THE REQUEST, BEFORE ASKING FOR A PASSPHRASE.  Every field below goes into a
# GOVERNANCE PROPOSAL, and AddServiceProvider refuses an existing nodeID
# (ErrServiceProviderAlreadyExists) while deactivate overwrites rather than deletes -- so a wrong
# value here burns the name with the wrong value baked in.  Nothing rejects it at proposal time.
# ---------------------------------------------------------------------------------------------
nodeid=$(jq -r '.nodeID // empty' "$REQUEST")
pubkid=$(jq -r '.pubKID // empty' "$REQUEST")
sptype=$(jq -r '.serviceProviderType // empty' "$REQUEST")
pioneer=$(jq -r '.homePioneerID // empty' "$REQUEST")
_rchain=$(jq -r '.chain_id // ""' "$REQUEST")

# THE JSON FIELD NAME, NOT THE SHELL VARIABLE'S.  The operator is looking at the file, not at
# this script, and "has no pubkid" does not grep against a block that says "pubKID".
for _pair in nodeid:nodeID pubkid:pubKID sptype:serviceProviderType pioneer:homePioneerID; do
    [ -n "${(P)${_pair%%:*}}" ] \
        || { echo "REFUSING: $REQUEST has no ${_pair#*:}" >&2; exit 1; }
done
case "$pubkid" in
    qadena1*) ;;
    *) echo "REFUSING: pubKID '$pubkid' is not a qadena address" >&2; exit 1 ;;
esac

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
NODE_HOME="${QADENAHOME:-$HOME/qadena}"
NODE="${NODE:-${QADENA_NODE:-tcp://localhost:26657}}"
[ -n "$COORD_HOME" ] || COORD_HOME="$NODE_HOME"

KRPASS=""
if [ "$BACKEND" = "file" ]; then
    if [ -n "$KEYRING_PASSFILE" ]; then
        KRPASS=$(head -1 "$KEYRING_PASSFILE")
    elif [ -n "${QADENA_KEYRING_PASS:-}" ]; then
        KRPASS="$QADENA_KEYRING_PASS"
    else
        printf "Coordinator keyring passphrase (%s, hidden): " "$COORD_HOME" >&2
        read -s KRPASS; echo "" >&2
    fi
fi

qk() {
    if [ -n "$KRPASS" ]; then
        { printf '%s\n' "$KRPASS"; printf '%s\n' "$KRPASS"; } \
            | "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    else
        "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    fi
}
qq() { "$QBIN" --home "$NODE_HOME" "$@" --node "$NODE"; }

CHAIN="${QADENA_CHAIN_ID:-$(qq status 2>/dev/null | sed -n '/^{/,$p' | jq -r '.node_info.network // empty')}"
[ -n "$CHAIN" ] || { echo "cannot determine the chain-id; set QADENA_CHAIN_ID" >&2; exit 1; }

# THE CHAIN THE REQUEST WAS BUILT FOR.
if [ -n "$_rchain" ] && [ "$_rchain" != "$CHAIN" ]; then
    echo "REFUSING: $REQUEST was generated on chain '$_rchain', this node is '$CHAIN'." >&2
    exit 1
fi

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
    echo "  Pass --coord-home <dir>, the same --home you gave derive_launch_keys.sh." >&2
    exit 1; }
unset _kout


# THE PIONEER MUST EXIST.  A wrong one does not fail at proposal time: the registration passes
# governance and looks healthy for the life of the chain, then fails somewhere else entirely --
# sign-recover-key resolves the provider's home pioneer to sign a recovery share,
# GetIntervalPublicKey misses, and the operator sees `key not found` naming neither the provider
# nor the pioneer.  And it is UNRECOVERABLE.  The partner typed this; check it here.
_ipk=$(qq query qadena list-interval-public-key-id --output json 2>/dev/null | sed -n '/^{/,$p')
if ! print -r -- "$_ipk" | jq -e --arg n "$pioneer" \
        '(.intervalPublicKeyID // [])[] | select(.nodeID==$n)' >/dev/null 2>&1; then
    echo "REFUSING: '$pioneer' is not a registered node on $CHAIN." >&2
    echo "  A proposal naming a pioneer that does not exist passes governance and strands" >&2
    echo "  the provider's key recovery, permanently.  Ask the partner to re-run step_1" >&2
    echo "  with the right --pioneer." >&2
    exit 1
fi

# ALREADY REGISTERED?  A second add_service_provider_proposal for an existing nodeID passes its
# vote and fails on EXECUTION, which reads as a governance problem rather than "it was already
# done".  The chain is the authority here, not any local file.
if print -r -- "$_ipk" | jq -e --arg n "$nodeid" \
        '(.intervalPublicKeyID // [])[] | select(.nodeID==$n)' >/dev/null 2>&1; then
    echo "$nodeid is ALREADY a registered service provider on $CHAIN -- nothing to submit."
    echo "Tell the partner to continue:  ekycph_partner_scripts/step_3.sh $nodeid"
    exit 0
fi

echo "==================================================================="
echo "FOUNDATION: submitting the registration proposal"
echo "  nodeID    : $nodeid"
echo "  pubKID    : $pubkid"
echo "  type      : $sptype"
echo "  pioneer   : $pioneer"
echo "  proposer  : $foundation_appsvr ($fa_addr)"
echo "  chain     : $CHAIN"
echo "==================================================================="

# BUILT FROM THE SAME TEMPLATE provider_scripts/submit_service_provider_proposal.sh USES, with the
# same three substitutions -- but not by calling that script.  It resolves the provider address
# with `keys show` out of the NODE's keyring, which by design does not hold a partner's key, and
# it signs from a keyring this script does not use.  The substitutions are three jq assignments;
# the keyring plumbing is not.
_tmpl="$qadenaproviderscripts/templates/add_service_provider_proposal.json"
[ -r "$_tmpl" ] || { echo "no template at $_tmpl" >&2; exit 1; }

_work="${TMPDIR:-/tmp}/ekycph-partner-$nodeid.gen.json"
jq --arg nodeid "$nodeid" --arg pubkid "$pubkid" --arg sptype "$sptype" --arg pioneer "$pioneer" \
   '.messages[0].nodeID = $nodeid
    | .messages[0].pubKID = $pubkid
    | .messages[0].serviceProviderType = $sptype
    | .messages[0].homePioneerID = $pioneer' "$_tmpl" > "$_work"
chmod 600 "$_work"

echo ""
echo "--- proposal:"
jq -r '.messages[0] | "    \(.nodeID)  \(.serviceProviderType)  pioneer=\(.homePioneerID)  pubKID=\(.pubKID)"' "$_work"
echo "--- initial deposit: $(jq -r '.deposit' "$_work")  (paid by $foundation_appsvr)"
echo ""

gasflags=(--gas-prices "$minimum_gas_prices" --gas "$gas_auto" --gas-adjustment "$gas_adjustment")
out=$(qk tx gov submit-proposal "$_work" --from "$foundation_appsvr" --node "$NODE" \
        --chain-id "$CHAIN" --yes --output json "${gasflags[@]}" 2>&1) \
    || { echo "FAILED: submit-proposal did not broadcast: $(echo "$out" | tail -1)" >&2; exit 1; }
hash=$(echo "$out" | grep '^{' | tail -1 | jq -r '.txhash // ""' 2>/dev/null)
[ -n "$hash" ] || { echo "FAILED: submit-proposal produced no txhash" >&2; exit 1; }

qq query wait-tx "$hash" --timeout 60s >/dev/null 2>&1 || true
code=$(qq query tx "$hash" --output json 2>/dev/null | jq -r '.code // "?"')
[ "$code" = "0" ] || { echo "FAILED: submit-proposal on chain (code $code), tx $hash" >&2; exit 1; }

proposal_id=$(qq query tx "$hash" --output json 2>/dev/null \
    | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value' \
    | head -1)
[ -n "$proposal_id" ] || {
    echo "FAILED: the tx succeeded ($hash) but carried no proposal_id event." >&2; exit 1; }

echo "  ok: submitted.  tx $hash"

# WHERE EVERY OTHER PROPOSAL ID IN THIS REPO LANDS.  provider_scripts/submit_service_provider_proposal.sh
# writes <name>.proposal_id here and setup_ekycph.sh reads it back; the devnet harness reads this
# one the same way, so the two paths do not need different plumbing.  It is a CACHE, not the
# authority: the file is overwritten every run and says nothing about whether the registration
# landed, which is why every consumer checks list-interval-public-key-id instead.
mkdir -p "$qadenaproviderscripts/proposals"
print -r -- "$proposal_id" > "$qadenaproviderscripts/proposals/$nodeid.proposal_id"

echo ""
echo "==================================================================="
echo "PROPOSAL ID: $proposal_id"
echo "==================================================================="
echo ""
echo "Deposit and vote -- a foundation-bucket ceremony, the same one the deployment uses:"
echo ""
echo "    foundation_scripts/ekycph_after_step_2.sh $proposal_id \\"
echo "        --coord-home $COORD_HOME --members foundation-m1,foundation-m2,foundation-m3"
echo ""
echo "Then watch it to PASSED:"
echo "    provider_scripts/query_service_provider_proposal.sh $proposal_id --wait${QADENA_NODE:+ --node $QADENA_NODE}"
echo ""
echo "Once it passes, eKYC PH issues the contact credentials and the partner runs step_3."
echo "==================================================================="
