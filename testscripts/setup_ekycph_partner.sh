#!/bin/zsh
#
# A whole eKYC PH PARTNER bring-up on a DEVNET, end to end -- all three roles on one box.
#
#   ./testscripts/setup_ekycph_partner.sh acme
#   ./testscripts/setup_ekycph_partner.sh acme -- --email ops@acme.ph --count 0
#
# WHAT THIS IS FOR.  A partner is a chain identity that the eKYC PH app server signs AS, and three
# parties touch its bring-up: the PARTNER (which holds the key), the FOUNDATION (which pays for
# every transaction and submits the registration proposal) and eKYC PH (which attests the
# partner's contact details).  On a launch chain those are three machines with three keyrings and
# the handovers are paste blocks.  THIS SCRIPT IS THE TEST HARNESS: it plays all three at once,
# holds every key in one keyring, and deposits and votes with `treasury` -- a key no launch chain
# has, which is why the real path is separate.  Same relationship setup_ekycph.sh has to
# foundation_scripts/ekycph_*.sh.
#
# THE REAL PATH, which this drives in order:
#
#   PARTNER     ekycph_partner_scripts/step_1.sh <name> --sponsor <addr>
#                   mints the mnemonic, derives every address offline, emits the pre-grant block
#   FOUNDATION  foundation_scripts/ekycph_partner_after_step_1.sh --pregrant <file>
#                   one narrow fee allowance per address, signed before anything exists
#   PARTNER     ekycph_partner_scripts/step_2.sh <name>
#                   creates the wallets, emits the registration request
#   FOUNDATION  foundation_scripts/ekycph_partner_after_step_2.sh --request <file>
#                   submits the proposal; the deposit comes from the foundation's balance
#   FOUNDATION  deposit + vote  (here: from treasury; on a fleet: ekycph_after_step_2.sh)
#   eKYC PH     ekycph_partner_scripts/ekycph_issue_credentials.sh <name>
#                   issues email and phone, signed by ekycphidentitysrvprv
#   PARTNER     ekycph_partner_scripts/step_3.sh <name>
#                   claims them, exports the armored key, prints the Add Partner form values
#
# PREREQUISITE: an ekycph deployment on this chain -- testscripts/setup_ekycph.sh.  It creates the
# foundation sponsor accounts this partner is funded by and the identity provider that attests it.
#
# Options:
#   --pioneer N            home pioneer                 (default: $QADENA_PIONEER or pioneer1)
#   --foundation-appsvr K  the devnet sponsor account   (default: foundation-appsvr)
#   --node RPC             chain RPC
#   --home DIR             the partner's state directory
#                          (default: $QADENA_LAUNCH_ROOT/ekycph_partners/<name>)
#   --                     everything after is passed through to step_1.sh (--email, --phone,
#                          --friendly-name, --logo, --rep-*, --count, --mnemonic, --find-a, ...)
#
# Re-running is safe: every step asks the CHAIN or the keyring what already exists.
#
# OUTPUT CONTAINS A PRIVATE KEY AND A MNEMONIC.  Everything under --home is 0600 and nothing in it
# belongs in git.

set -e

SCRIPT_DIR="${0:A:h}"
_HERE="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"
# EXPORT THE RESOLVED BACKEND. setup_env.sh reads it from client.toml (`file` on a current devnet)
# but does not export it, so a child defaulting it to `test` would look in an empty keyring.
export QADENA_KEYRING_BACKEND

# DEV STATE, KEPT APART FROM FLEET STATE.  EXPORTED, because every step below is a CHILD PROCESS
# that derives the partner home from this -- an unexported value would put the parent and the
# children in different directories, which is precisely the split that reported a successful
# step_1 as a failure in the ekycph harness.
export QADENA_LAUNCH_ROOT="${QADENA_LAUNCH_ROOT:-$HOME/qadena-dev-launch}"

pioneer="${QADENA_PIONEER:-pioneer1}"
# THE DEVNET SPONSOR, NOT THE PROFILE'S.  foundation_scripts/deployment_profile.sh names ekycph's
# production sponsor `foundation-ekycph-appsvr`; the devnet shares one `foundation-appsvr` across
# veritas/ekycph/enf, created by testscripts/setup_foundation_accounts.sh.  authz and feegrant are
# keyed on (granter, grantee), so sharing a granter does not collide.
foundation_appsvr="foundation-appsvr"
unset partner home
EXTRA=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer)           pioneer="$2"; shift 2 ;;
        --foundation-appsvr) foundation_appsvr="$2"; shift 2 ;;
        --node)              export QADENA_NODE="$2"; shift 2 ;;
        --home)              home="$2"; shift 2 ;;
        --)                  shift; EXTRA=("$@"); break ;;
        --help)
            awk 'NR<3{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
            exit 0 ;;
        --*) echo "Unknown option: $1  (step_1 options go after --)" >&2; exit 1 ;;
        *)   [ -z "${partner:-}" ] && partner="$1"; shift 1 ;;
    esac
done

[ -n "${partner:-}" ] || {
    echo "Usage: $0 <partner-name> [options] [-- step_1 options]   (--help for the full list)" >&2
    exit 1; }
: ${home:="$QADENA_LAUNCH_ROOT/ekycph_partners/$partner"}

# UNLOCK ONCE, HERE.  Every step below signs, and on a current devnet the keyring is the encrypted
# `file` backend.  Exported to the children by qadena_keyring_unlock, so none of them re-prompts.
# AFTER the argument loop, so --help never prompts.
qadena_keyring_unlock

# ---------------------------------------------------------------------------------------------
# PREREQUISITES.  Checked together, before anything is created, because each one failing midway
# leaves a partially-registered partner whose nodeID cannot be reused.
# ---------------------------------------------------------------------------------------------
_missing=0
for _k in treasury "$foundation_appsvr"; do
    # READ THE ERROR, DO NOT DISCARD IT.  A WRONG PASSPHRASE AND AN ABSENT KEY BOTH MAKE
    # `keys show` fail, and reporting both as "not in this keyring" tells an operator who simply
    # mistyped to go and re-run setup_ekycph.sh against a deployment that is already up.  The
    # backend distinguishes them plainly -- "incorrect passphrase" / "too many failed passphrase
    # attempts" against "decoding bech32 failed" -- so this reads what it said.
    if ! _err=$(qadenad_alias keys show "$_k" 2>&1 >/dev/null); then
        case "$_err" in
            *"incorrect passphrase"*|*"too many failed passphrase attempts"*)
                echo "WRONG KEYRING PASSPHRASE for $QADENAHOME." >&2
                echo "  The keys are there; what was typed does not open them.  Nothing has been" >&2
                echo "  created, on chain or on disk -- re-run and type it again." >&2
                exit 1 ;;
        esac
        echo "MISSING: key '$_k' is not in this keyring." >&2
        _missing=1
    fi
done
unset _err
if [ "$_missing" -ne 0 ]; then
    echo "" >&2
    echo "This harness plays the foundation too, so it needs the devnet's funding keys." >&2
    echo "Bring the deployment up first:  testscripts/setup_ekycph.sh" >&2
    exit 1
fi

sponsor_addr=$(qadenad_alias keys show "$foundation_appsvr" -a)
[ -n "$sponsor_addr" ] || { echo "FAILED: could not resolve $foundation_appsvr" >&2; exit 1; }

echo "============================================================"
echo "eKYC PH PARTNER (devnet, all three roles)"
echo "  partner            : $partner"
echo "  foundation sponsor : $foundation_appsvr ($sponsor_addr)"
echo "  pioneer            : $pioneer"
echo "  state directory    : $home"
echo "============================================================"

# ---------------------------------------------------------------------------------------------
echo ""
echo "### 1/7  PARTNER: keys and the pre-grant block"
# ---------------------------------------------------------------------------------------------
$ekycphpartnerscripts/step_1.sh "$partner" --sponsor "$sponsor_addr" \
    --pioneer "$pioneer" --home "$home" "${EXTRA[@]}"

_pregrant="$home/pregrant_addresses.json"
[ -r "$_pregrant" ] || { echo "FAILED: no $_pregrant -- step_1 did not complete" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
echo ""
echo "### 2/7  FOUNDATION: pre-grant every wallet"
# ---------------------------------------------------------------------------------------------
# --foundation-appsvr names the shared devnet account; --coord-home is left to default to the
# node's home, because on a devnet the "coordinator keyring" and the node keyring are one.
$qadenafoundationscripts/ekycph_partner_after_step_1.sh \
    --pregrant "$_pregrant" --foundation-appsvr "$foundation_appsvr"

# ---------------------------------------------------------------------------------------------
echo ""
echo "### 3/7  PARTNER: create the wallets"
# ---------------------------------------------------------------------------------------------
$ekycphpartnerscripts/step_2.sh "$partner" --home "$home"

_request="$home/proposal_request.json"
[ -r "$_request" ] || { echo "FAILED: no $_request -- step_2 did not complete" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
echo ""
echo "### 4/7  FOUNDATION: submit the registration proposal"
# ---------------------------------------------------------------------------------------------
# _registered NAME -- echoes the pubKID if NAME is already a registered service provider.
# THE CHAIN IS THE AUTHORITY, not the .proposal_id file: that file is overwritten every run and
# says nothing about registration.  A second proposal for an existing nodeID passes its vote and
# then fails on EXECUTION, which reads as a governance problem rather than "already done".
_registered() {
    qadenad_alias query qadena list-interval-public-key-id --output json 2>/dev/null \
        | sed -n '/^{/,$p' \
        | jq -r --arg n "$1" '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID' 2>/dev/null | head -1
}

if [ -n "$(_registered "$partner")" ]; then
    echo "--- $partner is already a registered service provider, skipping the proposal"
else
    $qadenafoundationscripts/ekycph_partner_after_step_2.sh \
        --request "$_request" --foundation-appsvr "$foundation_appsvr"

    _pid_file="$qadenaproviderscripts/proposals/$partner.proposal_id"
    [ -s "$_pid_file" ] || { echo "FAILED: no proposal id at $_pid_file" >&2; exit 1; }
    _pid=$(head -1 "$_pid_file")

    # -----------------------------------------------------------------------------------------
    echo ""
    echo "### 5/7  FOUNDATION: deposit and vote on proposal $_pid"
    # -----------------------------------------------------------------------------------------
    # ON A FLEET THIS IS A MULTISIG CEREMONY -- foundation_scripts/ekycph_after_step_2.sh, from the
    # `foundation` bucket, which is the only bucket holding both the liquid tokens the deposit
    # needs and the bonded ones the vote needs.  On a devnet `treasury` holds both.
    $qadenatestscripts/gov_deposit_from_treasury.sh "$_pid" 10000000qdn
    $qadenatestscripts/gov_vote_from_treasury.sh "$_pid" yes
    $qadenaproviderscripts/query_service_provider_proposal.sh "$_pid" --wait

    # TRUST THE CHAIN, NOT THE EXIT STATUS: the proposal passing and the registration landing are
    # two different things, and a partner row built on an unregistered nodeID fails later with
    # ErrServiceProviderUnauthorized, far from here.
    if [ -z "$(_registered "$partner")" ]; then
        echo "FAILED: proposal $_pid completed but $partner is not in list-interval-public-key-id" >&2
        exit 1
    fi
fi
echo "    registered: $(_registered "$partner")"

# ---------------------------------------------------------------------------------------------
echo ""
echo "### 6/7  eKYC PH: issue the contact credentials"
# ---------------------------------------------------------------------------------------------
$ekycphpartnerscripts/ekycph_issue_credentials.sh "$partner" --variables "$home/variables.json"

# ---------------------------------------------------------------------------------------------
echo ""
echo "### 7/7  PARTNER: claim, export, and print the form values"
# ---------------------------------------------------------------------------------------------
$ekycphpartnerscripts/step_3.sh "$partner" --home "$home"
