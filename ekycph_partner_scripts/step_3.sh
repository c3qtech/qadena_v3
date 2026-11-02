#!/bin/zsh
#
# PARTNER SIDE, step 3 of 3.  Claim the credentials eKYC PH issued, export the armored key, and
# print the four values the "Add Partner" form wants.
#
#   ekycph_partner_scripts/step_3.sh <partner-name> [--home DIR] [--node RPC]
#
# RUN THIS AFTER the registration proposal has PASSED and eKYC PH has run
# ekycph_partner_scripts/ekycph_issue_credentials.sh.  Both are checked below rather than
# assumed: a claim against a credential that was never issued fails with a message about the
# credential, not about the missing step.
#
# THIS IS THE STEP WHERE A KEY CROSSES THE LINE, and it is worth being explicit about.  Everything
# before it was arranged so that no foundation key reached the partner's machine.  But
# RegisterKYCPartner imports an armored private key and the app server then signs AS the partner
# (helpers.FindPartner -> PrepareIdentityServiceProviderClientContextForPartner), so the
# partner's own signing key necessarily goes to eKYC PH.  No ceremony changes that; what the split
# buys is that the partner generated the key itself, the foundation never held it, and the handover
# is one file at one moment rather than a standing arrangement.

set -e

SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"
export QADENA_KEYRING_BACKEND
export QADENA_LAUNCH_ROOT="${QADENA_LAUNCH_ROOT:-$HOME/qadena-dev-launch}"

unset partner home armor_pass
while [[ $# -gt 0 ]]; do
    case "$1" in
        --home)             home="$2"; shift 2 ;;
        --node)             export QADENA_NODE="$2"; shift 2 ;;
        --armor-passphrase) armor_pass="$2"; shift 2 ;;
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
[ -r "$_vars" ] || { echo "no $_vars -- step_1 has not run for '$partner'." >&2; exit 1; }

friendly_name=$(jq -r '.friendly_name' "$_vars")
logo=$(jq -r '.logo' "$_vars")
find_a=$(jq -r '.find_a' "$_vars")
find_bf=$(jq -r '.find_bf' "$_vars")
rep_first=$(jq -r '.rep.first // ""' "$_vars")
rep_last=$(jq -r '.rep.last // ""' "$_vars")

qadena_keyring_unlock

# _registered NAME -- echoes the pubKID if NAME is a registered service provider.
# THE CHAIN IS THE AUTHORITY, not a .proposal_id file: that file is overwritten every run and
# says nothing about whether the registration landed.
_registered() {
    qadenad_alias query qadena list-interval-public-key-id --output json 2>/dev/null \
        | sed -n '/^{/,$p' \
        | jq -r --arg n "$1" '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID' 2>/dev/null | head -1
}

reg=$(_registered "$partner")
if [ -z "$reg" ]; then
    echo "FAILED: $partner is not in list-interval-public-key-id." >&2
    echo "        The foundation's proposal has not passed (or was never submitted)." >&2
    echo "        Watch it:  provider_scripts/query_service_provider_proposal.sh <id> --wait" >&2
    echo "" >&2
    echo "        STOPPING RATHER THAN CONTINUING.  An unregistered partner can still be" >&2
    echo "        added to the dashboard and still reads credentials -- the write path is" >&2
    echo "        what fails, and it fails in DeliverTx with the fee taken, long after the" >&2
    echo "        API has returned 200.  Better to be blocked here." >&2
    exit 1
fi
echo "registered as           : $reg"

# ------------------------------------------------------------------------------------------
# 1. Claim the credentials.  A REPEAT IS NOT A FAILURE: re-running is the normal way to finish an
#    interrupted bring-up, and the chain answers a duplicate with an error that would abort the
#    script under `set -e` after the expensive half already succeeded.
# ------------------------------------------------------------------------------------------
_claim() {
    local ctype="$1"
    echo "-------------------------"
    echo "$partner: claim $ctype"
    echo "-------------------------"
    if ! qadenad_alias tx qadena claim-credential "$find_a" "$find_bf" "$ctype" \
            --from "$partner" --yes; then
        echo "    NOTE: claim-credential $ctype did not succeed -- already claimed? continuing." >&2
    fi
}

_claim email-contact-info
_claim phone-contact-info
if [ -n "$rep_first" ] && [ -n "$rep_last" ]; then
    _claim personal-info
else
    echo "--- no personal-info to claim: step_1 was given no --rep-first-name / --rep-last-name."
fi

# ------------------------------------------------------------------------------------------
# 2. Export the armored key -- the thing the Add Partner form actually consumes.
# ------------------------------------------------------------------------------------------
# THE ARMOR PASSPHRASE IS THE KEYRING PASSPHRASE UNDER THE `file` BACKEND, and nothing can change
# that from here.  qadenad_alias supplies its OWN stdin -- $QADENA_KEYRING_PASS, repeated for as
# many prompts as the command asks for -- so the armor prompt is answered with it too and any
# --armor-passphrase would be silently ignored.  extract_ephem_keys.sh learned this the hard way:
# the app server imports with ARMOR_PASS_PHRASE and dies at startup on a mismatch, reporting
# "Failed to import private key" with an EMPTY reason.
#
# Under the `test` backend there is no keyring passphrase and the wrapper feeds nothing, so the
# armor prompt would reach the terminal -- invisible here, because the output is captured.  That
# branch supplies the passphrase itself through the raw wrapper.
if [ -n "${QADENA_KEYRING_PASS:-}" ]; then
    if [ -n "${armor_pass:-}" ] && [ "$armor_pass" != "$QADENA_KEYRING_PASS" ]; then
        echo "NOTE: --armor-passphrase is ignored under the '$QADENA_KEYRING_BACKEND' backend;" >&2
        echo "      the export is encrypted with the keyring passphrase.  Using that instead." >&2
    fi
    armor_pass="$QADENA_KEYRING_PASS"
    armor_key=$(qadenad_alias keys export "$partner")
else
    : ${armor_pass:="dev-armor-passphrase"}
    armor_key=$({ repeat 8 print -r -- "$armor_pass" } 2>/dev/null \
                  | qadenad_alias_raw keys export "$partner")
fi

[ -n "$armor_key" ] || { echo "FAILED: could not export the armored private key for $partner" >&2; exit 1; }

umask 077
print -r -- "$armor_key" > "$home/$partner.armor"
chmod 600 "$home/$partner.armor"

# The exact POST body for /partner/register-ekyc-partner, so the registration can be driven by
# curl as well as by the form.  jq builds it, because the armored key is multi-line and
# hand-rolled JSON would have to escape it.
jq -n --arg fn "$friendly_name" --arg n "$partner" --arg k "$armor_key" \
      --arg p "$armor_pass" --arg l "$logo" \
   '{friendly_name:$fn, name:$n, armor_priv_key:$k, armor_pass_phrase:$p, logo:$l}' \
   > "$home/partner.json"
chmod 600 "$home/partner.json"

echo ""
echo "============================================================"
echo "ADD PARTNER -- paste these into the partner dashboard's form"
echo "============================================================"
echo ""
echo "Friendly Name : $friendly_name"
echo "Name          : $partner"
echo "Passphrase    : $armor_pass"
echo "Logo URL      : $logo"
echo "Armored Private Key:"
echo ""
print -r -- "$armor_key"
echo ""
echo "------------------------------------------------------------"
echo "registered as  : $reg"
echo ""
echo "files (0600, do not commit):"
echo "  $home/partner.json          POST body for /partner/register-ekyc-partner"
echo "  $home/$partner.armor        the armored key on its own"
echo "  $home/$partner.mnemonic     the ONLY way to recover this wallet"
echo ""
echo "AFTER REGISTERING: the partner row is created with active=0."
echo "RegisterKYCPartner hardcodes it (handlers/user_partner.go), and only an eKYC PH"
echo "admin -- models.IsEKYCPhAdmin, not a partner admin -- can flip it via"
echo "SetPartnerActivation.  Until then the row exists and the partner does nothing."
echo ""
echo "or register it directly:"
echo "  curl -X POST \$API/v1/partner/register-ekyc-partner \\"
echo "       -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TOKEN\" \\"
echo "       -d @$home/partner.json"
echo "============================================================"
