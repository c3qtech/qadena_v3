#!/bin/zsh
#
# eKYC PH SIDE.  Issue the partner's contact credentials, between the partner's step_2 and step_3.
#
#   ekycph_partner_scripts/ekycph_issue_credentials.sh <partner-name> [options]
#
# RUN BY eKYC PH, NOT BY THE PARTNER AND NOT BY THE FOUNDATION.  It signs with
# ekycphidentitysrvprv -- the deployment's identity provider -- which is the whole point: the
# partner's email and phone are ATTESTED BY eKYC PH, the way secdsvs's are attested in
# testscripts/setup_credentials.sh.
#
# WHY NOT SELF-ISSUED.  Once the proposal passes, the partner is itself an `identity` service
# provider and MsgCreateCredential would accept it as msg.Creator -- it could issue its own
# contact credentials.  Structurally that works and means nothing: a self-asserted contact
# credential attests only that the partner typed its own address.  Keeping issuance here is a
# product decision, not a chain constraint.
#
# create/claim is a PAIR.  This script only creates; the partner claims in step_3.  Both sides use
# the same find-credential Pedersen pair, which is why it travels in variables.json rather than
# being chosen twice.
#
# Options:
#   --variables FILE     the partner's variables.json, which step_1 wrote.  Carries the find pair,
#                        the email and the phone.  Default:
#                        $QADENA_LAUNCH_ROOT/ekycph_partners/<name>/variables.json
#   --find-a N / --find-bf N / --email A / --phone N   override individually, when eKYC PH has
#                        the values but not the file (the real two-party case).
#   --rep-first-name S / --rep-middle-name S / --rep-last-name S / --rep-birthdate S
#   --rep-citizenship S / --rep-residency S / --rep-gender S
#                        a personal-info credential for the partner's authorized representative.
#                        OPT-IN, here as in step_1: issued only when first and last are both
#                        present, because personal-info describes a PERSON and inventing one puts
#                        fabricated identity data on an immutable chain.
#   --identity-provider N  who signs (default: the ekycph profile's identity provider)
#   --node RPC

set -e

SCRIPT_DIR="${0:A:h}"
_HERE="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"
export QADENA_KEYRING_BACKEND
export QADENA_LAUNCH_ROOT="${QADENA_LAUNCH_ROOT:-$HOME/qadena-dev-launch}"

# THE DEPLOYMENT PROFILE, sourced AFTER setup_env.sh -- which clobbers SCRIPT_DIR, so the path is
# re-derived from $0 rather than trusting the variable to still point here.  It is the one place
# that knows ekycph's identity provider is `ekycphidentitysrvprv`; a literal here would be a
# second source of truth for the same fact.
source "$_HERE/../foundation_scripts/deployment_profile.sh"
deployment_profile_load "ekycph" || exit 1

unset partner variables find_a find_bf email phone identityprovider
unset rep_first rep_middle rep_last rep_birthdate rep_citizenship rep_residency rep_gender

while [[ $# -gt 0 ]]; do
    case "$1" in
        --variables)          variables="$2"; shift 2 ;;
        --find-a)             find_a="$2"; shift 2 ;;
        --find-bf)            find_bf="$2"; shift 2 ;;
        --email)              email="$2"; shift 2 ;;
        --phone)              phone="$2"; shift 2 ;;
        --rep-first-name)     rep_first="$2"; shift 2 ;;
        --rep-middle-name)    rep_middle="$2"; shift 2 ;;
        --rep-last-name)      rep_last="$2"; shift 2 ;;
        --rep-birthdate)      rep_birthdate="$2"; shift 2 ;;
        --rep-citizenship)    rep_citizenship="$2"; shift 2 ;;
        --rep-residency)      rep_residency="$2"; shift 2 ;;
        --rep-gender)         rep_gender="$2"; shift 2 ;;
        --identity-provider)  identityprovider="$2"; shift 2 ;;
        --node)               export QADENA_NODE="$2"; shift 2 ;;
        --help)
            awk 'NR<3{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
            exit 0
            ;;
        --*) echo "Unknown option: $1" >&2; exit 1 ;;
        *)   [ -z "${partner:-}" ] && partner="$1"; shift 1 ;;
    esac
done

[ -n "${partner:-}" ] || { echo "Usage: $0 <partner-name> [options]   (--help for the full list)" >&2; exit 1; }
: ${identityprovider:="$DEPLOY_IDENTITY_PRV"}
: ${variables:="$QADENA_LAUNCH_ROOT/ekycph_partners/$partner/variables.json"}

# THE FILE FILLS ONLY WHAT THE FLAGS DID NOT.  A flag is the operator speaking now; the file is
# what step_1 recorded.  Where both exist the flag wins, so a correction does not need the file
# edited -- but a value present in neither is a hard error below rather than an empty string in a
# credential nobody can claim.
if [ -r "$variables" ]; then
    : ${find_a:="$(jq -r '.find_a // empty' "$variables")"}
    : ${find_bf:="$(jq -r '.find_bf // empty' "$variables")"}
    : ${email:="$(jq -r '.email // empty' "$variables")"}
    : ${phone:="$(jq -r '.phone // empty' "$variables")"}
    : ${rep_first:="$(jq -r '.rep.first // empty' "$variables")"}
    : ${rep_middle:="$(jq -r '.rep.middle // empty' "$variables")"}
    : ${rep_last:="$(jq -r '.rep.last // empty' "$variables")"}
    : ${rep_birthdate:="$(jq -r '.rep.birthdate // empty' "$variables")"}
    : ${rep_citizenship:="$(jq -r '.rep.citizenship // empty' "$variables")"}
    : ${rep_residency:="$(jq -r '.rep.residency // empty' "$variables")"}
    : ${rep_gender:="$(jq -r '.rep.gender // empty' "$variables")"}
fi

for _req in find_a find_bf email phone; do
    if [ -z "${(P)_req:-}" ]; then
        echo "FAILED: no $_req.  Pass --$(print -r -- "$_req" | tr '_' '-'), or point --variables at" >&2
        echo "        the partner's variables.json (tried $variables)." >&2
        exit 1
    fi
done

# WHICH KEYRING HOLDS THE ISSUER.  A deployment's keys are NOT in the node keyring on a devnet:
# veritas_scripts/step_1.sh writes ekycphidentitysrvprv into $DEPLOY_SEC_HOME/keyring -- one
# directory over -- so a plain qadenad_alias here reported "not in this keyring" with the key
# sitting right there.  scripts/deployment_keyring.sh already decides this for enf_cli.sh and
# epdc_cli.sh, and it decides from the keyring FILES rather than by asking qadenad, so it can run
# BEFORE the unlock and the passphrase prompt can name the keyring it is really for.
source "$qadenascripts/deployment_keyring.sh"
deployment_keyring_select "ekycph" "$identityprovider" "$identityprovider"

qadena_keyring_unlock

# A WRONG PASSPHRASE IS NOT A MISSING KEY, and here the two are especially easy to confuse: the
# deployment keyring selected above may not share the node keyring's passphrase, so the caller's
# exported QADENA_KEYRING_PASS can be right for one and wrong for the other.
if ! _err=$(qadenad_alias keys show "$identityprovider" 2>&1 >/dev/null); then
    case "$_err" in
        *"incorrect passphrase"*|*"too many failed passphrase attempts"*)
            echo "WRONG PASSPHRASE for ${QADENA_KEYRING_DIR:-$QADENAHOME}." >&2
            echo "        '$identityprovider' is there; what was supplied does not open it." >&2
            echo "        A deployment keyring need not share the node keyring's passphrase." >&2
            exit 1 ;;
    esac
    echo "FAILED: $identityprovider is not in ${QADENA_KEYRING_DIR:-$QADENAHOME}." >&2
    echo "        This step runs on the eKYC PH machine, which holds the identity provider." >&2
    exit 1
fi
unset _err

echo "============================================================"
echo "eKYC PH issues credentials for : $partner"
echo "issuer                         : $identityprovider"
echo "find-credential pair           : $find_a / $find_bf"
echo "============================================================"

# A REPEAT IS NOT A FAILURE.  Re-running is the normal way to finish an interrupted bring-up, and
# the chain answers a duplicate with an error; under `set -e` that would abort the run.
_credential() {
    local ctype="$1"; shift
    echo "-------------------------"
    echo "$partner: create $ctype"
    echo "-------------------------"
    if ! qadenad_alias tx qadena create-credential "$find_a" "$find_bf" "$ctype" "$@" \
            --from "$identityprovider" --yes; then
        echo "    NOTE: create-credential $ctype did not succeed -- already issued? continuing." >&2
    fi
}

_credential email-contact-info "$email"
_credential phone-contact-info "$phone"

if [ -n "${rep_first:-}" ] && [ -n "${rep_last:-}" ]; then
    _credential personal-info "$rep_first" "${rep_middle:-}" "$rep_last" \
        "${rep_birthdate:-2000-Jan-01}" "${rep_citizenship:-ph}" "${rep_residency:-ph}" \
        "${rep_gender:-M}"
else
    echo "--- no personal-info credential: no representative given."
    echo "    This matches secdsvs, the institution in setup_credentials.sh, which holds"
    echo "    contact credentials only."
fi

echo ""
echo "Issued.  The partner claims them:"
echo "    ekycph_partner_scripts/step_3.sh $partner"
