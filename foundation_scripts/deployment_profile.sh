#!/bin/zsh
#
# THE DEPLOYMENT PROFILE -- one place that answers "what is this deployment called, in every
# namespace it appears in".
#
#   source foundation_scripts/deployment_profile.sh          # uses $DEPLOYMENT, default veritas
#   foundation_scripts/deployment_profile.sh --show ekycph   # print one, for eyeballing
#   foundation_scripts/deployment_profile.sh --list
#
# WHY THIS EXISTS.  The foundation sponsors more than one programme out of the same bucket, and
# the keyring has no namespaces -- a name is unique per keyring and nothing warns on reuse.  Every
# name a deployment owns has to vary together: an --appsvr resolving to another programme's key
# funds the wrong programme, and a pool file left from an earlier run verifies green against a pool
# that was never created.  Both succeed without an error, so the mapping lives here rather than in
# a flag each caller has to remember.
#
# ADDING A DEPLOYMENT.  Either add a case below, or -- without touching this file -- drop
# <name>.env into $QADENA_DEPLOYMENT_DIR (default ~/launch/deployments) setting any DEPLOY_* var.
# The file is sourced AFTER the built-in case, so it overrides rather than replaces, and a
# deployment that is merely a rename of another needs two lines.
#
# NOT HERE: mnemonics, addresses, amounts.  This maps names to names.  An address belongs to a
# chain and a mnemonic belongs in a sealed file.

# ---------------------------------------------------------------------------------------------
# THE PROFILE
# ---------------------------------------------------------------------------------------------
# DEPLOY_NAME           the short name; every artefact filename is built from it
# DEPLOY_DISPLAY        how the deployment is NAMED IN PROSE -- the operator the run is talking
#                       about ("SEC", "ekyc.ph", "Qadena ENF").  The scripts were written for one
#                       deployment and say "SEC" throughout; every one of those is really "whoever
#                       runs the non-foundation half", so it varies with the profile.  Not a key
#                       name and never used to resolve anything -- output only.
# DEPLOY_APPSVR         foundation key funding the deployment's OWN operational wallets
# DEPLOY_USERS          foundation key funding CITIZEN wallets (granted at runtime via authz)
# DEPLOY_ADMIN          the deployment's admin key -- receives the authz delegation in after_step_1
# DEPLOY_SPONSOR_BASE   the create-wallet sponsor; step_3's pool is <base>-0, <base>-1, ...
# DEPLOY_TREASURY       the (banksend-mode only) treasury key
# DEPLOY_IDENTITY_PRV   identity service provider key name
# DEPLOY_DSVS_PRV       DSVS service provider key name
# DEPLOY_DSVS           DSVS signer key name
# DEPLOY_SEC_HOME       where variables.json / mnemonics / pool_addresses.json live
# DEPLOY_FUND_BUCKET    allocations.csv bucket that funds the two sponsor accounts
# DEPLOY_STAKE_BUCKET   allocations.csv bucket that provides voting power
#
# THE DEPLOYMENT'S OWN IDENTITY.  step_3 mints a personal-info, a phone-contact-info and an
# email-contact-info credential for the create-wallet sponsor and for the DSVS signer, and the
# chain keys a credential on (CredentialID, CredentialType) -- where CredentialID is a hash of the
# very fields below (msg_server_create_credential.go:49).  Two deployments sharing them therefore
# hash to ONE id, and the second one to run dies with `code 1115: Credential already exists`.
# These MUST differ per deployment for deployments that share a chain.
# DEPLOY_FIRSTNAME      personal-info first name
# DEPLOY_BIRTHDATE      personal-info birthdate
# DEPLOY_EMAIL          email-contact-info credential
# DEPLOY_PHONE          phone-contact-info credential
# DEPLOY_AVALUE         commitment amount; step_3 uses avalue for the sponsor and avalue+1 for DSVS
#
# Derived, so they cannot drift apart from DEPLOY_NAME:
# DEPLOY_STATE_FILE     <coord>/<name>-sponsors.json   written by before_step_1 --stage prepare
# DEPLOY_PREGRANT_FILE  <coord>/<name>-pregrant.json   retained by after_step_1
# DEPLOY_POOL_FILE      <coord>/<name>-pool.json       retained by after_step_3

_dp_usage() {
    print -r -- "Usage: deployment_profile.sh [--show <name>] [--list]"
    print -r -- ""
    print -r -- "  Sourced by the foundation scripts; \$DEPLOYMENT selects the profile."
    print -r -- "  --show <name>   print one profile as shell assignments"
    print -r -- "  --list          list the known deployment names"
}

deployment_profile_load() {
    local _d="${1:-${DEPLOYMENT:-veritas}}"

    DEPLOY_NAME="$_d"
    DEPLOY_DISPLAY=""

    # THE APPSVR FEE-GRANT ALLOW-LIST.  An AllowedMsgAllowance pays gas ONLY for the message types
    # named in it, and the chain rejects the WHOLE tx when one is missing -- so a type absent here
    # is not a degraded feature, it is a deployment that comes up looking healthy and fails on
    # first use.  Lived as a literal in BOTH veritas_scripts/step_3.sh and
    # provider_scripts/setup_provider_base.sh, with sec_veritas_verify.sh grepping only the first
    # of the two for the set it enforces -- so the two copies could drift and the verifier would
    # still pass.  One copy now; the extras below are what actually varies.
    DEPLOY_APPSVR_MSGS="/qadena.dsvs.MsgCreateDocument,/qadena.dsvs.MsgRemoveDocument,/qadena.dsvs.MsgSignDocument,/qadena.dsvs.MsgRegisterAuthorizedSignatory,/qadena.qadena.MsgCreateCredential,/qadena.qadena.MsgRemoveCredential,/qadena.qadena.MsgClaimCredential,/qadena.qadena.MsgUpdateCredential,/qadena.qadena.MsgClaimUpdatedCredential,/qadena.qadena.MsgProtectPrivateKey,/qadena.qadena.MsgSignRecoverPrivateKey,/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet,/qadena.nameservice.MsgBindCredential,/qadena.nameservice.MsgUnbindCredential,/cosmos.feegrant.v1beta1.MsgGrantAllowance,/cosmos.feegrant.v1beta1.MsgRevokeAllowance"
    DEPLOY_APPSVR_MSGS_EXTRA=""
    DEPLOY_STAKE_BUCKET="foundation"   # 03 Foundation Treasury -- the only bucket with stakes=yes
    # Bucket 03 is 3-of-5 and provides voting power for EVERY deployment, so this does not vary.
    DEPLOY_STAKE_MEMBERS="foundation-m1,foundation-m2,foundation-m3"

    case "$_d" in
    veritas)
        # SEC PH VERITAS.  The names here are step_1.sh's built-in defaults, which is why
        # testscripts/setup_veritas.sh passes almost none of them: `veritas` IS the default
        # profile, and every value below must keep matching step_1.sh or a run started from the
        # foundation side and a run started from the SEC side will disagree about the key names.
        DEPLOY_APPSVR="foundation-veritas-appsvr"
        DEPLOY_USERS="foundation-veritas-users"
        DEPLOY_ADMIN="sec-veritas-admin"
        DEPLOY_SPONSOR_BASE="sec-create-wallet-sponsor"
        DEPLOY_TREASURY="sec-treasury"
        DEPLOY_IDENTITY_PRV="secidentitysrvprv"
        DEPLOY_DSVS_PRV="secdsvssrvprv"
        DEPLOY_DSVS="secdsvs"
        DEPLOY_SEC_HOME="$HOME/sec-veritas"
        DEPLOY_DISPLAY="SEC"
        # step_1.sh's historical hardcoded values -- keep them, so a veritas run before and after
        # this block moved into the profile mints the SAME credential ids.
        DEPLOY_FIRSTNAME="SEC"
        DEPLOY_BIRTHDATE="1936-Oct-26"
        DEPLOY_EMAIL="no-reply@sec.gov.ph"
        DEPLOY_PHONE="+63282504521"
        DEPLOY_AVALUE="200"
        # 10 Public Sector Programs.  allocations.csv earmarks it: "SEC PH VERITAS 60M; future
        # MOUs" and, on the same row, "funds foundation-appsvr/foundation-users sponsors".
        DEPLOY_FUND_BUCKET="pubsec"
        # The .base64 filename stem step_3 writes -- sec-create-wallet-sponsor-names.base64 etc.
        # NOT the env VARIABLE prefix, which stays SEC_ for every deployment (gen_key_env_vars.sh).
        DEPLOY_PREFIX="sec"
        # Bucket 10 is 5-of-7; naming all seven lets the ceremony pick.  derive_launch_keys.sh
        # mints them as <bucket>-m1..mN, so these are a convention, not something the chain knows.
        DEPLOY_FUND_MEMBERS="pubsec-m1,pubsec-m2,pubsec-m3,pubsec-m4,pubsec-m5,pubsec-m6,pubsec-m7"
        ;;
    ekycph)
        DEPLOY_APPSVR="foundation-ekycph-appsvr"
        DEPLOY_USERS="foundation-ekycph-users"
        DEPLOY_ADMIN="ekycph-admin"
        DEPLOY_SPONSOR_BASE="ekycph-create-wallet-sponsor"
        DEPLOY_TREASURY="ekycph-treasury"
        DEPLOY_IDENTITY_PRV="ekycphidentitysrvprv"
        DEPLOY_DSVS_PRV="ekycphdsvssrvprv"
        DEPLOY_DSVS="ekycphdsvs"
        DEPLOY_SEC_HOME="$HOME/ekyc-ph"
        DEPLOY_DISPLAY="ekyc.ph"
        DEPLOY_FIRSTNAME="EKYCPH"
        DEPLOY_BIRTHDATE="2025-Jan-01"
        DEPLOY_EMAIL="no-reply@ekyc.ph"
        DEPLOY_PHONE="+6320000000"
        DEPLOY_AVALUE="2000"
        # 01 Adoption Programs.  Bucket 10 stays earmarked for SEC PH VERITAS and future MOUs.
        # Adoption is a 3of5 multisig where pubsec is 5of7, so the ceremonies here need three
        # signatures and --fund-members names adoption's members.
        DEPLOY_FUND_BUCKET="adoption"
        DEPLOY_PREFIX="ekycph"
        # Bucket 01 is 3-of-5 -- five members, not seven.  Handing the ceremony pubsec's list here
        # would name keys that are in the keyring but not in this bucket's multisig.
        DEPLOY_FUND_MEMBERS="adoption-m1,adoption-m2,adoption-m3,adoption-m4,adoption-m5"
        ;;
    enf)
        DEPLOY_APPSVR="foundation-enf-appsvr"
        DEPLOY_USERS="foundation-enf-users"
        DEPLOY_ADMIN="enf-admin"
        DEPLOY_SPONSOR_BASE="enf-create-wallet-sponsor"
        DEPLOY_TREASURY="enf-treasury"
        DEPLOY_IDENTITY_PRV="enfidentitysrvprv"
        DEPLOY_DSVS_PRV="enfdsvssrvprv"
        DEPLOY_DSVS="enfdsvs"
        DEPLOY_SEC_HOME="$HOME/qadena-enf"
        DEPLOY_DISPLAY="Qadena ENF"
        # THE ELECTRONIC NOTARIAL BOOK.  ENF is the only deployment that drives a CosmWasm
        # contract: create_entry / register_enp / update_enp, plus every CND anchor write, all
        # signed by the ENF wallet pool.  Reported by the follow-the-money app-server session
        # 2026-09-11 (api/helpers/qadena_util.go PrepareENFClientContext).  Without it ENF passes
        # bring-up and dies on the first notarization.
        # NOT MsgStoreCode / MsgInstantiateContract: the operator deploys the contract with
        # qadenad and hands the address to POST /v1/enf/setup_enf, so those belong to the
        # bring-up account, never to a sponsored wallet.
        DEPLOY_APPSVR_MSGS_EXTRA="/cosmwasm.wasm.v1.MsgExecuteContract"
        DEPLOY_FIRSTNAME="ENF"
        DEPLOY_BIRTHDATE="2025-Jan-01"
        # NOT ekycph's +6320000000.  Both scripts carried that same number, so deploying ekycph and
        # enf to one chain collided on the phone-contact-info credential -- the personal-info one
        # differs only because FIRSTNAME does.
        DEPLOY_EMAIL="no-reply@enf.ph"
        DEPLOY_PHONE="+6320000001"
        DEPLOY_AVALUE="2100"
        # 01 Adoption Programs, as for ekycph: 3of5, so --fund-members names adoption's members.
        DEPLOY_FUND_BUCKET="adoption"
        DEPLOY_PREFIX="enf"
        DEPLOY_FUND_MEMBERS="adoption-m1,adoption-m2,adoption-m3,adoption-m4,adoption-m5"
        ;;
    *)
        # An unknown name is NOT an error if a profile file defines it -- that is the documented
        # way to add a deployment without editing this script.  It IS an error otherwise: guessing
        # `foundation-$name-appsvr` for a typo'd deployment would create real keys and fund them.
        DEPLOY_APPSVR=""; DEPLOY_USERS=""; DEPLOY_ADMIN=""; DEPLOY_SPONSOR_BASE=""
        DEPLOY_TREASURY=""; DEPLOY_IDENTITY_PRV=""; DEPLOY_DSVS_PRV=""; DEPLOY_DSVS=""
        DEPLOY_SEC_HOME=""; DEPLOY_FUND_BUCKET=""
        DEPLOY_FIRSTNAME=""; DEPLOY_BIRTHDATE=""; DEPLOY_EMAIL=""; DEPLOY_PHONE=""; DEPLOY_AVALUE=""
        ;;
    esac

    # The override file lands AFTER the case, so it can also correct a built-in profile -- e.g.
    # pinning ekycph's --fund-bucket for a deployment that has settled the question.
    local _dir="${QADENA_DEPLOYMENT_DIR:-$HOME/launch/deployments}"
    if [[ -r "$_dir/$_d.env" ]]; then
        source "$_dir/$_d.env"
        DEPLOY_PROFILE_SOURCE="$_dir/$_d.env"
    fi

    if [[ -z "$DEPLOY_APPSVR" || -z "$DEPLOY_ADMIN" ]]; then
        print -u2 -- "unknown deployment '$_d' and no profile at $_dir/$_d.env"
        print -u2 -- "known: $(deployment_profile_list)"
        print -u2 -- "To add one, write $_dir/$_d.env setting the DEPLOY_* names -- see the header"
        print -u2 -- "of foundation_scripts/deployment_profile.sh for the full list."
        return 1
    fi

    # DERIVED FROM DEPLOY_NAME, NEVER SET PER PROFILE.  These three filenames are how a run finds
    # the previous run's output; if a profile could set them independently of the name, two
    # deployments could be made to share one -- which is the exact silent-collision this file
    # exists to prevent.
    : ${DEPLOY_DISPLAY:="$DEPLOY_NAME"}
    # EXPORTED, unlike the rest: the provider scripts run as CHILD PROCESSES of step_3 and print
    # the operator's name in their own messages.  They take no --deployment of their own, so the
    # environment is the only way the name reaches them.
    export DEPLOY_DISPLAY

    [[ -n "$DEPLOY_APPSVR_MSGS_EXTRA" ]] \
        && DEPLOY_APPSVR_MSGS="$DEPLOY_APPSVR_MSGS,$DEPLOY_APPSVR_MSGS_EXTRA"
    export DEPLOY_APPSVR_MSGS

    DEPLOY_STATE_FILE="$DEPLOY_NAME-sponsors.json"
    DEPLOY_PREGRANT_FILE="$DEPLOY_NAME-pregrant.json"
    DEPLOY_POOL_FILE="$DEPLOY_NAME-pool.json"
    DEPLOY_WORKDIR_TAG="$DEPLOY_NAME-sponsor"

    return 0
}

deployment_profile_list() { print -r -- "veritas ekycph enf" }

# Print the profile the way a caller would set it -- used by --show and by the dev harnesses, which
# eval it rather than duplicating the name table.
deployment_profile_print() {
    local _v
    for _v in NAME DISPLAY PREFIX APPSVR_MSGS APPSVR USERS ADMIN SPONSOR_BASE TREASURY IDENTITY_PRV DSVS_PRV DSVS \
              SEC_HOME FUND_BUCKET FUND_MEMBERS STAKE_BUCKET STAKE_MEMBERS \
              FIRSTNAME BIRTHDATE EMAIL PHONE AVALUE STATE_FILE PREGRANT_FILE POOL_FILE; do
        print -r -- "DEPLOY_$_v=${(P)${:-DEPLOY_$_v}}"
    done
}

# Only act when RUN, not when sourced.  ${zsh_eval_context[-1]} is "file" for a sourced file and
# "toplevel" for an executed script -- $0 comparisons do not work here because the foundation
# scripts source this by absolute path.
if [[ "${zsh_eval_context[-1]}" == "toplevel" ]]; then
    case "${1:-}" in
        --list)      deployment_profile_list; exit 0 ;;
        --show)      deployment_profile_load "${2:?--show needs a deployment name}" || exit 1
                     deployment_profile_print; exit 0 ;;
        --help|-h|"") _dp_usage; exit 0 ;;
        *)           print -u2 -- "unknown option: $1"; _dp_usage >&2; exit 1 ;;
    esac
fi
