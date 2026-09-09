#!/bin/zsh
#
# THE DEPLOYMENT PROFILE -- one place that answers "what is this deployment called, in every
# namespace it appears in".
#
#   source foundation_scripts/deployment_profile.sh          # uses $DEPLOYMENT, default veritas
#   foundation_scripts/deployment_profile.sh --show ekycph   # print one, for eyeballing
#   foundation_scripts/deployment_profile.sh --list
#
# WHY THIS EXISTS.  The foundation's sponsored/multisig layer was written for SEC VERITAS and named
# for it throughout: `foundation-veritas-appsvr`, `veritas-sponsors.json`, `sec-veritas-admin`.
# sec_veritas_before_step_1.sh already said what was coming --
#
#     "Bucket 10's notes list 'SEC PH VERITAS 60M; future MOUs; OTC swap reserve' -- so the
#      foundation will sponsor more than one programme out of the same bucket, and a bare
#      `foundation-appsvr` would collide the moment the second one starts.  The keyring has no
#      namespaces: a name is unique per keyring and nothing warns on reuse."
#
# -- and ekycph and enf are that second and third programme.  Every one of those names has to vary
# together or a run silently reads one deployment's state while writing another's.  THE COLLISION IS
# SILENT IN BOTH DIRECTIONS: an `--appsvr` that resolves to the wrong key funds the wrong programme,
# and a `veritas-pool.json` left from an earlier run verifies green against a pool that was never
# created.  So the mapping lives here, once, rather than in a flag each caller has to remember.
#
# ADDING A DEPLOYMENT.  Either add a case below, or -- without touching this file -- drop
# <name>.env into $QADENA_DEPLOYMENT_DIR (default ~/launch/deployments) setting any DEPLOY_* var.
# The file is sourced AFTER the built-in case, so it overrides rather than replaces, and a
# deployment that is merely a rename of another needs two lines.
#
# WHAT IS DELIBERATELY *NOT* HERE: mnemonics, addresses, amounts.  This maps names to names.  An
# address belongs to a chain and a mnemonic belongs in a sealed file; putting either in a profile
# that gets copied between machines is how they leak.

# ---------------------------------------------------------------------------------------------
# THE PROFILE
# ---------------------------------------------------------------------------------------------
# DEPLOY_NAME           the short name; every artefact filename is built from it
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
    DEPLOY_STAKE_BUCKET="foundation"   # 03 Foundation Treasury -- the only bucket with stakes=yes

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
        # 10 Public Sector Programs.  allocations.csv earmarks it: "SEC PH VERITAS 60M; future
        # MOUs" and, on the same row, "funds foundation-appsvr/foundation-users sponsors".
        DEPLOY_FUND_BUCKET="pubsec"
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
        DEPLOY_SEC_HOME="$HOME/sec-ekycph"
        # 01 Adoption Programs.  DECIDED 2026-09-09: eKYC PH is an adoption programme, not a
        # public-sector one -- bucket 10 stays earmarked for SEC PH VERITAS and future MOUs.
        # NOTE THE DIFFERENT THRESHOLD: adoption is a 3of5 multisig where pubsec is 5of7, so the
        # ceremonies here need three signatures, not five, and --fund-members names adoption's
        # members.  Sizing the gas for the wrong threshold is the usual way this bites.
        DEPLOY_FUND_BUCKET="adoption"
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
        DEPLOY_SEC_HOME="$HOME/sec-enf"
        # 01 Adoption Programs.  DECIDED 2026-09-09: ENF is an adoption programme, not a
        # public-sector one -- bucket 10 stays earmarked for SEC PH VERITAS and future MOUs.
        # NOTE THE DIFFERENT THRESHOLD: adoption is a 3of5 multisig where pubsec is 5of7, so the
        # ceremonies here need three signatures, not five, and --fund-members names adoption's
        # members.  Sizing the gas for the wrong threshold is the usual way this bites.
        DEPLOY_FUND_BUCKET="adoption"
        ;;
    *)
        # An unknown name is NOT an error if a profile file defines it -- that is the documented
        # way to add a deployment without editing this script.  It IS an error otherwise: guessing
        # `foundation-$name-appsvr` for a typo'd deployment would create real keys and fund them.
        DEPLOY_APPSVR=""; DEPLOY_USERS=""; DEPLOY_ADMIN=""; DEPLOY_SPONSOR_BASE=""
        DEPLOY_TREASURY=""; DEPLOY_IDENTITY_PRV=""; DEPLOY_DSVS_PRV=""; DEPLOY_DSVS=""
        DEPLOY_SEC_HOME=""; DEPLOY_FUND_BUCKET=""
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
    for _v in NAME APPSVR USERS ADMIN SPONSOR_BASE TREASURY IDENTITY_PRV DSVS_PRV DSVS \
              SEC_HOME FUND_BUCKET STAKE_BUCKET STATE_FILE PREGRANT_FILE POOL_FILE; do
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
