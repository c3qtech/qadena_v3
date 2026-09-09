#!/bin/zsh
#
# THE FLEET SITE PROFILE -- which machines a bring-up runs against, and the handful of values that
# vary with them.
#
#   source foundation_scripts/fleet_site_profile.sh        # uses $SITE, default local
#   foundation_scripts/fleet_site_profile.sh --show staging
#   foundation_scripts/fleet_site_profile.sh --list
#
# WHY THIS EXISTS.  testscripts/veritas_full_setup.sh and veritas_full_setup_sec_staging.sh were 514
# and 520 lines and differed in TEN VALUES -- the two hosts, the passphrase file, the launch
# directory, the state directory suffix, the env file name, whether joiners become validators, the
# two advertised addresses, and one exported flag.  Everything else was a copy.
#
# Copies drift, and these two had already drifted in the direction that matters: the staging file
# was missing the --keyring-passfile argument the local one passes to the fleet bring-up, and the
# compose.yml check that catches a wrong --env-file.  Neither absence was deliberate; staging was
# simply the copy nobody updated.  A site is data, so it lives here as data.
#
# SITE IS NOT DEPLOYMENT.  A site is a set of machines and therefore a CHAIN; a deployment is a
# programme running on one (see deployment_profile.sh).  Several deployments share one site -- that
# is the whole point of the launch chain -- so the two are chosen independently:
#
#     veritas_full_setup.sh --site staging --deployment ekycph
#
# WHAT IS DELIBERATELY NOT HERE: anything about a deployment's names, buckets or keys.  Those come
# from deployment_profile.sh and must not be duplicated into a site.

_fs_usage() {
    print -r -- "Usage: fleet_site_profile.sh [--show <name>] [--list]"
    print -r -- ""
    print -r -- "  Sourced by the fleet drivers; \$SITE selects the profile."
    print -r -- "  --show <name>   print one profile as shell assignments"
    print -r -- "  --list          list the known site names"
}

fleet_site_profile_load() {
    local _s="${1:-${SITE:-local}}"

    SITE_NAME="$_s"
    # Cleared first: a profile file that sets only some fields must not inherit the rest from
    # whatever a previous load left behind.
    SITE_PRIMARY=""; SITE_JOINER=""; SITE_PASSFILE=""; SITE_LAUNCH_DIR=""
    SITE_ADVERTISE_P=""; SITE_ADVERTISE_J=""; SITE_HOME_SUFFIX=""
    SITE_ENV_FILE_NAME=""; SITE_JOINER_VALIDATOR=""; SITE_ALLOW_UNVERIFIED_AGREEMENT=0

    case "$_s" in
    local)
        # The Parallels fleet on this machine.  M1 is the primary and the only builder; M2 joins.
        SITE_PRIMARY="alvillarica@10.211.55.5"
        SITE_JOINER="alvillarica@10.211.55.6"
        SITE_PASSFILE="$HOME/fleet-launch-password"
        SITE_LAUNCH_DIR="$HOME/fleet-launch"
        # Both hosts are on one flat network, so each advertises the address its peer already dials
        # -- the ssh host -- and neither needs an override.
        SITE_ADVERTISE_P=""
        SITE_ADVERTISE_J=""
        SITE_HOME_SUFFIX=""
        SITE_ENV_FILE_NAME="env-sponsored-test"
        # Bond the joiner: on a two-node fleet that is what gives the chain a second validator, and
        # without it the primary is the only vote.
        SITE_JOINER_VALIDATOR=1
        ;;
    staging)
        # Azure primary, AWS joiner.  Two clouds, so nothing is on one network.
        SITE_PRIMARY="azureuser@20.212.178.16"
        SITE_JOINER="ubuntu@172.31.20.18"
        SITE_PASSFILE="$HOME/.sec-veritas-password"
        SITE_LAUNCH_DIR="$HOME/sec-veritas-staging-fleet-launch"
        # WHAT EACH NODE TELLS PEERS TO DIAL, which is NOT the address we ssh to.  The joiner is
        # behind an NLB and its ssh address is a private 172.31 one that the primary cannot reach;
        # advertising that would produce a peer nobody can dial and a chain that never gossips.
        SITE_ADVERTISE_P="20.212.178.16"
        SITE_ADVERTISE_J="dev-nlb-97f5978861fac526.elb.ap-southeast-1.amazonaws.com"
        # A SEPARATE STATE DIRECTORY.  Staging shared ~/sec-veritas with the local fleet, and the
        # rebuild stage DELETES it -- so a staging run wiped the local deployment's keys and
        # mnemonics before it had even reached its own chain (2026-09-07).  Two sites, two homes.
        SITE_HOME_SUFFIX="-staging"
        SITE_ENV_FILE_NAME="env-staging-no-aws"
        # Full nodes only: the joiner serves RPC and syncs but does not vote, so the primary stays
        # the sole validator and a joiner outage cannot stall the chain.
        SITE_JOINER_VALIDATOR=0
        # The peer-agreement check reads addresses out of netinfo, which behind an NLB reports the
        # load balancer rather than the peer.  The check cannot verify that and refusing on it would
        # block every staging run; see the note in fleet_bringup_with_tests.sh.
        SITE_ALLOW_UNVERIFIED_AGREEMENT=1
        ;;
    *)
        ;;
    esac

    # Sourced AFTER the built-ins so it overrides rather than replaces -- the documented way to add
    # a site, or to correct one, without editing this file.
    local _dir="${QADENA_SITE_DIR:-$HOME/launch/sites}"
    if [[ -r "$_dir/$_s.env" ]]; then
        source "$_dir/$_s.env"
        SITE_PROFILE_SOURCE="$_dir/$_s.env"
    fi

    if [[ -z "$SITE_PRIMARY" ]]; then
        print -u2 -- "unknown site '$_s' and no profile at $_dir/$_s.env"
        print -u2 -- "known: $(fleet_site_profile_list)"
        print -u2 -- "To add one, write $_dir/$_s.env setting SITE_PRIMARY, SITE_JOINER,"
        print -u2 -- "SITE_PASSFILE, SITE_LAUNCH_DIR and the rest -- see this file's header."
        return 1
    fi
    : ${SITE_JOINER_VALIDATOR:=1}
    : ${SITE_ENV_FILE_NAME:=env-sponsored-test}
    return 0
}

fleet_site_profile_list() { print -r -- "local staging" }

fleet_site_profile_print() {
    local _v
    for _v in NAME PRIMARY JOINER PASSFILE LAUNCH_DIR ADVERTISE_P ADVERTISE_J \
              HOME_SUFFIX ENV_FILE_NAME JOINER_VALIDATOR ALLOW_UNVERIFIED_AGREEMENT; do
        print -r -- "SITE_$_v=${(P)${:-SITE_$_v}}"
    done
}

# Only act when RUN, not when sourced -- the fleet drivers source this by absolute path, so a $0
# comparison would not work.
if [[ "${zsh_eval_context[-1]}" == "toplevel" ]]; then
    case "${1:-}" in
        --list)       fleet_site_profile_list; exit 0 ;;
        --show)       fleet_site_profile_load "${2:?--show needs a site name}" || exit 1
                      fleet_site_profile_print; exit 0 ;;
        --help|-h|"") _fs_usage; exit 0 ;;
        *)            print -u2 -- "unknown option: $1"; _fs_usage >&2; exit 1 ;;
    esac
fi
