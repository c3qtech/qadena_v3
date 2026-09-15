#!/bin/zsh
#
# THE FLEET SITE PROFILE -- which machines a bring-up runs against, and the handful of values that
# vary with them.
#
#   source testscripts/fleet_site_profile.sh        # uses $SITE, default M1-M2
#   testscripts/fleet_site_profile.sh --show staging
#   testscripts/fleet_site_profile.sh --list
#
# WHY THIS EXISTS.  The M1/M2 and staging fleet drivers differed in ten values -- the two hosts,
# the passphrase file, the launch directory, the state-directory suffix, the env file name, whether
# joiners bond, the two advertised addresses and one exported flag -- and were otherwise identical.
# A site is data, so it lives here as data rather than as a second copy of the driver.
#
# SITE IS NOT DEPLOYMENT, AND THEY LIVE APART ON PURPOSE.  A site is a set of machines and
# therefore a CHAIN; a deployment is a programme running on one
# (foundation_scripts/deployment_profile.sh).  That one is shared vocabulary -- 26 files across
# foundation_scripts/, veritas_scripts/ and testscripts/ read it.  This one is read by the two
# fleet drivers here and holds dev-machine ssh addresses, which have no business sitting next to
# derive_launch_keys.sh and mnemonic.sh.  Several deployments share one site -- that
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
    # A CloudFormation template to populate with the run's keys.  Empty on every site that does
    # not deploy to AWS, which is all of them today -- veritas_full_setup.sh skips the step then.
    SITE_CF_TEMPLATE=""
    SITE_NODE_GRANTER=""

    case "$_s" in
    M1-M2|m1-m2)
        # The Parallels fleet on this machine.  M1 is the primary and the only builder; M2 joins.
        # NAMED FOR THE MACHINES, not "local": every site is local to somebody, and the fleet is
        # referred to as M1/M2 everywhere else.  Lowercase is accepted so the capitals are optional.
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
        # WHO PAYS THE NODES' FEES.  A node's fee grant is a property of the CHAIN, not of any one
        # deployment -- several deployments share these machines -- so it belongs to the site.
        # nodeops is allocations.csv bucket 12, Node Operations, and it is a 3of5 multisig in the
        # coordinator keyring, so each join runs a ceremony.
        #
        # This covers FEES only.  A validator's self-bond is delivered as a TRANSFER by
        # ensure_self_bond: staked principal is the node's own, it is what gets bonded and what
        # slashing burns, so it cannot be a fee grant.
        SITE_NODE_GRANTER="nodeops"
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
        # A SEPARATE STATE DIRECTORY.  Staging shared ~/sec-veritas with the M1/M2 fleet, and the
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
        SITE_NODE_GRANTER="nodeops"
        ;;
    qfi-testnet)
        # LIKE staging, BUT SINGLE-NODE.  One validator, no joiner: the primary is the whole fleet.
        #
        # !! SAME HOST AS staging !!  20.212.178.16 is staging's primary too.  The two sites have
        # separate LOCAL state (SITE_LAUNCH_DIR, SITE_HOME_SUFFIX), but they share the REMOTE node
        # home, so they cannot both run: bringing one up replaces the other's chain, and
        # --rebuild-chain purges whichever chain is there now.  That is fine if qfi-testnet is
        # meant to SUPERSEDE staging on that box; it is data loss if both are wanted at once, and
        # the fix then is a second host, not a second profile.
        SITE_PRIMARY="cloudsigma@45.115.225.104"
        SITE_JOINER=""
        # VISIBLE, AND INSIDE THE LAUNCH DIRECTORY -- not a dotfile in $HOME like the other two
        # sites.  This is a throwaway testnet whose passphrase is generated rather than chosen, so
        # it wants to be findable next to the chain it unlocks.  veritas_full_setup.sh mints it on
        # the first run when the directory has no keyring yet.
        SITE_LAUNCH_DIR="$HOME/qfi-testnet-fleet-launch"
        SITE_PASSFILE="$SITE_LAUNCH_DIR/keyring-password"
        SITE_ADVERTISE_P="45.115.225.104"
        SITE_ADVERTISE_J=""
        # ITS OWN STATE DIRECTORY, for the reason staging has one: --rebuild-chain DELETES the
        # deployment home, so a site sharing it with another fleet destroys that fleet's keys and
        # mnemonics on the way to building its own chain.
        SITE_HOME_SUFFIX="-qfi-testnet"
        SITE_ENV_FILE_NAME="env-staging-no-aws"
        # MOOT, BUT SET: with no joiner there is nothing to convert.  Left at 0 so that adding a
        # joiner later does not silently start bonding it.
        SITE_JOINER_VALIDATOR=0
        # Nothing to agree WITH on a single node, so the peer-agreement check has no peers to read
        # out of netinfo.  Same relaxation staging needs for its NLB, different reason.
        SITE_ALLOW_UNVERIFIED_AGREEMENT=1
        SITE_NODE_GRANTER="nodeops"
        # THE CLOUDFORMATION SOURCE.  Read, never written: veritas_full_setup.sh renders a populated
        # COPY into the deployment home and leaves this tracked file alone.  The older
        # api/aws/patch-*-cloud-formation-ssm-parameters.yaml files are superseded; do not target them.
        SITE_CF_TEMPLATE="$HOME/test/follow-the-money/api/aws/v2-cloud-formation-ssm-parameters.yaml"
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
        # A KNOWN site with no host is a different problem from a TYPO, and telling an operator
        # "unknown site 'qfi-testnet'" when the name is right sends them looking in the wrong file.
        if [[ " $(fleet_site_profile_list) " == *" $_s "* ]]; then
            print -u2 -- "site '$_s' has no SITE_PRIMARY -- its host is not recorded in this repo."
            print -u2 -- "Set it in $_dir/$_s.env:"
            print -u2 -- "    SITE_PRIMARY=\"user@host\""
            print -u2 -- "    SITE_ADVERTISE_P=\"<ip or dns the peers dial>\""
            print -u2 -- "or pass --primary user@host on the command line."
            return 1
        fi
        print -u2 -- "unknown site '$_s' and no profile at $_dir/$_s.env"
        print -u2 -- "known: $(fleet_site_profile_list)"
        print -u2 -- "To add one, write $_dir/$_s.env setting SITE_PRIMARY, SITE_JOINER,"
        print -u2 -- "SITE_PASSFILE, SITE_LAUNCH_DIR and the rest -- see this file's header."
        return 1
    fi
    : ${SITE_JOINER_VALIDATOR:=1}
    : ${SITE_ENV_FILE_NAME:=env-sponsored-test}
    : ${SITE_NODE_GRANTER:=nodeops}
    return 0
}

fleet_site_profile_list() { print -r -- "M1-M2 staging qfi-testnet" }

fleet_site_profile_print() {
    local _v
    for _v in NAME PRIMARY JOINER PASSFILE LAUNCH_DIR ADVERTISE_P ADVERTISE_J \
              HOME_SUFFIX ENV_FILE_NAME JOINER_VALIDATOR ALLOW_UNVERIFIED_AGREEMENT NODE_GRANTER; do
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
