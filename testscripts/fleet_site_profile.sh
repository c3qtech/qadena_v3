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
# ONE PRIMARY, ANY NUMBER OF JOINERS.  A site names its joiners in SITE_JOINERS (an array);
# SITE_JOINER is the single-joiner spelling and stays in step with the first of them, so a site or
# an override file may use either and every consumer may read either.  SITE_ADVERTISE_JS is
# positional against SITE_JOINERS, or one entry that all of them advertise.
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
    # TWO OR MORE JOINERS.  SITE_JOINERS is the canonical form and SITE_JOINER is the one-joiner
    # spelling kept for every site and env file already written against it; the normalisation after
    # the case below keeps the two in step whichever was set, so a consumer may read either.
    # SITE_ADVERTISE_JS is positional against SITE_JOINERS -- one entry per joiner, or a single
    # entry meaning "all of them advertise this", which is what a shared NLB or NAT address wants.
    SITE_JOINERS=(); SITE_ADVERTISE_JS=()
    SITE_ENV_FILE_NAME=""; SITE_JOINER_VALIDATOR=""; SITE_ALLOW_UNVERIFIED_AGREEMENT=0
    # A CloudFormation template to populate with the run's keys.  Empty on every site that does
    # not deploy to AWS, which is all of them today -- veritas_full_setup.sh skips the step then.
    SITE_CF_TEMPLATE=""
    SITE_NODE_GRANTER=""

    case "$_s" in
    M1-M4|m1-m4)
        # The Parallels fleet on this machine.  M1 is the primary and the only builder; M2 joins.
        # NAMED FOR THE MACHINES, not "local": every site is local to somebody, and the fleet is
        # referred to as M1/M2 everywhere else.  Lowercase is accepted so the capitals are optional.
        SITE_PRIMARY="alvillarica@10.211.55.5"
        SITE_JOINERS=("alvillarica@10.211.55.6" "alvillarica@10.211.55.7" "alvillarica@10.211.55.8")
        SITE_PASSFILE="$HOME/fleet-launch-password"
        SITE_LAUNCH_DIR="$HOME/fleet-launch"
        # Both hosts are on one flat network, so each advertises the address its peer already dials
        # -- the ssh host -- and neither needs an override.
        SITE_ADVERTISE_P=""
        SITE_ADVERTISE_J=""
        SITE_HOME_SUFFIX="-m1-m4"
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
        SITE_HOME_SUFFIX="-m1-m2"
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
    qfi-mainnet)
        # LIKE staging, BUT SINGLE-NODE.  One validator, no joiner: the primary is the whole fleet.
        #
        # !! SAME HOST AS staging !!  20.212.178.16 is staging's primary too.  The two sites have
        # separate LOCAL state (SITE_LAUNCH_DIR, SITE_HOME_SUFFIX), but they share the REMOTE node
        # home, so they cannot both run: bringing one up replaces the other's chain, and
        # --rebuild-chain purges whichever chain is there now.  That is fine if qfi-testnet is
        # meant to SUPERSEDE staging on that box; it is data loss if both are wanted at once, and
        # the fix then is a second host, not a second profile.
        # .229 IS PRIMARY BECAUSE IT IS THE ONLY BOX THAT CAN ATTEST.  .104 and .170 cannot produce
        # a DCAP quote at all: Intel PCS answers 404 for their QE IDs, i.e. those platforms are not
        # registered, so there is no PCK cert to sign a quote with.  That is not a PCCS or config
        # problem on our side and no amount of retrying fixes it -- it needs the host provider to
        # register them.  Since sync-enclave makes the JOINER produce a quote too, they cannot join
        # either; hence no joiners, which also matches SITE_JOINER_VALIDATOR=0 below.
        #
        # .229 attests, but reports TCB OutOfDateConfigurationNeeded (level tcbDate 2022-08-10 for
        # FMSPC 00606A000000).  That is admitted only because common.AllowOutOfDateTCB is true --
        # read the commentary there before assuming this site is safe for real key material.
        SITE_PRIMARY="cloudsigma@103.56.5.229"
        SITE_JOINERS=("azureuser@172.188.59.88")
        # VISIBLE, AND INSIDE THE LAUNCH DIRECTORY -- not a dotfile in $HOME like the other two
        # sites.  This is a throwaway testnet whose passphrase is generated rather than chosen, so
        # it wants to be findable next to the chain it unlocks.  veritas_full_setup.sh mints it on
        # the first run when the directory has no keyring yet.
        SITE_LAUNCH_DIR="$HOME/qfi-mainnet-fleet-launch"
        SITE_PASSFILE="$SITE_LAUNCH_DIR/keyring-password"
        SITE_ADVERTISE_P="103.56.5.229"
        SITE_ADVERTISE_J=""
        # ITS OWN STATE DIRECTORY, for the reason staging has one: --rebuild-chain DELETES the
        # deployment home, so a site sharing it with another fleet destroys that fleet's keys and
        # mnemonics on the way to building its own chain.
        SITE_HOME_SUFFIX="-qfi-mainnet"
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
        # IN-REPO, not the app-server checkout.  veritas_deployment/ carries this repo's own copy,
        # so a bring-up does not depend on a sibling repo being present or on which branch it is on.
        # ${(%):-%x} IS THIS FILE, ${0} IS THE SOURCING SCRIPT.  This file is sourced, so $0 names
        # whatever sourced it -- veritas_full_setup.sh from testscripts/, but the profile itself
        # when run directly -- and the repo root came out one level off.  %x always names the file
        # being read, so the path is correct however this is reached.
        SITE_CF_TEMPLATE="${${(%):-%x}:A:h:h}/veritas_deployment/v2-cloud-formation-ssm-parameters.yaml"
        ;;
    SGX|sgx)
        # THE ONLY REAL-SGX FLEET.  Two x86 boxes with SGX devices, ego and a working PCCS; M1-M4
        # are ARM debug enclaves and cannot stand in for them.  SGX1 is the primary and the ONLY
        # builder -- a measurement is the hash of the binary, so a second independent build is a
        # second enclave that the chain will refuse.  SGX2 installs the package SGX1 produces.
        #
        # SGX IS NOT SET HERE, AND CANNOT BE.  veritas_full_setup.sh takes --sgx 0|1 per run and
        # DEFAULTS TO 0, which forwards --no-build-sgx and builds debug artifacts even on this
        # hardware.  A debug chain binary on an SGX box verifies real quotes with the debug
        # verifier and accepts forged ones for the life of the chain, and nothing fails loudly.
        # So a bring-up of this site MUST pass --sgx 1; there is no site field that can do it.
        SITE_PRIMARY="alvillarica@192.168.86.120"
        SITE_JOINER="alvillarica@192.168.86.140"
        # Its own launch directory and generated passphrase, like qfi-testnet and for the same
        # reason: --rebuild-chain deletes the deployment home, so sharing one with another fleet
        # destroys that fleet's keys on the way to building this chain.
        SITE_LAUNCH_DIR="$HOME/sgx-fleet-launch"
        SITE_PASSFILE="$SITE_LAUNCH_DIR/keyring-password"
        # One flat LAN (192.168.86.0/24): each node advertises the host its peer already dials, so
        # neither needs an override.
        SITE_ADVERTISE_P=""
        SITE_ADVERTISE_J=""
        # ITS OWN DEPLOYMENT HOMES, like staging and qfi-testnet -- NOT "" as M1-M2 has.  SEC_HOME
        # is $DEPLOY_SEC_HOME$SITE_HOME_SUFFIX (veritas_full_setup.sh:88), so an empty suffix here
        # would point this site at ~/sec-veritas and ~/ekyc-ph -- the SAME directories the M1-M2
        # fleet uses.  Two consequences, both seen: a ceremony here fails with "too many failed
        # passphrase attempts" because those mnemonics are sealed under M1-M2's passphrase and not
        # this site's, and a --rebuild-chain here would try to DELETE the other fleet's keys (it is
        # refused only when the coordinator already holds that deployment's sponsors file).
        SITE_HOME_SUFFIX="-sgx"
        SITE_ENV_FILE_NAME="env-sponsored-test"
        # Bond the joiner: two real-SGX validators is the whole point of this site, and it is the
        # only fleet where an attested validator set can be exercised at all.
        SITE_JOINER_VALIDATOR=1
        SITE_ALLOW_UNVERIFIED_AGREEMENT=0
        SITE_NODE_GRANTER="nodeops"
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
        print -u2 -- "To add one, write $_dir/$_s.env setting SITE_PRIMARY, SITE_JOINERS (an array,"
    print -u2 -- "or SITE_JOINER for a single one),"
        print -u2 -- "SITE_PASSFILE, SITE_LAUNCH_DIR and the rest -- see this file's header."
        return 1
    fi
    # KEEP THE ONE-JOINER AND MANY-JOINER SPELLINGS IN STEP, in whichever direction the profile
    # (or an env-file override, which is sourced above and may use either) happened to write.
    # Done AFTER the override so a file setting SITE_JOINERS=() wins over a built-in SITE_JOINER,
    # and vice versa.
    if (( ${#SITE_JOINERS} == 0 )) && [[ -n "$SITE_JOINER" ]]; then
        SITE_JOINERS=("$SITE_JOINER")
    fi
    SITE_JOINER="${SITE_JOINERS[1]:-}"
    if (( ${#SITE_ADVERTISE_JS} == 0 )) && [[ -n "$SITE_ADVERTISE_J" ]]; then
        SITE_ADVERTISE_JS=("$SITE_ADVERTISE_J")
    fi
    SITE_ADVERTISE_J="${SITE_ADVERTISE_JS[1]:-}"
    # One advertise address for several joiners is a shared route, not a mistake -- but more
    # addresses than joiners means the two lists have drifted, and the extra would be silently
    # dropped at exactly the node that then advertises the wrong host.
    if (( ${#SITE_ADVERTISE_JS} > 1 && ${#SITE_ADVERTISE_JS} != ${#SITE_JOINERS} )); then
        print -u2 -- "site '$_s': ${#SITE_ADVERTISE_JS} joiner advertise address(es) for ${#SITE_JOINERS} joiner(s)."
        print -u2 -- "  Give one per joiner, in the same order, or exactly one for all of them."
        return 1
    fi
    : ${SITE_JOINER_VALIDATOR:=1}
    : ${SITE_ENV_FILE_NAME:=env-sponsored-test}
    : ${SITE_NODE_GRANTER:=nodeops}
    return 0
}

fleet_site_profile_list() { print -r -- "M1-M2 M1-M4 staging qfi-mainnet SGX" }

fleet_site_profile_print() {
    local _v
    for _v in NAME PRIMARY JOINER PASSFILE LAUNCH_DIR ADVERTISE_P ADVERTISE_J \
              HOME_SUFFIX ENV_FILE_NAME JOINER_VALIDATOR ALLOW_UNVERIFIED_AGREEMENT NODE_GRANTER; do
        print -r -- "SITE_$_v=${(P)${:-SITE_$_v}}"
    done
    # THE ARRAYS TOO, because SITE_JOINER alone shows only the FIRST of them -- and "--show says
    # one joiner" is exactly how a three-node site would look correct while two nodes went missing.
    print -r -- "SITE_JOINERS=(${SITE_JOINERS[*]})"
    print -r -- "SITE_ADVERTISE_JS=(${SITE_ADVERTISE_JS[*]})"
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
