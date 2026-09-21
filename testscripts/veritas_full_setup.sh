#!/bin/zsh
#
# The whole VERITAS bring-up, end to end, plus the app-server deployment that consumes it.
#
#   ./testscripts/veritas_full_setup.sh --node tcp://10.211.55.5:26657 --passfile ~/.qadena-pass
#
# WHAT THIS IS FOR.  The flow is eight commands across two organisations, and the ordering
# constraints between them are not obvious from any one of them: SEC cannot start until the
# foundation has funded and delegated, the foundation cannot vote until SEC has submitted, and
# step_3 cannot run until the providers are REGISTERED (not merely proposed).  Every one of those
# has been got wrong by hand at least once.  Here they are in one place, in order, with the
# handoffs wired instead of pasted.
#
# BOTH SIDES ON ONE BOX.  A real deployment splits these across two machines and the handoffs are
# printed blocks a human carries.  This runs them together, which is right for a test fleet and
# WRONG for anything else -- it needs the foundation's coordinator keyring and SEC's keyring on
# the same host, which is exactly the arrangement the split exists to prevent.
#
# RESUMABLE.  --from <stage> restarts at a named stage; every underlying script is individually
# idempotent (wallets, claims and grants are all checked against the CHAIN before being created),
# so re-running a stage that already completed is safe and cheap.
#
# WHAT IT DOES NOT DO: rebuild the chain.  --rebuild-chain is offered but must be asked for; it
# purges both fleet nodes, which destroys every wallet, credential and grant on them, including
# anything another team is testing against.  Nothing here is recoverable afterwards except from
# the mnemonics.

set -e
set -u

SCRIPT_DIR="${0:A:h}"
REPO="${SCRIPT_DIR:h}"

# WHICH FLEET, AND WHICH PROGRAMME ON IT.  Pre-scanned before anything is defaulted, because every
# default below comes from one or the other -- the ordering bug that split a deployment across two
# directories in step_1 is the same shape as deriving these after parsing.
#
#   --site        the machines, and therefore the chain: M1-M2 or staging (Azure/AWS).
#                 Replaces veritas_full_setup_sec_staging.sh, which was this file with ten values
#                 changed and two later fixes missing.
#   --deployment  the programme: veritas, ekycph, enf.  Selects the sponsor keys, the admin key,
#                 the service-provider names, the allocation bucket that funds it and the members
#                 who sign for that bucket.
SITE="${SITE:-M1-M2}"
DEPLOYMENT="${DEPLOYMENT:-veritas}"
_i=1
while (( _i <= $# )); do
    case "${@[$_i]}" in
        --site)       SITE="${@[$((_i+1))]:?--site needs a name}" ;;
        --deployment) DEPLOYMENT="${@[$((_i+1))]:?--deployment needs a name}" ;;
    esac
    _i=$(( _i + 1 ))
done
source "$SCRIPT_DIR/fleet_site_profile.sh"
fleet_site_profile_load "$SITE" || exit 1
source "$SCRIPT_DIR/../foundation_scripts/deployment_profile.sh"
deployment_profile_load "$DEPLOYMENT" || exit 1

NODE="${QADENA_NODE:-}"
NODE_EXPLICIT=0
PASSFILE="$SITE_PASSFILE"
LAUNCH_DIR="$SITE_LAUNCH_DIR"
CHAIN_ID="qadena_4824-1"
# WHICH COMMIT THE FLEET BUILDS.  Empty means "leave the primary's checkout where it is", which is
# what 1st_node_bringup does by default -- so a run with no --ref builds whatever M1 happens to
# have, NOT what is in front of you.  That is how a bring-up died on
#     Unknown option: --keyring-passfile
# with the flag present and committed here and absent on the node.  Name the branch to be sure.
REF=""
# SGX=0 BUILDS A DEBUG ENCLAVE, and that has to be said explicitly rather than left to inference.
# build.sh's default is "ego installed means SGX", so a host with ego and NO /dev/sgx* devices --
# traxion-vm-01 is exactly that -- produces a signed enclave it cannot load unless --no-sgx is
# passed.  Omitting --build-sgx is not the same as passing --no-sgx; the bringup's own comment
# records that this once printed "debug (forced)" while producing a signed SGX build.
#
# SGX=1 passes nothing and lets the bringup probe the host: ego plus devices -> SGX, otherwise
# debug.  Use it on the SGX fleet.
SGX=0
# JOINER_VALIDATOR=1 bonds each joiner so it counts toward quorum -- what a test fleet wants, and
# what several suites need (an audit with one validator heals nothing).  0 leaves them as full
# nodes: they sync and serve RPC but never bond, which makes the PRIMARY the only validator and
# therefore a single point of failure for the chain.
JOINER_VALIDATOR="$SITE_JOINER_VALIDATOR"
COORD_HOME="$LAUNCH_DIR/coord"
# THE DEPLOYMENT'S HOME, SUFFIXED BY THE SITE.  ~/ekyc-ph on M1/M2, ~/ekyc-ph-staging
# on staging.  The suffix is not cosmetic: the rebuild stage DELETES this directory, and staging
# once shared ~/sec-veritas with the M1/M2 fleet and wiped its keys and mnemonics.
SEC_HOME="${VERITAS_SEC_HOME:-$DEPLOY_SEC_HOME$SITE_HOME_SUFFIX}"
COUNT=3
FROM="bootstrap"
REBUILD=0
UNTIL=""
# The CloudFormation template to populate alongside the env file.  Empty = skip that step; an
# AWS-deployed site sets SITE_CF_TEMPLATE in its profile, everyone else passes --cloud-formation-template.
CF_TEMPLATE="${SITE_CF_TEMPLATE:-}"
# ONE PATH, NOT A DIRECTORY PLUS A NAME -- see the staging script for why.
# The stack is named for the DEPLOYMENT, the env file within it for the SITE.
ENV_FILE="$HOME/test/follow-the-money/stacks/$DEPLOY_NAME/$SITE_ENV_FILE_NAME"
PREFIX="$DEPLOY_PREFIX"
PRIMARY="$SITE_PRIMARY"
# THE WHOLE LIST, NOT THE FIRST.  A site may name several joiners; SITE_JOINER is only the first
# of them, kept for the single-joiner spelling.  JOINER stays in step for the messages that name
# one host.
JOINERS=("${SITE_JOINERS[@]}")
JOINER="${JOINERS[1]:-}"
# Positional against JOINERS, or one entry meaning "all of them advertise this".
ADVERTISE_JS=("${SITE_ADVERTISE_JS[@]}")
_JOINER_FROM_CLI=0
_ADV_J_FROM_CLI=0
SKIP_APP=0
NODE_GRANTER="$SITE_NODE_GRANTER"
ADVERTISE_P="$SITE_ADVERTISE_P"
ADVERTISE_J="${ADVERTISE_JS[1]:-}"

usage() {
    print -r -- "Usage: veritas_full_setup.sh [options]"
    print -r -- ""
    print -r -- "  --site <name>       which fleet: $(fleet_site_profile_list).  Default $SITE_NAME."
    print -r -- "                      Selects the hosts, the passphrase file, the launch dir, the"
    print -r -- "                      advertised addresses and whether joiners bond."
    print -r -- "  --deployment <name> which programme: $(deployment_profile_list).  Default"
    print -r -- "                      $DEPLOY_NAME.  Selects the sponsor keys, the admin key, the"
    print -r -- "                      providers, the allocation bucket and its signing members."
    print -r -- "  --passfile <file>   keyring passphrase, first line.  Default $PASSFILE."
    print -r -- "                      The keyrings default"
    print -r -- "                      to the encrypted 'file' backend and a prompt with no terminal"
    print -r -- "                      looks exactly like a hang."
    print -r -- "  --node <rpc>        the chain RPC.  Default: derived from --primary"
    print -r -- "                      (tcp://<primary-host>:26657), or \$QADENA_NODE, or"
    print -r -- "                      tcp://localhost:26657 when there is no --primary."
    print -r -- "  --count <n>         ephemeral wallets per user (default 3; 30 for a real run)"
    print -r -- "  --coord-home <dir>  foundation keyring (default ~/fleet-launch/coord)"
    print -r -- "  --sec-home <dir>    the deployment's directory (default $SEC_HOME)"
    print -r -- "  --from <stage>      resume: bootstrap|prepare|step1|delegate|step2|approve|step3|pool|verify|app"
    print -r -- "  --until <stage>     stop AFTER that stage.  --rebuild-chain --until bootstrap"
    print -r -- "                      builds and starts the chain and runs no ceremony at all."
    print -r -- "  --cloud-formation-template <file>"
    print -r -- "                      also patch this CloudFormation template's SSM parameters"
    print -r -- "                      with the same keys.  Default ${CF_TEMPLATE:-<none: skipped>}"
    print -r -- "  --node-granter <k>  bucket that fee-grants each joiner.  Default $NODE_GRANTER"
    print -r -- "                      (allocations.csv 12 Node Operations).  Covers node FEES; a"
    print -r -- "                      validator's self-bond is a transfer and is not sponsored."
    print -r -- "  --ref <git-ref>     branch or commit the FLEET builds.  Default: leave the"
    print -r -- "                      primary's checkout alone -- which builds whatever is on it,"
    print -r -- "                      not what is here.  Must be pushed to origin first."
    print -r -- "  --rebuild-chain     PURGE both fleet nodes and rebuild the chain first."
    print -r -- "                      Destroys every wallet and credential on them."
    print -r -- "  --advertise-ip-address <ip>         what the PRIMARY tells peers to dial"
    print -r -- "                                      (reaches init.sh).  Default: the ssh host."
    print -r -- "  --joiner <user@host>   REPEATABLE.  Overrides the site's joiners entirely (the"
    print -r -- "                      first --joiner replaces the list, later ones add to it), so"
    print -r -- "                      a site with three joiners and one --joiner runs with one."
    print -r -- "  --joiner-advertise-ip-address <ip>   what each JOINER advertises (reaches"
    print -r -- "                                      add_full_node.sh).  REPEATABLE: one per"
    print -r -- "                                      --joiner in the same order, or one for all"
    print -r -- "                                      of them.  Default: the ssh host."
    print -r -- "  --launch-dir <dir>  the foundation's directory (default ~/fleet-launch).  Created"
    print -r -- "                      by the bootstrap stage if absent -- keys, sealed mnemonics,"
    print -r -- "                      addresses.csv and the rendered launch config."
    print -r -- "  --sgx 0|1           0 (default) builds a DEBUG enclave via --no-build-sgx;"
    print -r -- "                      1 lets the bringup probe the host.  Omitting --build-sgx is"
    print -r -- "                      NOT the same as --no-sgx: build.sh defaults to SGX wherever"
    print -r -- "                      ego is installed, devices or not."
    print -r -- "  --joiner-validator 0|1"
    print -r -- "                      1 (default) bonds each joiner so it counts toward quorum;"
    print -r -- "                      0 leaves them as full nodes -- they sync and serve RPC but"
    print -r -- "                      never vote, making the primary the only validator."
    print -r -- "  --chain-id <id>     for the rendered config (default qadena_4824-1).  Only used"
    print -r -- "                      when bootstrap has to create it."
    print -r -- "  --skip-app          stop after verify; do not touch the app-server stack"
    print -r -- "  --env-file <path>   FULL PATH to the stack's env file.  Its directory is taken"
    print -r -- "                      as the stack (compose.yml and the Makefile live beside it)."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --passfile)      PASSFILE="$2"; shift 2 ;;
        --node)          NODE="$2"; NODE_EXPLICIT=1; shift 2 ;;
        --count)         COUNT="$2"; shift 2 ;;
        --coord-home)    COORD_HOME="$2"; shift 2 ;;
        --sec-home)      SEC_HOME="$2"; shift 2 ;;
        --from)          FROM="$2"; shift 2 ;;
        --until)         UNTIL="$2"; shift 2 ;;
        --cloud-formation-template) CF_TEMPLATE="$2"; shift 2 ;;
        --ref)           REF="$2"; shift 2 ;;
        --node-granter)  NODE_GRANTER="$2"; shift 2 ;;
        --site)          shift 2 ;;   # pre-scanned above
        --deployment)    shift 2 ;;   # pre-scanned above
        --rebuild-chain) REBUILD=1; shift ;;
        --skip-app)      SKIP_APP=1; shift ;;
        --launch-dir)    LAUNCH_DIR="$2"; shift 2 ;;
        --chain-id)      CHAIN_ID="$2"; shift 2 ;;
        --sgx)           SGX="$2"; shift 2 ;;
        --joiner-validator) JOINER_VALIDATOR="$2"; shift 2 ;;
        --env-file)      ENV_FILE="$2"; shift 2 ;;
        --primary)       PRIMARY="$2"; shift 2 ;;
        # What each node tells peers to dial.  Both default to the ssh host, which is wrong behind
        # NAT (public ssh address, private interface) and across networks.
        --advertise-ip-address)        ADVERTISE_P="$2"; shift 2 ;;
        # Repeatable too, one per --joiner in the same order (or one for all of them).
        --joiner-advertise-ip-address)
            (( _ADV_J_FROM_CLI )) || { ADVERTISE_JS=(); _ADV_J_FROM_CLI=1 }
            ADVERTISE_JS+=("$2"); ADVERTISE_J="${ADVERTISE_JS[1]}"; shift 2 ;;
        # REPEATABLE, AND THE FIRST ONE REPLACES THE SITE'S LIST rather than adding to it:
        # `--site SGX --joiner other` means "that joiner", not "the site's joiner and that one".
        --joiner)
            (( _JOINER_FROM_CLI )) || { JOINERS=(); _JOINER_FROM_CLI=1 }
            JOINERS+=("$2"); JOINER="${JOINERS[1]}"; shift 2 ;;
        --help|-h)       usage; exit 0 ;;
        *) print -u2 -- "unknown option: $1"; usage >&2; exit 1 ;;
    esac
done

# THE NODE FOLLOWS THE PRIMARY unless you say otherwise.  --primary already names the host the
# chain runs on, and the RPC is on it at 26657, so requiring --node too meant writing the same
# address twice and let them disagree -- a run that ssh'd to one machine and queried another would
# report a perfectly consistent chain that was not the one it just built.
#
# localhost is only right when there is no --primary at all, which is the single-box devnet case.
if [[ "$NODE_EXPLICIT" -eq 0 && -z "$NODE" ]]; then
    if [[ -n "$PRIMARY" ]]; then
        NODE="tcp://${PRIMARY##*@}:26657"
        print -r -- "node derived from --primary: $NODE"
    else
        NODE="tcp://localhost:26657"
    fi
fi

# MINT A PASSPHRASE FOR A GENUINELY FRESH SITE, AND ONLY THEN.
#
# A site whose keyring already exists has a passphrase that opens it; inventing a new one there
# produces a file that unseals nothing, and the failure arrives later as "too many failed
# passphrase attempts" against a keyring nobody can recover -- exactly the ekycph collision of
# 2026-09-10.  So this is gated on the launch directory holding NO coordinator keyring and NO
# sealed mnemonics: if either exists, a passphrase was already chosen and must be supplied.
if [[ -n "$PASSFILE" && ! -e "$PASSFILE" ]]; then
    _has_state=0
    [[ -d "$LAUNCH_DIR/coord/keyring-file" ]] && _has_state=1
    # (N) -- the NULL_GLOB qualifier.  A non-matching glob is a SHELL error in zsh ("no matches
    # found"), raised before the command runs, so `2>/dev/null` on the command cannot suppress it
    # and the operator sees a spurious error on every fresh site.
    _mn=("$LAUNCH_DIR"/mnemonics/*.mnemonic.enc(N))
    (( ${#_mn} )) && _has_state=1
    if (( _has_state )); then
        print -u2 -- "$PASSFILE is missing, but $LAUNCH_DIR already holds a keyring or sealed"
        print -u2 -- "mnemonics -- they were sealed under a passphrase this run cannot guess."
        print -u2 -- "Restore the passphrase file, or point --passfile at it."
        exit 1
    fi
    mkdir -p "${PASSFILE:h}"
    # Alphanumeric only.  The passphrase is fed down pipes, embedded in ssh command strings and
    # written into heredocs all over this toolchain; a quote or a backslash in it would break in a
    # different place each time.  40 chars of [A-Za-z0-9] is ~238 bits, so the restriction costs
    # nothing.
    LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 40 > "$PASSFILE"
    print -r -- "" >> "$PASSFILE"
    chmod 600 "$PASSFILE"
    print -r -- "generated a new keyring passphrase for site '$SITE' -> $PASSFILE"
    print -r -- "  IT IS THE ONLY COPY.  Everything this run seals -- the coordinator keyring and"
    print -r -- "  every sealed mnemonic -- is recoverable only with it.  Back it up now."
fi

[[ -n "$PASSFILE" && -r "$PASSFILE" ]] || { print -u2 "need a readable --passfile"; usage >&2; exit 1 }

# CHECK THE TEMPLATE PATH NOW, NOT IN THE app STAGE.  The cfn patch runs AFTER patch_env_file, so
# a typo'd path discovered there costs a half-applied app stage: env file rewritten, SSM not.
# Checked here it costs nothing, and a wrong --site or a moved file is named before the run starts.
if [[ -n "$CF_TEMPLATE" && ! -f "$CF_TEMPLATE" ]]; then
    print -u2 -- "--cloud-formation-template $CF_TEMPLATE does not exist"
    exit 1
fi
export QADENA_NODE="$NODE"
export QADENA_KEYRING_PASSFILE="$PASSFILE"

# STAGE ORDER, and the gate that lets --from skip forward.
STAGES=(bootstrap prepare step1 delegate step2 approve step3 pool verify app)
_stage_index() { local i=1; for s in "${STAGES[@]}"; do [[ "$s" == "$1" ]] && { print -r -- $i; return }; i=$(( i + 1 )); done; print -r -- 0 }
START=$(_stage_index "$FROM")
(( START > 0 )) || { print -u2 "unknown --from stage '$FROM'"; exit 1 }
# --until STOPS AFTER the named stage, so a chain can be built and the ceremony driven by hand.
# Defaults to the last stage, which is the old behaviour exactly.
if [[ -n "$UNTIL" ]]; then
    END=$(_stage_index "$UNTIL")
    (( END > 0 )) || { print -u2 "unknown --until stage '$UNTIL'"; exit 1 }
    # `print -u2 --` : the message STARTS with "--until", and print parses -u out of the string
    # itself without the -- terminator ("number expected after -u").
    (( END >= START )) || { print -u2 -- "--until $UNTIL comes before --from $FROM"; exit 1 }
else
    END=${#STAGES}
fi
# NOT GATED: --rebuild-chain is a standalone block, not a stage, so it still runs when asked for.
# That is deliberate -- "--rebuild-chain --until bootstrap" is how you get a built, running chain
# and nothing else.
_want() { local i=$(_stage_index "$1"); (( i >= START && i <= END )) }

banner() {
    print -r -- ""
    print -r -- "==========================================================================="
    print -r -- ">>> $1"
    print -r -- "==========================================================================="
}

# EVERY STAGE'S FAILURE IS ATTRIBUTED.  A bare `set -e` death in the middle of eight scripts tells
# you nothing about which one, and the underlying scripts print a lot.
# $0 INSIDE A FUNCTION IS THE FUNCTION'S NAME in zsh, so the resume hint printed
# "_on_exit --passfile ..." -- a command that does not exist.  Capture the script path here.
_SELF="${0:A}"
_CURRENT="startup"
_on_exit() {
    local rc=$?
    (( rc == 0 )) && return 0
    print -u2 -- ""
    print -u2 -- "==========================================================================="
    print -u2 -- "FAILED in stage: $_CURRENT   (exit $rc)"
    print -u2 -- "  resume from here once fixed:"
    # ONLY SUGGEST A COMMAND THAT RUNS.  `rebuild` is not in STAGES -- it is a standalone block
    # guarded by --rebuild-chain -- so a failure there printed "--from rebuild", which the very
    # next run rejects with "unknown --from stage 'rebuild'".  A resume hint that does not resume
    # is worse than none: it is read as the answer and costs a cycle to disprove.
    if (( $(_stage_index "$_CURRENT") > 0 )); then
        print -u2 -- "      $_SELF --passfile $PASSFILE --node $NODE --count $COUNT --from $_CURRENT"
    else
        print -u2 -- "      $_SELF --passfile $PASSFILE --node $NODE --count $COUNT \\"
        print -u2 -- "          --rebuild-chain --ref <branch>"
        print -u2 -- "  NOTE: '$_CURRENT' is not a resumable stage -- it is the --rebuild-chain block,"
        print -u2 -- "  which runs before them and PURGES BOTH NODES again.  If the primary built and"
        print -u2 -- "  only the joiner failed, resume the join instead, without rebuilding"
        print -u2 -- "  (one command per joiner; this site has ${#JOINERS}):"
        print -u2 -- "      testscripts/nth_node_bringup.sh --primary $PRIMARY --joiner ${JOINER:-<joiner>} \\"
        print -u2 -- "          --pioneer <name> --from 3 --keyring-passfile $PASSFILE"
    fi
    print -u2 -- "==========================================================================="
    return $rc
}
trap _on_exit EXIT

cd "$REPO"


# --------------------------------------------------------------------------------------------
if _want bootstrap; then
    _CURRENT="bootstrap"
    # CREATE THE FOUNDATION'S SIDE IF IT IS NOT THERE.
    #
    # ~/fleet-launch holds four things the bring-up cannot run without: the coordinator keyring,
    # the sealed mnemonics, addresses.csv, and the rendered launch config.  On a fresh machine none
    # of it exists, and the failure without it arrives deep inside the chain build as a missing
    # file -- so check here, where the message can say what to do.
    #
    # Each piece is created only if MISSING.  derive_launch_keys.sh mints keys, and re-minting them
    # would change every bucket address in genesis, so it must never run against an existing
    # keyring by accident.
    _need_keys=0; _need_cfg=0
    [[ -d "$LAUNCH_DIR/coord" ]] && ls "$LAUNCH_DIR"/mnemonics/*.mnemonic.enc > /dev/null 2>&1 || _need_keys=1
    # RE-RENDER WHEN THE SOURCE HAS MOVED, not only when the rendered file is absent.
    #
    # This tested for existence alone, so a launch config rendered before a change to
    # config/launch-config.yml was reused forever.  That is not a stale comment -- it is how a fleet
    # got built with an UNENCRYPTED node keyring after keyring-backend: "file" was added to the
    # source: the rendered instance predated it, the primary came up with keyring-test, and nothing
    # said so.  Genesis is built from the rendered file, so a stale one is a wrong chain.
    #
    # Mtime, not content: the rendered file is a transformation of the source (addresses, enclave
    # ids), so it is never equal to it and only "newer than" is meaningful.
    if [[ ! -r "$LAUNCH_DIR/fleet-launch-config.yml" ]]; then
        _need_cfg=1
    elif [[ config/launch-config.yml -nt "$LAUNCH_DIR/fleet-launch-config.yml" ]]; then
        _need_cfg=1
        print -r -- "  config/launch-config.yml is NEWER than the rendered instance -- re-rendering"
        print -r -- "    (a rendered config older than its source builds the previous chain's genesis)"
    fi

    if (( _need_keys || _need_cfg )); then
        banner "0. BOOTSTRAP the foundation directory ($LAUNCH_DIR)"
    fi

    if (( _need_keys )); then
        print -r -- "  minting the launch keys -- coordinator keyring, sealed mnemonics, addresses.csv"
        print -r -- "  (this is a ONE-TIME act: these addresses go into genesis and cannot change afterwards)"
        mkdir -p "$LAUNCH_DIR"
        foundation_scripts/derive_launch_keys.sh \
            --home          "$LAUNCH_DIR/coord" \
            --mnemonics-dir "$LAUNCH_DIR/mnemonics" \
            --out           "$LAUNCH_DIR/addresses.csv" \
            --passphrase-file "$PASSFILE"
    else
        print -r -- "  keys present: $(ls "$LAUNCH_DIR"/mnemonics/*.mnemonic.enc 2>/dev/null | wc -l | tr -d ' ') sealed mnemonic(s)"
    fi

    if (( _need_cfg )); then
        print -r -- "  rendering the launch config for $CHAIN_ID"
        # ENCLAVE IDS FIRST.  --enclave writes the TEMPLATE, so running it after --apply would
        # leave the instance carrying whatever the template held before.
        python3 foundation_scripts/fill_launch_config.py --enclave --test-fleet
        python3 foundation_scripts/fill_launch_config.py \
            --apply "$LAUNCH_DIR/addresses.csv" \
            --out   "$LAUNCH_DIR/fleet-launch-config.yml" \
            --chain-id "$CHAIN_ID" --test-gov-timings --zero-incentives
    else
        print -r -- "  launch config present: $LAUNCH_DIR/fleet-launch-config.yml"
    fi
fi

# --------------------------------------------------------------------------------------------
if (( REBUILD )); then
    _CURRENT="rebuild"
    banner "0. PURGE AND REBUILD THE CHAIN  (destroys everything on both nodes)"
    # SINGLE-NODE SITES PASS NO JOINER.  `--node ""` is not "no node": stop_fleet takes it as an
    # empty ssh target and the purge either fails or, worse, runs somewhere unintended.
    _stopn=(--node "$PRIMARY"); for _j in "${JOINERS[@]}"; do _stopn+=(--node "$_j"); done
    ./testscripts/stop_fleet.sh "${_stopn[@]}" \
        --purge --reap-archives --immediate
    # SAY WHAT IS BEING DESTROYED, AND REFUSE IF IT BELONGS TO ANOTHER CHAIN.
    #
    # This is an unrecoverable delete: mnemonics.json (or the sealed mnemonics) and the keyring are
    # the only copies of every SEC key, and the wallets they control stay on chain afterwards with
    # nobody able to sign for them.  It ran silently, and when the staging script shared this path
    # with the local one it destroyed a working deployment on the way to rebuilding a different
    # chain.  variables.json records which sponsor -- and therefore which chain -- this home
    # belongs to, so a mismatch is detectable rather than merely regrettable.
    if [[ -d "$SEC_HOME" ]]; then
        _existing=$(jq -r '.appsvraddr // empty' "$SEC_HOME/variables.json" 2>/dev/null || true)
        _keys=$(ls "$SEC_HOME"/keyring/keyring-*/*.info 2>/dev/null | wc -l | tr -d ' ')
        print -r -- "  about to DELETE $SEC_HOME ($_keys key(s)${_existing:+, sponsor ${_existing:0:16}...})"
        if [[ -n "$_existing" && -r "$COORD_HOME/$DEPLOY_STATE_FILE" ]]; then
            _target=$(jq -r '.appsvr // empty' "$COORD_HOME/$DEPLOY_STATE_FILE" 2>/dev/null || true)
            if [[ -n "$_target" && "$_existing" != "$_target" ]]; then
                print -u2 "REFUSING: $SEC_HOME belongs to a DIFFERENT deployment."
                print -u2 "  its sponsor:   $_existing"
                print -u2 "  this run's:    $_target"
                print -u2 "  Deleting it would strand wallets on that chain with no keys."
                print -u2 "  Use --sec-home <dir> for this deployment, or remove it deliberately."
                exit 1
            fi
        fi
        rm -rf "$SEC_HOME"
        print -r -- "  deleted $SEC_HOME"
    fi
    # The pioneer mnemonic must be in the clear for the bringup; unseal it here and remove it the
    # moment the chain is up -- it is the genesis validator's key.
    # UNSEAL PROPERLY, OR NOT AT ALL.
    #
    # Three things went wrong here at once (2026-09-07): mnemonic.sh show PROMPTS for the sealing
    # passphrase and nothing fed it; the `>` redirect had already created the file, so the failure
    # left it EMPTY; and `[[ ! -r ]]` accepts an empty file, so every retry reused it.  The bringup
    # then ran `--pioneer-mnemonic "$(cat <empty>)"` and init.sh answered "requires the mnemonic in
    # quotes" -- a message about quoting, three layers from a passphrase that was never supplied.
    #
    # Write to a temp, CHECK IT IS A MNEMONIC, and only then put it in place.
    # THE SEALED FILE GOES OVER, NOT THE WORDS.  init.sh takes --pioneer-mnemonic-enc and opens it
    # in-process with the --keyring-passfile passphrase (the same one that sealed it), which
    # 1st_node_bringup.sh detects by the openssl "Salted__" magic.  Nothing is unsealed on this
    # machine, nothing plaintext is copied to the primary, and the words never reach the primary's
    # process table or its run log -- all three of which happened while this unsealed first.
    #
    # The unseal below is kept ONLY as the fallback for a launch dir that has no sealed file.
    _pm_enc="$LAUNCH_DIR/mnemonics/qfi-pioneer1.mnemonic.enc"
    if [[ -r "$_pm_enc" ]]; then
        _pm="$_pm_enc"
        print -r -- "  passing the SEALED pioneer mnemonic to the bringup (never unsealed here)"
    else
        _pm="$LAUNCH_DIR/pioneer-mnemonic.txt"
        if [[ ! -s "$_pm" ]] || (( $(wc -w < "$_pm") < 12 )); then
            umask 077
            _tmp=$(mktemp)
            if ! print -r -- "$(head -1 "$PASSFILE")" \
                  | foundation_scripts/mnemonic.sh show "$LAUNCH_DIR/mnemonics" qfi-pioneer1 > "$_tmp" 2>/dev/null; then
                rm -f "$_tmp"
                print -u2 "could not unseal qfi-pioneer1 from $HOME/fleet-launch/mnemonics"
                print -u2 "  the sealing passphrase is the one in $PASSFILE -- is it right?"
                exit 1
            fi
            _wc=$(wc -w < "$_tmp" | tr -d ' ')
            if [[ "$_wc" != "12" && "$_wc" != "24" ]]; then
                rm -f "$_tmp"
                print -u2 "unsealed $_wc words, which is not a mnemonic -- refusing to build a chain with it"
                exit 1
            fi
            mv "$_tmp" "$_pm"; chmod 600 "$_pm"
            print -r -- "  unsealed the pioneer mnemonic ($_wc words) for the bringup"
        fi
    fi
    # SGX=0 -> --no-build-sgx (which reaches build.sh as --no-sgx).  SGX=1 -> pass nothing and let
    # the bringup detect what the host can actually do.
    _sgx=()
    [[ "$SGX" == "0" ]] && _sgx=(--no-build-sgx)
    _jv=()
    [[ "$JOINER_VALIDATOR" == "0" ]] && _jv=(--no-convert-joiners)
    _adv=()
    [[ -n "$ADVERTISE_P" ]] && _adv+=(--advertise-ip-address "$ADVERTISE_P")
    for _a in "${ADVERTISE_JS[@]}"; do _adv+=(--joiner-advertise-ip-address "$_a"); done
    # ONE PASSPHRASE FOR THE WHOLE RUN.  $PASSFILE already unlocks the coordinator keyring and
    # SEC's; passing it here makes it the NODE keyring's too, once config.yml asks for
    # keyring-backend: file.  Same file, so they cannot drift -- and a fleet whose nodes need a
    # different passphrase from the operator running the bring-up is a fleet nobody can restart.
    # NODE-SPONSORED, matching the deployment.  Without --foundation-sponsored the joiner is SENT
    # 10,100 QDN -- the transfer the sponsored model exists to avoid -- and the bring-up says so in
    # a "MODE: NOT SPONSORED" banner.  With it, the joiner is never sent operating coins: it gets a
    # bounded, recurring fee grant from $NODE_GRANTER covering the messages a node broadcasts for
    # life (join, SS rotation, SS re-share).  A bucket name is a MULTISIG, so each join runs a
    # ceremony here, where the bucket keys are.
    #
    # --stake STAYS.  A validator's self-bond is not sponsorable: those tokens become the node's
    # own, they are what gets bonded, and slashing burns them.  ensure_self_bond delivers them as a
    # transfer.  It is only paid when the joiner is being converted to a validator.
    _ref=(); [[ -n "$REF" ]] && _ref=(--ref "$REF")
    # fleet_bringup_with_tests keeps joiners in an ARRAY and reports "<none>" for an empty one, so
    # a single-node site just does not pass the flag.  Passing --joiner "" would append an empty
    # entry and every per-joiner loop would run once against nothing.
    _jn=(); for _j in "${JOINERS[@]}"; do _jn+=(--joiner "$_j"); done
    ./testscripts/fleet_bringup_with_tests.sh \
        --primary "$PRIMARY" "${_jn[@]}" --block-sync "${_sgx[@]}" "${_jv[@]}" "${_adv[@]}" "${_ref[@]}" \
        --mainnet-source        "$LAUNCH_DIR/fleet-launch-config.yml" \
        --pioneer-mnemonic-file "$_pm" \
        --keyring-passfile      "$PASSFILE" \
        --coord-home            "$COORD_HOME" \
        --foundation-sponsored "$NODE_GRANTER" --stake 10000
    # ONLY THE PLAINTEXT FALLBACK IS DELETED.  $_pm is now usually the SEALED
    # mnemonics/qfi-pioneer1.mnemonic.enc, which is the authoritative copy of the genesis
    # validator's key and the only one outside the node keyrings -- deleting it would make that
    # validator unrecoverable.
    [[ "$_pm" == *.mnemonic.enc ]] || rm -f "$_pm"
fi

# --------------------------------------------------------------------------------------------
if _want prepare; then
    _CURRENT="prepare"
    banner "1. FOUNDATION: fund and stake the two sponsors"
    # pubsec is 5-of-7 on this fleet and foundation is 3-of-5; the member lists are a local naming
    # convention, not something the chain knows, so they have to be named.
    foundation_scripts/sec_veritas_before_step_1.sh --deployment "$DEPLOY_NAME" --stage prepare \
        --coord-home "$COORD_HOME" --keyring-passfile "$PASSFILE" \
        --mnemonics-dir "$LAUNCH_DIR/mnemonics" --node "$NODE" \
        --fund-members "$DEPLOY_FUND_MEMBERS" \
        --members "$DEPLOY_STAKE_MEMBERS"
fi

# GATED ON A CONSUMER, NOT UNCONDITIONAL.  These three prerequisite checks sit BETWEEN stages and
# used to run whatever --from/--until asked for, so `--rebuild-chain --until bootstrap` built the
# chain correctly and then died on "run the prepare stage first" -- reporting FAILED in stage
# rebuild for a rebuild that had succeeded.  A prerequisite belongs to the stage that reads it.
_sponsors="$COORD_HOME/$DEPLOY_STATE_FILE"
APPSVR=""; USERS=""
if _want step1 || _want delegate || _want step2 || _want approve || _want step3 || _want pool; then
    [[ -r "$_sponsors" ]] || { print -u2 "no $_sponsors -- run the prepare stage first"; exit 1 }
    APPSVR=$(jq -r '.appsvr' "$_sponsors")
    USERS=$(jq -r '.users'  "$_sponsors")
fi

# --------------------------------------------------------------------------------------------
if _want step1; then
    _CURRENT="step1"
    banner "2. $DEPLOY_DISPLAY: mint keys, derive every wallet address, emit the pre-grant block"
    veritas_scripts/step_1.sh --deployment "$DEPLOY_NAME" --count "$COUNT" \
        --appsvr "$APPSVR" --users "$USERS" \
        --node "$NODE" --sec-home "$SEC_HOME" --keyring-passfile "$PASSFILE"
fi

PREGRANT="$SEC_HOME/pregrant_addresses.json"
if _want delegate || _want step2 || _want approve || _want step3 || _want pool || _want verify; then
    [[ -r "$PREGRANT" ]] || { print -u2 "no $PREGRANT -- step_1 did not complete"; exit 1 }
fi

# --------------------------------------------------------------------------------------------
if _want delegate; then
    _CURRENT="delegate"
    banner "3. FOUNDATION: delegate the three authorities, pre-grant every wallet"
    foundation_scripts/sec_veritas_after_step_1.sh --deployment "$DEPLOY_NAME" --pregrant "$PREGRANT" \
        --coord-home "$COORD_HOME" --keyring-passfile "$PASSFILE" --node "$NODE"
fi

# --------------------------------------------------------------------------------------------
if _want step2; then
    _CURRENT="step2"
    banner "4. $DEPLOY_DISPLAY: create the service providers, submit their proposals"
    veritas_scripts/step_2.sh --deployment "$DEPLOY_NAME" --node "$NODE" --sec-home "$SEC_HOME" --keyring-passfile "$PASSFILE"
fi

# THE IDS COME FROM THE FILES step_2 WROTE, and it overwrites them every run -- so read them HERE,
# immediately after, rather than trusting a value carried from an earlier invocation.
_pdir="$REPO/provider_scripts/proposals"
IDENTITY_PID=$(cat "$_pdir/$DEPLOY_IDENTITY_PRV.proposal_id" 2>/dev/null || true)
DSVS_PID=$(cat "$_pdir/$DEPLOY_DSVS_PRV.proposal_id" 2>/dev/null || true)

# --------------------------------------------------------------------------------------------
if _want approve; then
    _CURRENT="approve"
    banner "5. FOUNDATION: deposit and vote on proposals $IDENTITY_PID $DSVS_PID"
    # after_step_2 verifies each id IS a service-provider proposal and skips ones already decided,
    # so a re-run costs nothing and cannot deposit on somebody else's proposal.
    if [[ -n "$IDENTITY_PID" && -n "$DSVS_PID" ]]; then
        foundation_scripts/sec_veritas_after_step_2.sh --deployment "$DEPLOY_NAME" "$IDENTITY_PID" "$DSVS_PID" \
            --coord-home "$COORD_HOME" --keyring-passfile "$PASSFILE" --node "$NODE" \
            --members "$DEPLOY_STAKE_MEMBERS"
    else
        print -r -- "  no proposal ids on file -- assuming the providers are already registered"
    fi

    banner "5b. WAIT for both providers to be REGISTERED (not merely voted)"
    # A vote is not a result: the provider is registered when the proposal EXECUTES, and step_3
    # creates wallets that need the providers to exist.  Poll the registration itself rather than
    # the proposal, because a re-run's proposal id may be a duplicate that will never pass.
    for _p in "$DEPLOY_IDENTITY_PRV" "$DEPLOY_DSVS_PRV"; do
        _n=0
        while (( _n < 60 )); do
            _id=$("$HOME/qadena/bin/qadenad" --home "${QADENAHOME:-$HOME/qadena}" \
                    query qadena list-interval-public-key-id --node "$NODE" --output json 2>/dev/null \
                    | jq -r --arg n "$_p" '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID' 2>/dev/null)
            if [[ -n "$_id" ]]; then print -r -- "  $_p registered"; break; fi
            _n=$(( _n + 1 )); sleep 5
        done
        [[ -n "${_id:-}" ]] || { print -u2 "  $_p never registered after 5 minutes"; exit 1 }
    done
fi

# --------------------------------------------------------------------------------------------
if _want step3; then
    _CURRENT="step3"
    banner "6. $DEPLOY_DISPLAY: create the sponsor pool and the DSVS user, claim credentials"
    veritas_scripts/step_3.sh --deployment "$DEPLOY_NAME" --node "$NODE" --sec-home "$SEC_HOME" --keyring-passfile "$PASSFILE"
fi

POOL="$SEC_HOME/pool_addresses.json"

# --------------------------------------------------------------------------------------------
if _want pool; then
    _CURRENT="pool"
    banner "7. FOUNDATION: authorise the sponsor pool"
    [[ -r "$POOL" ]] || { print -u2 "no $POOL -- step_3 did not complete"; exit 1 }
    foundation_scripts/sec_veritas_after_step_3.sh --deployment "$DEPLOY_NAME" --pool-addresses "$POOL" \
        --coord-home "$COORD_HOME" --keyring-passfile "$PASSFILE" --node "$NODE"
fi

# --------------------------------------------------------------------------------------------
if _want verify; then
    _CURRENT="verify"
    banner "8. VERIFY the whole deployment against the chain"
    # A NON-ZERO EXIT HERE STOPS THE RUN, deliberately -- the app stage below would otherwise
    # deploy an app-server against a chain that cannot serve it.  Three of the verifier's checks
    # exist because they were ALL absent on 2026-09-07 while every other check passed: wallets
    # existing at all, providers holding a transaction pubkey, and secdsvs having an authorized
    # signatory.  Without those, onboarding fails at a query and SEC cannot counter-sign, and
    # nothing before this point would have said so.
    # Read-only.  Fails on anything the bring-up was supposed to establish and did not -- including
    # the three that used to pass vacuously: wallets existing, providers holding keys, and SEC
    # being able to counter-sign.
    # AN ARRAY, NOT ${VAR:+...}.  zsh does not word-split an unquoted parameter expansion, so
    # `${POOL:+--pool "$POOL"}` reaches the script as ONE argument -- "--pool /path" -- and it
    # answers "unknown option: --pool /path", which reads like a missing flag rather than a
    # quoting bug.  Measured 2026-09-07 at the end of a full bring-up.
    _vargs=(--deployment "$DEPLOY_NAME" --coord-home "$COORD_HOME" --node "$NODE" --pregrant "$PREGRANT")
    [[ -r "$POOL" ]] && _vargs+=(--pool "$POOL")
    foundation_scripts/sec_veritas_verify.sh "${_vargs[@]}"
fi

# --------------------------------------------------------------------------------------------
if (( SKIP_APP )) || ! _want app; then
    print -r -- ""
    print -r -- "VERITAS bring-up complete.  App-server stage skipped."
    exit 0
fi

_CURRENT="app"
banner "9. APP-SERVER: patch the env, install it, restart the stack"

# THE .base64 FILES MUST BE THIS RUN'S.  step_3 regenerates them via extract_ephem_keys, writing to
# the REPO ROOT (its cwd).  Stale ones from a previous deployment decode cleanly and name wallets
# that do not exist on this chain -- a failure that surfaces much later as a signing error, so
# check they are newer than step_3's own output rather than merely present.
# The stack is the env file's directory.  Checked together so a wrong --env-file cannot half-run.
ENV_FILE="${ENV_FILE:A}"
STACK="${ENV_FILE:h}"
[[ -f "$ENV_FILE" ]] || { print -u2 "no env file at $ENV_FILE"; exit 1 }
[[ -f "$STACK/compose.yml" ]] || { print -u2 "no compose.yml beside $ENV_FILE -- is $STACK the stack?"; exit 1 }
# STEP_3 NOW WRITES THEM INTO THE DEPLOYMENT HOME.  The repo root is still accepted so that an
# older run's files, or a by-hand extract_ephem_keys with no --out-dir, are still found -- but the
# home wins, because it is the only one of the two that cannot belong to a different site.
_b64dir="$SEC_HOME"
_n=$(ls "$_b64dir"/${PREFIX}*-names.base64 2>/dev/null | wc -l | tr -d ' ')
if (( _n == 0 )); then
    _b64dir="$REPO"
    _n=$(ls "$_b64dir"/${PREFIX}*-names.base64 2>/dev/null | wc -l | tr -d ' ')
    (( _n > 0 )) && print -r -- "  using .base64 files from $REPO (pre-dating --out-dir)"
fi
(( _n > 0 )) || { print -u2 "no ${PREFIX}*.base64 files in $SEC_HOME or $REPO -- did step_3 run?"; exit 1 }
# ARE THESE KEYS FROM THIS DEPLOYMENT?  Not "are they recent" -- my first version compared mtimes
# against the pool file and was backwards by construction: step_3 writes the .base64 files (line
# ~494) BEFORE the pool block (line ~514), two seconds apart, so a correct run always failed it.
#
# Timestamps cannot answer this anyway.  The honest test is whether the keys these files carry are
# the ones on the CURRENT chain: SEC's keys are re-minted every deployment, so an address from a
# previous one will not appear in this run's pool file.  Decode a name, resolve it, compare.
_check_name=$(base64 -d < "$_b64dir/${PREFIX}-create-wallet-sponsor-names.base64" 2>/dev/null \
                | jq -r '.[0] // empty' 2>/dev/null)
if [[ -n "$_check_name" ]] && [[ -r "$POOL" ]]; then
    _check_addr=$("$HOME/qadena/bin/qadenad" --home "${QADENAHOME:-$HOME/qadena}" \
                    --keyring-dir "$SEC_HOME/keyring" --keyring-backend file \
                    keys show "$_check_name" --address 2>/dev/null < "$PASSFILE" | tail -1)
    if [[ -n "$_check_addr" ]] && ! grep -qF "$_check_addr" "$POOL"; then
        print -u2 "the .base64 files are from a DIFFERENT deployment."
        print -u2 "  $_check_name resolves to $_check_addr, which is not in $POOL."
        print -u2 "  Re-run step_3, or regenerate them with testscripts/extract_ephem_keys.sh."
        exit 1
    fi
    print -r -- "  key files verified against this deployment ($_check_name)"
fi

# --armor-passfile IS NOT OPTIONAL HERE.  The keys in the block below are armored with the KEYRING
# passphrase (extract_ephem_keys exports through qadenad_alias, which supplies its own stdin), so
# the app-server's ARMOR_PASS_PHRASE has to be that same value.  Patching the keys and leaving the
# old passphrase produces an app that starts, fails to import every key, and exits 1 in a restart
# loop -- reporting "Failed to import private key for <name>:" with an EMPTY reason.  Measured
# 2026-09-07.  Same passfile as the rest of the run, so they cannot drift.
./testscripts/patch_env_file.sh "$PREFIX" "$ENV_FILE" \
    --key-dir "$_b64dir" --sponsors "$_sponsors" --armor-passfile "$PASSFILE"

# THE SAME VALUES INTO CLOUDFORMATION, WHEN THERE IS ONE.  An AWS-deployed site reads its config
# from SSM rather than from .env, so patching only the env file leaves it running the PREVIOUS
# bring-up's keys -- which is not a failure, it is a deployment quietly signing as the wrong
# wallets.  Both patchers share gen_key_env_vars.sh, so the two targets cannot disagree.
#
# OPTIONAL BY DESIGN: the local and staging fleets have no template, and demanding one would
# block every run that does not deploy to AWS.
if [[ -n "$CF_TEMPLATE" ]]; then
    # Re-checked: the path was validated at startup, so reaching this means the file went away
    # DURING the run.  Loud either way -- reporting DONE for a deployment whose SSM parameters were
    # never written is the outcome worth preventing.
    if [[ ! -f "$CF_TEMPLATE" ]]; then
        print -u2 -- "$CF_TEMPLATE disappeared during the run"
        print -u2 -- "  the env file IS patched; re-run --from app once the path is right."
        exit 1
    fi
    print -r -- ""
    print -r -- "  patching CloudFormation template ${CF_TEMPLATE:t}"
    ./veritas_scripts/patch_cloud_formation_template.sh "$PREFIX" "$CF_TEMPLATE" \
        --key-dir "$_b64dir" --sponsors "$_sponsors" --armor-passfile "$PASSFILE"
fi

# .env IS WHAT compose READS (env_file: .env in compose.yml).  The stack keeps several env files
# for different targets; installing the one we just patched is a deliberate copy, not a symlink,
# so the source stays readable as the record of what was deployed.
cp "$ENV_FILE" "$STACK/.env"
chmod 600 "$STACK/.env"
print -r -- "  installed ${ENV_FILE:t} -> $STACK/.env"

print -r -- ""
print -r -- "==========================================================================="
print -r -- "DONE.  chain $NODE"
print -r -- "  foundation-appsvr $APPSVR"
print -r -- "  foundation-users  $USERS"
print -r -- ""
[[ -n "$CF_TEMPLATE" ]] && print -r -- "  cfn:        $CF_TEMPLATE  (contains private keys -- do not commit)"
print -r -- "  app logs:   make -C $STACK logs-api"
print -r -- "  re-verify:  foundation_scripts/sec_veritas_verify.sh --deployment $DEPLOY_NAME --coord-home $COORD_HOME --node $NODE"
print -r -- "==========================================================================="
