#!/bin/zsh
#
# A whole deployment bring-up on a DEVNET, end to end, with the app-server stage that consumes it.
#
#   ./testscripts/ekycph_full_setup.sh --from setup
#   ./testscripts/enf_full_setup.sh --from setup --until verify
#
# WHAT THIS IS FOR.  testscripts/veritas_full_setup.sh does this for VERITAS against a launch
# FLEET, where every foundation spend is a multisig ceremony against a coordinator keyring.  This is
# the DEVNET counterpart for the other deployments: one box, one keyring, one chain, `treasury` a
# single key the primary holds.  The stage names line up with the fleet script's on purpose, so a
# procedure learned on one reads on the other.
#
# NOT A LAUNCH-CHAIN SCRIPT.  It funds by `tx bank send --from treasury`, which no launch chain has.
# The production path for these deployments is foundation_scripts/<name>_before_step_1.sh and
# friends -- see docs/HOWTO-SPONSOR-DEPLOYMENT.md.
#
# RESUMABLE, AND THAT IS THE POINT.  --from <stage> starts at a named stage and --until <stage>
# stops after one; every underlying script is individually idempotent (keys, wallets, claims and
# grants are all checked against the CHAIN before being created), so re-running a completed stage is
# safe.  The build stage is FIRST and separate precisely so it can be skipped:
#
#     --from setup            skip build and chain, go straight at the deployment
#     --from base --until verify   everything but the app-server
#
# STAGES
#   build     compile the chain and re-init it.  DESTRUCTIVE -- see the guard below.
#   chain     start the node and wait for it to produce blocks
#   base      stake the pioneer; create and fund the two foundation sponsor accounts
#   setup     the deployment itself: steps 1-3 and the sponsor pool (setup_<name>.sh)
#   verify    the 15 gating checks against the chain
#   app       write the env file and restart the app-server stack
#
# WHY `base` IS SEPARATE FROM `setup`.  The pioneer stake and the two sponsor accounts are shared by
# every deployment on the devnet and are already-done on any chain that has run one.  Splitting them
# out means the second and third deployment skip straight to `setup` instead of re-running work that
# is idempotent but slow.

set -e
set -u

SCRIPT_DIR="${0:A:h}"
REPO="${SCRIPT_DIR:h}"

# $0 IS THE FUNCTION'S NAME INSIDE A ZSH FUNCTION, so usage() and the resume hint below would print
# "Usage: usage [...]" and "run _on_exit --from step3".  Captured here, at the top level, where it
# is still the script.  Both of those have been printed for real.
_SELF="${QADENA_PROG:-${0:A}}"

DEPLOYMENT="${DEPLOYMENT:-}"
FROM="build"
UNTIL=""
NODE="${QADENA_NODE:-tcp://localhost:26657}"
COUNT="${VERITAS_COUNT:-2}"
PIONEER="${QADENA_PIONEER:-pioneer1}"
FUND_MODE="foundation-sponsored"
ALLOW_BUILD=0
KEYRING_PASSFILE="$HOME/fleet-launch-password"
ENV_FILE=""
EXTRA=()

usage() {
    print -r -- "Usage: $_SELF [--from <stage>] [--until <stage>] [options]"
    print -r -- ""
    print -r -- "  --deployment <name>  which programme (required unless the wrapper set it)"
    print -r -- "  --from <stage>       start here.  build|chain|base|setup|verify|app"
    print -r -- "                       Default build.  Use --from setup to skip the build."
    print -r -- "  --until <stage>      stop after this stage (default: run to the end)"
    print -r -- "  --node <rpc>         default \$QADENA_NODE or tcp://localhost:26657"
    print -r -- "  --count <n>          sponsor pool size, default $COUNT"
    print -r -- "  --pioneer <name>     genesis validator, default $PIONEER"
    print -r -- "  --fund-mode <m>      foundation-sponsored (default) | banksend"
    print -r -- "  --env-file <path>    FULL path to the app-server env file for the app stage"
    print -r -- "  --keyring-passfile <f>  the NODE keyring's passphrase.  Required once the chain"
    print -r -- "                       is built with keyring-backend: file -- detected from the"
    print -r -- "                       node's client.toml, so you are told rather than guessing."
    print -r -- "  --allow-build        REQUIRED to run the build stage.  Without it, --from build"
    print -r -- "                       refuses: the build re-inits the chain and destroys every"
    print -r -- "                       wallet, credential and grant on it."
    print -r -- "  --                   everything after is passed through to setup_<name>.sh"
    exit ${1:-1}
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deployment)  DEPLOYMENT="$2"; shift 2 ;;
        --from)        FROM="$2"; shift 2 ;;
        --until)       UNTIL="$2"; shift 2 ;;
        --node)        NODE="$2"; shift 2 ;;
        --count)       COUNT="$2"; shift 2 ;;
        --pioneer)     PIONEER="$2"; shift 2 ;;
        --fund-mode)   FUND_MODE="$2"; shift 2 ;;
        --env-file)    ENV_FILE="$2"; shift 2 ;;
        --keyring-passfile) KEYRING_PASSFILE="$2"; shift 2 ;;
        --allow-build) ALLOW_BUILD=1; shift ;;
        --)            shift; EXTRA=("$@"); break ;;
        --help|-h)     usage 0 ;;
        *)             print -u2 -- "unknown option: $1"; usage ;;
    esac
done

[[ -n "$DEPLOYMENT" ]] || { print -u2 -- "--deployment is required"; usage }

case "$FUND_MODE" in
    foundation-sponsored|banksend) ;;
    *) print -u2 -- "unknown --fund-mode '$FUND_MODE' (foundation-sponsored | banksend)"; exit 1 ;;
esac

# The profile validates the deployment name and gives us the state directory and sponsor names.
source "$REPO/foundation_scripts/deployment_profile.sh"
deployment_profile_load "$DEPLOYMENT" || exit 1

SETUP="$REPO/testscripts/setup_${DEPLOYMENT}.sh"
[[ -x "$SETUP" ]] || { print -u2 -- "no harness at $SETUP"; exit 1 }

# WHICH BACKEND THE NODE'S OWN KEYRING USES -- READ FROM THE NODE, NOT ASSUMED.
#
# `treasury` and the pioneer live in the NODE keyring, and every funding step here goes through
# them.  config.yml now asks for keyring-backend: file, and init.sh migrates the keys there and
# deletes keyring-test -- so the old unconditional `export QADENA_KEYRING_BACKEND=test` pointed
# every one of those lookups at a keyring that no longer exists, and they failed with "key not
# found": a message that says nothing about keyrings at all.
#
# Detected rather than flagged, because the answer is a property of the chain that is already
# built.  An operator cannot be expected to remember which way a given devnet went.
_node_kb=$(grep -aE '^keyring-backend' "${QADENAHOME:-$HOME/qadena}/config/client.toml" 2>/dev/null            | cut -d'"' -f2)
: ${_node_kb:=test}
export QADENA_KEYRING_BACKEND="$_node_kb"

if [[ "$_node_kb" == "file" ]]; then
    # The passphrase reaches every child through setup_env.sh's qadenad_alias, which feeds it with
    # zsh builtins so it never lands in `ps`.  Exported once here rather than passed as a flag to
    # each of the eight scripts below.
    [[ -n "$KEYRING_PASSFILE" ]] || {
        print -u2 -- ""
        print -u2 -- "This chain's node keyring is ENCRYPTED (client.toml says keyring-backend = file),"
        print -u2 -- "so every treasury and pioneer operation below needs its passphrase."
        print -u2 -- "    $_SELF --keyring-passfile <file> ..."
        exit 1
    }
    [[ -r "$KEYRING_PASSFILE" ]] || { print -u2 -- "cannot read $KEYRING_PASSFILE"; exit 1 }
    QADENA_KEYRING_PASS=$(head -1 "$KEYRING_PASSFILE")
    [[ -n "$QADENA_KEYRING_PASS" ]] || { print -u2 -- "$KEYRING_PASSFILE is empty"; exit 1 }
    export QADENA_KEYRING_PASS
fi
export QADENA_NODE="$NODE"

# --------------------------------------------------------------------------------------------
# STAGE ORDER, and the gate that lets --from skip forward / --until stop short.
STAGES=(build chain base setup verify app)
_stage_index() { local i=1; for s in "${STAGES[@]}"; do [[ "$s" == "$1" ]] && { print -r -- $i; return }; i=$(( i + 1 )); done; print -r -- 0 }
START=$(_stage_index "$FROM")
(( START > 0 )) || { print -u2 "unknown --from stage '$FROM' (${STAGES[*]})"; exit 1 }
if [[ -n "$UNTIL" ]]; then
    STOP=$(_stage_index "$UNTIL")
    (( STOP > 0 )) || { print -u2 "unknown --until stage '$UNTIL' (${STAGES[*]})"; exit 1 }
    # `print -u2 "--until ..."` parses the leading --until as the -u flag; -- ends option parsing.
    (( STOP >= START )) || { print -u2 -- "--until $UNTIL comes before --from $FROM"; exit 1 }
else
    STOP=${#STAGES[@]}
fi
_want() { local i=$(_stage_index "$1"); (( i >= START && i <= STOP )) }

banner() {
    print -r -- ""
    print -r -- "==================================================================="
    print -r -- "  $*"
    print -r -- "==================================================================="
}

# Names the stage that failed and the --from that resumes there.
_CURRENT="startup"
_NO_RESUME_HINT=0
_on_exit() {
    local rc=$?
    (( rc == 0 )) && return 0
    # Some failures are refusals with their own complete instructions.  Repeating the generic
    # "resume from that stage" hint after them tells the operator to re-run the exact command that
    # was just refused.
    (( _NO_RESUME_HINT )) && return $rc
    print -u2 -- ""
    print -u2 -- "FAILED during the '$_CURRENT' stage (exit $rc)."
    print -u2 -- "  Fix the cause, then resume from that stage:"
    print -u2 -- "      $_SELF --from $_CURRENT --node $NODE --count $COUNT"
    return $rc
}
trap _on_exit EXIT

print -r -- "deployment : $DEPLOY_NAME"
print -r -- "node       : $NODE"
print -r -- "stages     : ${STAGES[$START]} .. ${STAGES[$STOP]}"
print -r -- "fund mode  : $FUND_MODE"
print -r -- "sec home   : $DEPLOY_SEC_HOME"

# --------------------------------------------------------------------------------------------
if _want build; then
    _CURRENT="build"
    # THE GUARD IS THE POINT OF THIS STAGE BEING FIRST.  --from defaults to `build`, so a bare run
    # would otherwise re-init the chain and destroy every wallet, credential and grant on it --
    # including another deployment's.  Refusing unless asked makes the destructive default safe.
    if (( ! ALLOW_BUILD )); then
        print -u2 -- ""
        print -u2 -- "REFUSING to run the build stage without --allow-build."
        print -u2 -- "  It rebuilds and RE-INITS the chain, which destroys every wallet, credential"
        print -u2 -- "  and grant on it -- including any other deployment already set up here."
        print -u2 -- ""
        print -u2 -- "  To skip the build and work against the running chain:"
        print -u2 -- "      $_SELF --from chain      # start the node too"
        print -u2 -- "      $_SELF --from setup      # node already running"
        _NO_RESUME_HINT=1
        exit 1
    fi
    banner "0. BUILD and re-init the chain"
    "$REPO/buildscripts/build.sh"
    # init.sh REFUSES to build when the config asks for `file` and it is given no passphrase --
    # ignite puts the keys in keyring-test whatever client.toml says, so it migrates them and
    # removes the unencrypted copy rather than shipping a node whose config and keys disagree.
    _init_args=()
    [[ -n "$KEYRING_PASSFILE" ]] && _init_args=(--keyring-passfile "$KEYRING_PASSFILE")
    "$REPO/buildscripts/init.sh" "${_init_args[@]}"
fi

# --------------------------------------------------------------------------------------------
if _want chain; then
    _CURRENT="chain"
    banner "0b. START the chain"
    # NEVER PIPE OR POLL start_qadena.sh.  It runs the node in the foreground of its own process
    # group, and interrupting the pipeline SIGKILLs the chain -- which looks exactly like a crash.
    # Start it detached, then watch the RPC rather than the script.
    if curl -s --max-time 3 "${NODE/tcp:/http:}/status" > /dev/null 2>&1; then
        print -r -- "  chain already answering on $NODE"
    else
        # THE FIRST START MUST ANSWER THE ENCLAVE'S PROMPT, once in the node's life.  Without it
        # the node produces blocks, answers RPC and advances height while logging
        # `no key named "pioneer1"` every 25 blocks -- healthy by every check below, and with no
        # enclave.  repeat/print are builtins, so the passphrase never reaches `ps`; `yes "$pass"`
        # would put it there.  After GetJarRegulator finds the registration the keyring is never
        # read again, so later restarts need nothing.
        if [[ -n "${QADENA_KEYRING_PASS:-}" ]]; then
            { repeat 64 print -r -- "$QADENA_KEYRING_PASS" } 2>/dev/null \
                | "$REPO/scripts/start_qadena.sh" > /dev/null 2>&1 &
        else
            "$REPO/scripts/start_qadena.sh" > /dev/null 2>&1 &
        fi
        print -r -- "  started; waiting for blocks"
    fi
    _n=0
    while (( _n < 60 )); do
        _h=$(curl -s --max-time 3 "${NODE/tcp:/http:}/status" 2>/dev/null \
             | jq -r '.result.sync_info.latest_block_height // empty' 2>/dev/null)
        [[ -n "${_h:-}" ]] && (( _h > 0 )) && { print -r -- "  height $_h"; break }
        _n=$(( _n + 1 )); sleep 5
    done
    [[ -n "${_h:-}" ]] || { print -u2 "  chain never produced a block"; exit 1 }
fi

# The chain has to be reachable for everything below; say so once, here, rather than letting each
# stage fail with its own unrelated-looking error.
curl -s --max-time 5 "${NODE/tcp:/http:}/status" > /dev/null 2>&1 \
    || { print -u2 ""; print -u2 "cannot reach the chain at $NODE."; \
         print -u2 "  Start it, or run with --from chain."; exit 1 }

# --------------------------------------------------------------------------------------------
if _want base; then
    _CURRENT="base"
    banner "1. BASE: stake the pioneer, fund the two foundation sponsor accounts"
    # Both are idempotent and shared by every deployment on this chain, so this is a no-op on a
    # chain that has already run one -- which is why it is worth its own skippable stage.
    "$REPO/testscripts/gov_stake_from_treasury.sh" "$PIONEER" 10000000qdn
    if [[ "$FUND_MODE" != "banksend" ]]; then
        "$REPO/testscripts/setup_foundation_accounts.sh"
    else
        print -r -- "  banksend mode: no foundation sponsor accounts needed"
    fi
fi

# --------------------------------------------------------------------------------------------
if _want setup; then
    _CURRENT="setup"
    banner "2. ${(U)DEPLOY_NAME}: steps 1-3 and the sponsor pool"
    # setup_<name>.sh does the pioneer stake itself as well; harmless and idempotent.  Everything
    # deployment-specific -- mnemonics, provider names, the ENF contract half -- lives in there,
    # which is why this script does not try to reimplement any of it.
    "$SETUP" --pioneer "$PIONEER" --fund-mode "$FUND_MODE" "${EXTRA[@]}"
fi

# --------------------------------------------------------------------------------------------
if _want verify; then
    _CURRENT="verify"
    banner "3. VERIFY the deployment against the chain"
    if [[ "$FUND_MODE" = "banksend" ]]; then
        # The verifier checks the SPONSORED invariants -- authz delegation, the MsgExec feegrant,
        # the pool's two halves.  None of them exists in banksend mode, so running it would report
        # a broken deployment for a deployment that is working as asked.
        print -r -- "  banksend mode: the verifier checks sponsored-only invariants, skipping."
    else
        # ADDRESSES, NOT --coord-home.  On a launch chain the two sponsor addresses come from
        # <name>-sponsors.json, written by the multisig prepare ceremony.  There is no ceremony and
        # no coordinator keyring here, so read them from the keyring that does hold them.
        _fa=$("$HOME/qadena/bin/qadenad" keys show foundation-appsvr -a --keyring-backend test 2>/dev/null | tr -d '\r')
        _fu=$("$HOME/qadena/bin/qadenad" keys show foundation-users  -a --keyring-backend test 2>/dev/null | tr -d '\r')
        [[ -n "$_fa" && -n "$_fu" ]] \
            || { print -u2 "  cannot read the foundation sponsor addresses -- run the base stage"; exit 1 }

        # AN ARRAY, NOT ${VAR:+...}.  zsh does not word-split an unquoted parameter expansion, so
        # `${POOL:+--pool "$POOL"}` arrives as ONE argument -- "--pool /path" -- and the script
        # answers "unknown option: --pool /path", which reads like a missing flag rather than a
        # quoting bug.
        _vargs=(--deployment "$DEPLOY_NAME" --appsvr "$_fa" --users "$_fu" --node "$NODE")
        _pre="$DEPLOY_SEC_HOME/pregrant_addresses.json"
        _pool="$DEPLOY_SEC_HOME/pool_addresses.json"
        [[ -r "$_pre"  ]] && _vargs+=(--pregrant "$_pre")
        [[ -r "$_pool" ]] && _vargs+=(--pool "$_pool")
        "$REPO/foundation_scripts/sec_veritas_verify.sh" "${_vargs[@]}"
    fi
fi

# --------------------------------------------------------------------------------------------
if _want app; then
    _CURRENT="app"
    banner "4. APP-SERVER: env file and stack restart"
    if [[ -z "$ENV_FILE" ]]; then
        # NOT A FAILURE.  The app stage needs to know which env file to patch, and there is no
        # sensible default -- guessing one would rewrite somebody's stack.  The chain half is done
        # and useful on its own, so say what is missing and exit clean.
        print -r -- "  no --env-file given, so there is nothing to patch."
        print -r -- "  The chain-side bring-up is COMPLETE.  To do the app stage:"
        print -r -- "      $_SELF --from app --env-file /path/to/stacks/$DEPLOY_NAME/env-...."
    else
        [[ -r "$ENV_FILE" ]] || { print -u2 "cannot read $ENV_FILE"; exit 1 }
        _stack="${ENV_FILE:h}"
        # --armor-passfile IS NOT OPTIONAL when there is one.  extract_ephem_keys exports through
        # qadenad_alias, which supplies the KEYRING passphrase to the armor prompt too -- so the
        # blobs are armored with it and the app-server's ARMOR_PASS_PHRASE has to match.  Patching
        # the keys and leaving the old passphrase gives an app that starts, fails to import every
        # key, and exits 1 in a restart loop reporting an EMPTY reason.
        _pe_args=(--env-file "$ENV_FILE" --deployment "$DEPLOY_NAME")
        [[ -n "$KEYRING_PASSFILE" ]] && _pe_args+=(--armor-passfile "$KEYRING_PASSFILE")
        "$REPO/testscripts/patch_env_file.sh" "${_pe_args[@]}" \
            || { print -u2 "could not patch $ENV_FILE"; exit 1 }
        # `docker compose restart` does NOT re-read env_file; `up -d` does.  A restart here looked
        # like it worked and left the old values in the container.
        if [[ -r "$_stack/Makefile" ]]; then
            print -r -- "  make start in $_stack"
            make -C "$_stack" start
        else
            print -r -- "  no Makefile in $_stack -- patched the env file only"
        fi
    fi
fi

_CURRENT="done"
print -r -- ""
print -r -- "==================================================================="
print -r -- "  ${(U)DEPLOY_NAME} bring-up complete (${STAGES[$START]} .. ${STAGES[$STOP]})"
print -r -- "==================================================================="
