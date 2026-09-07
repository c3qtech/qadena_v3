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

NODE="${QADENA_NODE:-tcp://localhost:26657}"
PASSFILE=""
COORD_HOME="$HOME/fleet-launch/coord"
SEC_HOME="${VERITAS_SEC_HOME:-$HOME/sec-veritas}"
COUNT=3
FROM="prepare"
REBUILD=0
STACK="$HOME/test/follow-the-money/stacks/veritas"
ENV_FILE="env-sponsored-test"
PREFIX="sec"
PRIMARY="azureuser@20.212.178.16"
JOINER="ubuntu@172.31.20.18"
SKIP_APP=0
ADVERTISE_P="20.212.178.16"
ADVERTISE_J="dev-nlb-97f5978861fac526.elb.ap-southeast-1.amazonaws.com"

usage() {
    print -r -- "Usage: veritas_full_setup.sh --passfile <file> [options]"
    print -r -- ""
    print -r -- "  --passfile <file>   keyring passphrase, first line.  REQUIRED: the keyrings default"
    print -r -- "                      to the encrypted 'file' backend and a prompt with no terminal"
    print -r -- "                      looks exactly like a hang."
    print -r -- "  --node <rpc>        default \$QADENA_NODE or tcp://localhost:26657"
    print -r -- "  --count <n>         ephemeral wallets per user (default 3; 30 for a real run)"
    print -r -- "  --coord-home <dir>  foundation keyring (default ~/fleet-launch/coord)"
    print -r -- "  --sec-home <dir>    SEC's directory (default ~/sec-veritas)"
    print -r -- "  --from <stage>      resume: prepare|step1|delegate|step2|approve|step3|pool|verify|app"
    print -r -- "  --rebuild-chain     PURGE both fleet nodes and rebuild the chain first."
    print -r -- "                      Destroys every wallet and credential on them."
    print -r -- "  --advertise-ip-address <ip>         what the PRIMARY tells peers to dial"
    print -r -- "                                      (reaches init.sh).  Default: the ssh host."
    print -r -- "  --joiner-advertise-ip-address <ip>   same for each JOINER (reaches"
    print -r -- "                                      add_full_node.sh).  Default: the ssh host."
    print -r -- "  --skip-app          stop after verify; do not touch the app-server stack"
    print -r -- "  --stack <dir>       app-server stack (default ~/test/follow-the-money/stacks/veritas)"
    print -r -- "  --env-file <name>   env file inside the stack (default env-sponsored-test)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --passfile)      PASSFILE="$2"; shift 2 ;;
        --node)          NODE="$2"; shift 2 ;;
        --count)         COUNT="$2"; shift 2 ;;
        --coord-home)    COORD_HOME="$2"; shift 2 ;;
        --sec-home)      SEC_HOME="$2"; shift 2 ;;
        --from)          FROM="$2"; shift 2 ;;
        --rebuild-chain) REBUILD=1; shift ;;
        --skip-app)      SKIP_APP=1; shift ;;
        --stack)         STACK="$2"; shift 2 ;;
        --env-file)      ENV_FILE="$2"; shift 2 ;;
        --primary)       PRIMARY="$2"; shift 2 ;;
        # What each node tells peers to dial.  Both default to the ssh host, which is wrong behind
        # NAT (public ssh address, private interface) and across networks.
        --advertise-ip-address)        ADVERTISE_P="$2"; shift 2 ;;
        --joiner-advertise-ip-address) ADVERTISE_J="$2"; shift 2 ;;
        --joiner)        JOINER="$2"; shift 2 ;;
        --help|-h)       usage; exit 0 ;;
        *) print -u2 -- "unknown option: $1"; usage >&2; exit 1 ;;
    esac
done

[[ -n "$PASSFILE" && -r "$PASSFILE" ]] || { print -u2 "need a readable --passfile"; usage >&2; exit 1 }
export QADENA_NODE="$NODE"
export QADENA_KEYRING_PASSFILE="$PASSFILE"

# STAGE ORDER, and the gate that lets --from skip forward.
STAGES=(prepare step1 delegate step2 approve step3 pool verify app)
_stage_index() { local i=1; for s in "${STAGES[@]}"; do [[ "$s" == "$1" ]] && { print -r -- $i; return }; i=$(( i + 1 )); done; print -r -- 0 }
START=$(_stage_index "$FROM")
(( START > 0 )) || { print -u2 "unknown --from stage '$FROM'"; exit 1 }
_want() { local i=$(_stage_index "$1"); (( i >= START )) }

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
    print -u2 -- "      $_SELF --passfile $PASSFILE --node $NODE --count $COUNT --from $_CURRENT"
    print -u2 -- "==========================================================================="
    return $rc
}
trap _on_exit EXIT

cd "$REPO"

# --------------------------------------------------------------------------------------------
if (( REBUILD )); then
    _CURRENT="rebuild"
    banner "0. PURGE AND REBUILD THE CHAIN  (destroys everything on both nodes)"
    ./testscripts/stop_fleet.sh --node "$PRIMARY" --node "$JOINER" \
        --purge --reap-archives --immediate
    rm -rf "$SEC_HOME"
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
    _pm="$HOME/fleet-launch/pioneer-mnemonic.txt"
    if [[ ! -s "$_pm" ]] || (( $(wc -w < "$_pm") < 12 )); then
        umask 077
        _tmp=$(mktemp)
        if ! print -r -- "$(head -1 "$PASSFILE")" \
              | foundation_scripts/mnemonic.sh show "$HOME/fleet-launch/mnemonics" qfi-pioneer1 > "$_tmp" 2>/dev/null; then
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
    _adv=()
    [[ -n "$ADVERTISE_P" ]] && _adv+=(--advertise-ip-address "$ADVERTISE_P")
    [[ -n "$ADVERTISE_J" ]] && _adv+=(--joiner-advertise-ip-address "$ADVERTISE_J")
    ./testscripts/fleet_bringup_with_tests.sh \
        --primary "$PRIMARY" --joiner "$JOINER" --block-sync "${_adv[@]}" \
        --mainnet-source        "$HOME/fleet-launch/fleet-launch-config.yml" \
        --pioneer-mnemonic-file "$_pm" \
        --funder qfi-pioneer1 --fund-qdn 10100 --stake 10000
    rm -f "$_pm"
fi

# --------------------------------------------------------------------------------------------
if _want prepare; then
    _CURRENT="prepare"
    banner "1. FOUNDATION: fund and stake the two sponsors"
    # pubsec is 5-of-7 on this fleet and foundation is 3-of-5; the member lists are a local naming
    # convention, not something the chain knows, so they have to be named.
    foundation_scripts/sec_veritas_before_step_1.sh --stage prepare \
        --coord-home "$COORD_HOME" --keyring-passfile "$PASSFILE" \
        --mnemonics-dir "$HOME/fleet-launch/mnemonics" --node "$NODE" \
        --pubsec-members pubsec-m1,pubsec-m2,pubsec-m3,pubsec-m4,pubsec-m5,pubsec-m6,pubsec-m7 \
        --members foundation-m1,foundation-m2,foundation-m3
fi

_sponsors="$COORD_HOME/veritas-sponsors.json"
[[ -r "$_sponsors" ]] || { print -u2 "no $_sponsors -- run the prepare stage first"; exit 1 }
APPSVR=$(jq -r '.appsvr' "$_sponsors")
USERS=$(jq -r '.users'  "$_sponsors")

# --------------------------------------------------------------------------------------------
if _want step1; then
    _CURRENT="step1"
    banner "2. SEC: mint keys, derive every wallet address, emit the pre-grant block"
    veritas_scripts/step_1.sh --count "$COUNT" \
        --appsvr "$APPSVR" --users "$USERS" \
        --node "$NODE" --sec-home "$SEC_HOME" --keyring-passfile "$PASSFILE"
fi

PREGRANT="$SEC_HOME/pregrant_addresses.json"
[[ -r "$PREGRANT" ]] || { print -u2 "no $PREGRANT -- step_1 did not complete"; exit 1 }

# --------------------------------------------------------------------------------------------
if _want delegate; then
    _CURRENT="delegate"
    banner "3. FOUNDATION: delegate the three authorities, pre-grant every wallet"
    foundation_scripts/sec_veritas_after_step_1.sh --pregrant "$PREGRANT" \
        --coord-home "$COORD_HOME" --keyring-passfile "$PASSFILE" --node "$NODE"
fi

# --------------------------------------------------------------------------------------------
if _want step2; then
    _CURRENT="step2"
    banner "4. SEC: create the service providers, submit their proposals"
    veritas_scripts/step_2.sh --node "$NODE" --sec-home "$SEC_HOME" --keyring-passfile "$PASSFILE"
fi

# THE IDS COME FROM THE FILES step_2 WROTE, and it overwrites them every run -- so read them HERE,
# immediately after, rather than trusting a value carried from an earlier invocation.
_pdir="$REPO/provider_scripts/proposals"
IDENTITY_PID=$(cat "$_pdir/secidentitysrvprv.proposal_id" 2>/dev/null || true)
DSVS_PID=$(cat "$_pdir/secdsvssrvprv.proposal_id" 2>/dev/null || true)

# --------------------------------------------------------------------------------------------
if _want approve; then
    _CURRENT="approve"
    banner "5. FOUNDATION: deposit and vote on proposals $IDENTITY_PID $DSVS_PID"
    # after_step_2 verifies each id IS a service-provider proposal and skips ones already decided,
    # so a re-run costs nothing and cannot deposit on somebody else's proposal.
    if [[ -n "$IDENTITY_PID" && -n "$DSVS_PID" ]]; then
        foundation_scripts/sec_veritas_after_step_2.sh "$IDENTITY_PID" "$DSVS_PID" \
            --coord-home "$COORD_HOME" --keyring-passfile "$PASSFILE" --node "$NODE" \
            --members foundation-m1,foundation-m2,foundation-m3
    else
        print -r -- "  no proposal ids on file -- assuming the providers are already registered"
    fi

    banner "5b. WAIT for both providers to be REGISTERED (not merely voted)"
    # A vote is not a result: the provider is registered when the proposal EXECUTES, and step_3
    # creates wallets that need the providers to exist.  Poll the registration itself rather than
    # the proposal, because a re-run's proposal id may be a duplicate that will never pass.
    for _p in secidentitysrvprv secdsvssrvprv; do
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
    banner "6. SEC: create the sponsor pool and the DSVS user, claim credentials"
    veritas_scripts/step_3.sh --node "$NODE" --sec-home "$SEC_HOME" --keyring-passfile "$PASSFILE"
fi

POOL="$SEC_HOME/pool_addresses.json"

# --------------------------------------------------------------------------------------------
if _want pool; then
    _CURRENT="pool"
    banner "7. FOUNDATION: authorise the sponsor pool"
    [[ -r "$POOL" ]] || { print -u2 "no $POOL -- step_3 did not complete"; exit 1 }
    foundation_scripts/sec_veritas_after_step_3.sh --pool-addresses "$POOL" \
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
    _vargs=(--coord-home "$COORD_HOME" --node "$NODE" --pregrant "$PREGRANT")
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
[[ -d "$STACK" ]] || { print -u2 "no stack at $STACK"; exit 1 }
_n=$(ls "$REPO"/${PREFIX}*-names.base64 2>/dev/null | wc -l | tr -d ' ')
(( _n > 0 )) || { print -u2 "no ${PREFIX}*.base64 files in $REPO -- did step_3 run?"; exit 1 }
# ARE THESE KEYS FROM THIS DEPLOYMENT?  Not "are they recent" -- my first version compared mtimes
# against the pool file and was backwards by construction: step_3 writes the .base64 files (line
# ~494) BEFORE the pool block (line ~514), two seconds apart, so a correct run always failed it.
#
# Timestamps cannot answer this anyway.  The honest test is whether the keys these files carry are
# the ones on the CURRENT chain: SEC's keys are re-minted every deployment, so an address from a
# previous one will not appear in this run's pool file.  Decode a name, resolve it, compare.
_check_name=$(base64 -d < "$REPO/${PREFIX}-create-wallet-sponsor-names.base64" 2>/dev/null \
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

./testscripts/patch_env_file.sh "$PREFIX" "$STACK/$ENV_FILE" \
    --key-dir "$REPO" --sponsors "$_sponsors"

# .env IS WHAT compose READS (env_file: .env in compose.yml).  The stack keeps several env files
# for different targets; installing the one we just patched is a deliberate copy, not a symlink,
# so the source stays readable as the record of what was deployed.
cp "$STACK/$ENV_FILE" "$STACK/.env"
chmod 600 "$STACK/.env"
print -r -- "  installed $ENV_FILE -> $STACK/.env"

# `docker compose restart` does NOT re-read env_file -- it restarts the existing containers with
# the environment they were created with, so a patched .env would appear to deploy and change
# nothing.  `up -d` recreates any container whose configuration changed, which is what we want.
print -r -- "  restarting the stack (up -d, which re-reads .env; restart would not)"
make -C "$STACK" start

print -r -- ""
print -r -- "==========================================================================="
print -r -- "DONE.  chain $NODE"
print -r -- "  foundation-appsvr $APPSVR"
print -r -- "  foundation-users  $USERS"
print -r -- ""
print -r -- "  app logs:   make -C $STACK logs-api"
print -r -- "  re-verify:  foundation_scripts/sec_veritas_verify.sh --coord-home $COORD_HOME --node $NODE"
print -r -- "==========================================================================="
