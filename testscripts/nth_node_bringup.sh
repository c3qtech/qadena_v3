#!/bin/zsh
# Bring ANOTHER node onto an existing chain and prove the peers agree.
#
# Nothing here is specific to the second node.  It takes an existing --primary and a new --joiner,
# so the same run adds a third or a fourth; only the pioneer name has to be fresh (--pioneer),
# because add_full_node.sh refuses one the chain already knows.
#
# Run from a workstation with ssh access to both nodes.  It drives them over ssh rather than living
# on either, because the interesting failures are cross-node and a script that runs on one of them
# cannot see the other half.
#
#   ./nth_node_bringup.sh --primary 192.168.86.120 --joiner 192.168.86.140
#
# Phases are separately runnable (--from / --only) because the slow ones are very slow and the
# whole point of writing this down is not repeating the parts that already passed.
#
# ---------------------------------------------------------------------------------------------
# WHY THIS SCRIPT EXISTS
#
# Every step below has a trap that is invisible until it bites, and each one cost real time:
#
#   1. NEVER `pkill -f <pattern>` OVER SSH when the pattern appears in your own command line.  The
#      remote shell running your command MATCHES IT and kills itself mid-script.  The same flaw
#      silently inflates `pgrep -cf` counts.  Kill by PID; match with a bracket class ([r]egression)
#      when you must pattern-match.
#
#   2. add_full_node.sh REQUIRES A REAL PTY.  Every prompt guards against EOF and exits rather than
#      looping -- hardening added after a FIFO-driven run spun at 100% of a core for two and a half
#      hours.  Feeding it from a pipe therefore dies at the first prompt.  script(1) is the answer;
#      out-plumbing the guard is not.
#
#   3. ANSWER 'n' TO "start the node now?" AND START IT YOURSELF.  The in-script start is launched
#      several process layers beneath a PTY that exits moments later.  Observed: it reported
#      "Running in background", then produced NO output anywhere -- no log directory, no syslog, no
#      processes.  Started standalone it comes up first try, every time.
#
#   4. FUND THE JOINER BEFORE RUNNING THE JOIN.  The funding prompt polls 120x3s and then gives up.
#      Funding first turns a timing race into a lookup that succeeds immediately.
#
#   5. PAUSE CONTINUOUS REGRESSION ON THE PRIMARY FIRST.  enclave-rollback and enclave-crash STOP
#      AND RESTART THE CHAIN by design, so the primary's RPC vanishes for minutes -- and a joiner
#      needs it reachable for both funding and sync-enclave.  Symptom is a wall of
#      "connection refused" that looks like a network fault and is not.
#
#   6. THE JOINER'S ENCLAVE MEASUREMENT MUST MATCH THE CHAIN'S GENESIS.  EnclaveIdentity is keyed by
#      measurement, so a locally-built enclave that differs by one byte is refused by
#      verifyRemoteReport -- and the error names the measurement, not the cause.  Install the
#      joiner from a package BUILT ON THE PRIMARY.  This script refuses to proceed otherwise.
#
#   7. ROOT IS REQUIRED ONLY ON SGX.  The enclave needs privilege to open /dev/sgx_enclave; a DEBUG
#      enclave has no device and runs as the login user.  The root-owned /tmp/qadena_50051.sock that
#      used to justify sudo everywhere is a CONSEQUENCE of having started the enclave as root, not a
#      cause -- and it is expensive, because every file the node then creates is root-owned, so the
#      tree cannot be removed or reinstalled without sudo either.  sudo_for() decides per host.
#
#   8. THE NODE SCRIPTS ARE ZSH, and qadenad_alias is a zsh ALIAS.  Running them under `bash -lc`
#      yields "qadenad_alias: command not found".  (`bash -lc` is the fix for a different problem --
#      a non-login shell missing /usr/local/go/bin during builds.  Do not confuse the two.)
# ---------------------------------------------------------------------------------------------

set -u

PRIMARY=""
JOINER=""
FROM=1
UNTIL=7
ONLY=""
# Off by default: phase 2 only LOOKS at the primary.  --quiesce opts into stopping its continuous
# regression loop and waiting out the in-flight run, which is authority over a machine the operator
# did not necessarily ask us to change.
QUIESCE=0; QUIESCE_NOW=0
# DEVNET FIGURES.  Both assume the funder is the devnet `treasury`, which holds millions.  On a
# launch chain the funder is an ordinary account -- the genesis validator has 110,100 QDN total,
# ~100,100 liquid after its own bond -- so these defaults exceed the whole balance and the FIRST
# joiner fails with insufficient funds.  Override with --stake / --fund-qdn there.
VALIDATOR_STAKE="110000"
FUND_QDN="200000"
# WHO PAYS, on the unsponsored path.  Defaults to `treasury` because that is the key the DEVNET
# primary holds and funds with -- but a launch-config chain has no such account (the devnet's
# do-everything key was deliberately removed), so on those the default cannot sign and phase 4
# fails AFTER the primary and all its tests have run.  Name the funder instead: any key in the
# PRIMARY's keyring that holds coins and is on the AML whitelist, e.g. the genesis validator.
FUNDER="treasury"
# TOLL-FREE JOIN.  With --foundation-sponsored the joiner is never sent coins: phase 4 issues a
# bounded, recurring FEE GRANT instead, and phase 5 tells add_full_node.sh to wait for that grant
# rather than for a balance.  The granter defaults to `treasury` because that is the key the primary
# already holds and already funds with -- in a real deployment it is a foundation key.
SPONSORED=0
SPONSOR_GRANTER="treasury"
# A FULL NODE IS THE DEFAULT PRODUCT.  add_full_node.sh "covers JOINING only", and validating is
# a separate, optional act with its own script -- so this run bonds nothing and converts nothing
# unless told to.  --convert-to-validator declares the intent up front, and everything follows
# from the declaration: the self-bond moves at the FUNDING phase (4) together with the grant, the
# phase-3 ceremony instructions include it, and phase 7 performs the conversion.  Without the
# flag none of that happens, and no coins are parked on a node that may never bond -- which
# matters here because coins sent to an unidentified address CANNOT be sent back (AML code 1159).
CONVERT=0
PIONEER_NAME="pioneer2"
STATE_SYNC=0
SEED2=""

fail() { print -u2 "FAIL(nth_node_bringup): $*"; exit 1 }
info() { print "  $*" }
phase() { print ""; print "======================================================================"; print ">>> $*"; print "======================================================================" }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary) PRIMARY="$2"; shift 2 ;;
        --joiner)  JOINER="$2";  shift 2 ;;
        --quiesce) QUIESCE=1; shift ;;
        --quiesce-immediate) QUIESCE=1; QUIESCE_NOW=1; shift ;;
        --from)    FROM="$2";    shift 2 ;;
        --until)   UNTIL="$2";   shift 2 ;;
        --only)    ONLY="$2";    shift 2 ;;
        --stake)   VALIDATOR_STAKE="$2"; shift 2 ;;
        --fund-qdn) FUND_QDN="$2"; shift 2 ;;
        --pioneer) PIONEER_NAME="$2"; shift 2 ;;
        --state-sync) STATE_SYNC=1; shift ;;
        --convert-to-validator) CONVERT=1; shift ;;
        --funder)     FUNDER="$2"; shift 2 ;;
        --foundation-sponsored)
            SPONSORED=1
            if [[ -n "$2" && "$2" != --* ]]; then SPONSOR_GRANTER="$2"; shift 2; else shift; fi ;;
        --seed2)   SEED2="$2"; shift 2 ;;
        --help)
            print "Usage: nth_node_bringup.sh --primary <ip> --joiner <ip> [--from N] [--until N] [--only N]"
            print "                          [--stake qdn] [--quiesce]"
            print "                          [--pioneer <name>] [--state-sync] [--seed2 <ip>]"
            print ""
            print "  --quiesce-immediate  as --quiesce, but END the in-flight run NOW instead of"
            print "                waiting it out.  SIGTERM first so test traps run, then SIGKILL,"
            print "                then SIGCONT anything left STOPPED -- a killed enclave-crash test"
            print "                otherwise leaves the enclave halted and the node frozen."
            print "  --quiesce     stop the primary's continuous-regression loop and WAIT for the"
            print "                in-flight run to finish before joining.  OFF by default: phase 2"
            print "                only looks and warns.  Worth passing when the primary is running"
            print "                the loop, because enclave-rollback/crash/upgrade restart the"
            print "                chain and a joiner cannot survive its primary's RPC vanishing."
            print "  --from/--until  run a RANGE of phases, inclusive: --from 1 --until 6 brings a node"
            print "                up and stops short of converting it to a validator.  --only runs one."
            print "                PHASES: 1 preflight, 2 check primary, 3 mint the joiner key,"
            print "                        4 fund it, 5 join, 6 start+catch up, 7 validator, 8 peer agreement."
            print "                --until 3 then --from 5 SKIPS THE FUNDING, for custody this script"
            print "                cannot drive: a multisig, an HSM, or a foundation on another continent."
            print "  --pioneer     the joiner's pioneer name (default pioneer2).  MUST BE UNUSED ON"
            print "                THE CHAIN: add_full_node.sh refuses a name already registered, so"
            print "                a re-join after a wipe needs a fresh one -- the key is gone"
            print "                locally but the chain still remembers it."
            print "  --convert-to-validator"
            print "                bond and convert.  WITHOUT this the run produces a FULL NODE:"
            print "                no self-bond is sent anywhere, phase 3's ceremony instructions"
            print "                omit it, and phase 7 is skipped.  With it, the bond moves at the"
            print "                funding phase (4) alongside the grant -- ONE intervention for an"
            print "                external custodian -- and phase 7 only converts."
            print "  --fund-qdn <qdn>  how much the funder sends an unsponsored joiner (default"
            print "                  200000, a DEVNET figure).  It must cover the self-bond plus a"
            print "                  working balance, and must not exceed what --funder holds."
            print "  --funder <key>  UNSPONSORED path only: the key on the PRIMARY that sends the"
            print "                  joiner its coins (default: treasury).  A launch-config chain"
            print "                  has no 'treasury' account, so name one that exists -- the"
            print "                  genesis validator's own key is usually the one that can sign."
            print "  --foundation-sponsored [<granter-key-or-ADDRESS>]"
            print "                TOLL-FREE.  The joiner gets NO coins and needs no treasury of its"
            print "                own.  Phase 3 issues a bounded recurring fee grant from <granter-key>"
            print "                (default: treasury, the key the primary already holds) and phase 5"
            print "                waits for that grant instead of a balance.  The grant covers the"
            print "                five messages a node broadcasts for life -- join, SS rotation and"
            print "                SS re-share -- so the node keeps working, not just joining."
            print "                Does NOT sponsor a validator self-bond; --stake is unaffected."
            print "  --state-sync  join by STATE-SYNC instead of block-sync.  add_full_node.sh turns"
            print "                it on only when a SECOND genesis-pioneer IP is supplied and the"
            print "                two agree on the trust height and hash, so this passes the primary"
            print "                as both.  Needs the chain past height 1500."
            print "  --seed2       the SECOND genesis-pioneer IP for the state-sync trust check."
            print "                Defaults to the primary, which is all a two-node chain can"
            print "                offer -- and which makes the cross-check prove only that the"
            print "                primary agrees with itself.  Adding a THIRD node is what makes"
            print "                it meaningful: pass an existing peer here and the trust height"
            print "                and hash are then corroborated by an independent source."
            print ""
            print "  1 preflight      both reachable, measurements match genesis, primary healthy"
            print "  2 check          warn if the primary is running regression (it restarts the"
            print "                   chain); --quiesce stops it and waits instead"
            print "  3 fund           send qdn to the joiner's pioneer key"
            print "  4 join           drive add_full_node.sh over a PTY; does NOT start the node"
            print "  5 start          start the joiner separately and wait for catch-up"
            print "  6 validator      convert the joiner, re-split stake, verify neither node >= 2/3"
            print "  7 agreement      test_peer_agreement.sh -- the first run that compares anything"
            exit 0 ;;
        *) fail "unknown option $1" ;;
    esac
done

[[ "$FROM"  == <-> ]] || fail "--from takes a phase number, got \"$FROM\""
[[ "$UNTIL" == <-> ]] || fail "--until takes a phase number, got \"$UNTIL\""
[[ "$FROM" -le "$UNTIL" ]] || fail "--from $FROM is after --until $UNTIL, so nothing would run"
[[ -n "$PRIMARY" ]] || fail "--primary is required"
[[ -n "$JOINER" ]]  || fail "--joiner is required"

# rsh <host> <command...> -- run as root on a node, through a LOGIN zsh so PATH and the
# qadenad_alias definition in setup_env.sh are both present (trap 8).
rsh() {
    local host="$1"; shift
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "sudo zsh -lc $(printf '%q' "$*")"
}
# rsh_user -- same, without root, for things that must not create root-owned files.
rsh_user() {
    local host="$1"; shift
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"
}

qad() { print "\$HOME_BIN/qadenad --home \$NODE_HOME" }

# height <host> -- current height, or empty when the RPC is not answering.
height() {
    ssh -o ConnectTimeout=10 "$1" 'curl -s --max-time 5 localhost:26657/status 2>/dev/null | jq -r ".result.sync_info.latest_block_height // empty"' 2>/dev/null
}

# run_phase <n> -- should phase n run?
#
# --only wins outright.  Otherwise the range is [FROM, UNTIL] INCLUSIVE, so --from 1 --until 5 is
# "bring the node up and stop before the validator conversion" -- the common case when adding a
# node that is meant to follow rather than validate, and previously five separate --only runs.
run_phase() {
    [[ -n "$ONLY" ]] && { [[ "$1" == "$ONLY" ]] && return 0 || return 1 }
    [[ "$1" -ge "$FROM" ]]  || return 1
    [[ "$1" -le "$UNTIL" ]] || return 1
    return 0
}

# repo_on <host> -- absolute path to the checkout, resolved AS THE LOGIN USER.
#
# Never write `sudo zsh -lc "cd ~/test/qadena_v3"`: under sudo, ~ is /root, and the cd fails with
# "no such file or directory: /root/test/qadena_v3".  Resolve the path unprivileged, then hand the
# absolute path to the privileged command.
repo_on() {
    local host="$1" p
    for p in test/qadena_v3 qadena_v3 test/qv3 qv3; do
        if ssh -o ConnectTimeout=10 "$host" "test -d \$HOME/$p" 2>/dev/null; then
            ssh -o ConnectTimeout=10 "$host" "echo \$HOME/$p" 2>/dev/null | tr -d '\r'
            return 0
        fi
    done
    return 1
}

# JOINER_HOME -- the joiner's home directory, resolved AS THE LOGIN USER, once.
#
# `~` is safe when the OUTER remote shell expands it before sudo runs (ssh host "sudo ~/qadena/...")
# and unsafe the moment it appears inside a shell that sudo itself starts
# (sudo zsh -lc "cd ~/qadena/..."), because that one expands it as root and gets /root.  Both forms
# appear in this script and only the second is wrong, which is exactly why the failure looks like a
# broken install rather than a quoting bug.
JOINER_HOME=$(ssh -o ConnectTimeout=10 "$JOINER" 'echo $HOME' 2>/dev/null | tr -d '\r')
[[ -n "$JOINER_HOME" ]] || fail "cannot resolve the joiner's home directory on $JOINER"

# SGX_PROBE -- run on a target, answers BOTH questions at once via its exit status.
#
#   0  both devices present AND openable by the login user   -> SGX, no root needed
#   1  both present but NOT openable                          -> SGX, root needed
#   2  not both present                                       -> no usable SGX (debug)
#
# BOTH devices, because /dev/sgx_provision holds the key attestation quotes with: a box that has
# only the enclave node runs an enclave and then fails at JOIN time, naming a measurement rather
# than the missing device.  /dev/isgx is not accepted -- it is the pre-5.11 out-of-tree driver's
# single node, has no provisioning device, and nothing in this repo provisions it.
SGX_PROBE='e=""; p=""
for d in /dev/sgx_enclave /dev/sgx/enclave;     do [ -e "$d" ] && { e="$d"; break; }; done
for d in /dev/sgx_provision /dev/sgx/provision; do [ -e "$d" ] && { p="$d"; break; }; done
[ -n "$e" ] && [ -n "$p" ] || exit 2
[ -r "$e" ] && [ -w "$e" ] && [ -r "$p" ] && [ -w "$p" ] || exit 1
exit 0'

sgx_state() { ssh -o ConnectTimeout=10 "$1" "$SGX_PROBE" >/dev/null 2>&1; print $? }

# sudo_for <host> -- "sudo " when that host genuinely needs root, empty otherwise.
#
# ROOT IS AN SGX REQUIREMENT, NOT A QADENA ONE.  The enclave needs privilege to open
# /dev/sgx_enclave; a DEBUG enclave has no device to open, and runs perfectly as the login user --
# verified on this pair, where the node, the enclave and /tmp/qadena_50051.sock are all owned by
# alvillarica and the chain syncs normally.
#
# Using sudo anyway is not merely unnecessary, it is ACTIVELY HARMFUL: every file the node creates
# is then owned by root, so the install can only be removed by root, `rm -rf ~/qadena` as the login
# user fails on every entry, and the next install refuses because it cannot overwrite what is
# already there.  That sequence cost a full wipe-and-reinstall cycle today.
#
# The socket being root-owned -- the reason this script gave for requiring sudo everywhere -- is a
# CONSEQUENCE of having started the enclave as root, not a cause.
# STRIP ANY user@ PREFIX BEFORE AN ADDRESS GOES INTO A CONFIG FILE.
#
# --primary and --joiner are SSH TARGETS and legitimately accept user@host, so a node can be driven
# as a specific account.  add_full_node.sh's --advertise-ip-address and
# --genesis-pioneer-{first,second}-ip-address are NOT ssh targets: they become CometBFT addresses,
# which are parsed as <nodeid>@<host>:<port>.  Passing user@host puts TWO '@' in one address and the
# node exits 1 at startup with
#
#     address (85cd3d22...@alvillarica@192.168.86.136:26656) does not contain ID
#
# 1st_node_bringup.sh has stripped this for its own advertise address for some time; this script
# did not, and it contaminates THREE fields -- external_address, persistent_peers and the state-sync
# rpc_servers -- which fail ONE AT A TIME, each with a different error at a different startup stage.
# The failure lands in phase 6, minutes after phases 3-4 have already minted the key, funded it, fetched
# genesis and run sync-enclave, so it reads as a start problem rather than a bad argument.
# See TESTING-BACKLOG.md item 86.
#
# $PRIMARY and $JOINER stay WHOLE below -- ssh needs the account.  Only these derived forms go into
# add_full_node.sh.
ADVERTISE_J="${JOINER##*@}"
ADVERTISE_P="${PRIMARY##*@}"

# THE TRUST ANCHOR SITS 10 BLOCKS BACK ON A TEST FLEET, not the 2000 add_full_node.sh defaults to.
#
# 2000 is right for a mainnet-length chain and wrong for every chain this harness builds: joiners
# arrive around height 2300, so latest-2000 lands near 325 -- under add_full_node.sh's own
# "trust height is too low" gate, which SILENTLY falls back to block-sync.  The run would come up
# green having never exercised state-sync, which is the one thing --state-sync exists to test.
#
# 10 is enough to fix what the offset is actually for: the second seed corroborates the anchor at
# the SAME height, and asking it for the tip fails whenever it is a block behind -- which aborted a
# join on 2026-08-30 with "couldn't get it" on a fleet that was perfectly healthy.
TRUST_OFFSET_ARG=" --trust-height-offset ${TRUST_HEIGHT_OFFSET:-10}"
# UNCONDITIONAL, and it has to be: `set -u` is on and both add_full_node.sh call sites interpolate
# this, including the block-sync path.  Defining it only under STATE_SYNC made every block-sync join
# die on "parameter not set".  Harmless to pass either way -- add_full_node.sh only reads it when a
# second seed makes the trust block run at all.

# Passed to convert_to_validator.sh so the create-validator tx is fee-granted.  Unconditional for
# the same reason as TRUST_OFFSET_ARG: `set -u` is on and phase 7 interpolates it either way.
if (( SPONSORED )); then SPONSOR_CV_ARG=" --foundation-sponsored"; else SPONSOR_CV_ARG=""; fi

# SECOND_IP_ARG -- the extra seed that turns statesync on.  Computed here rather than inside phase
# 5, because phase 3 now drives add_full_node.sh too and the two must agree: a key minted for a
# block-sync join and then resumed as a state-sync one would rewrite config.toml mid-flight.
if (( STATE_SYNC )); then
    SECOND_IP_ARG=" --genesis-pioneer-second-ip-address ${${SEED2:-$PRIMARY}##*@}"
else
    SECOND_IP_ARG=""
fi

sudo_for() {
    local host="$1"
    # Q2 only.  Existence is the WRONG test: on a machine setup_qadena_build.sh has provisioned the
    # login user is in the device groups and opens them directly, so asking "does a device exist"
    # returns sudo precisely where it is unnecessary -- and needless sudo is what leaves the tree and
    # the enclave socket root-owned, breaking the next unprivileged start.
    [[ $(sgx_state "$host") == 1 ]] && print "sudo " || print ""
}
SUDO_P=$(sudo_for "$PRIMARY")
SUDO_J=$(sudo_for "$JOINER")

# REPORT THE STATE, DO NOT INFER IT FROM $SUDO -- the same correction 1st_node_bringup.sh already
# carries.  sudo_for is empty in TWO different situations: the devices are present and this user can
# open them (the normal, provisioned case), or there is no SGX at all.  Saying "has no SGX device"
# for both is right half the time and confidently wrong the other half: it printed exactly that for
# .120 and .140 in the middle of a real-SGX state-sync join.  A test log that misdescribes the
# hardware it is running on is worse than silence, because it gets quoted later as evidence.
sgx_desc() {
    case "$(sgx_state "$1")" in
        0) print "SGX present, devices usable -- no sudo needed" ;;
        1) print "SGX present, but this user cannot open the devices -- commands will use sudo" ;;
        *) print "no SGX device -- this node runs a DEBUG enclave" ;;
    esac
}
info "primary $PRIMARY: $(sgx_desc "$PRIMARY")"
info "joiner  $JOINER: $(sgx_desc "$JOINER")"

# ensure_self_bond: deliver the validator self-bond to the joiner's pioneer key, once.
#
# CALLED FROM TWO PHASES, IDEMPOTENTLY.  Phase 4 (funding) calls it under --convert-to-validator
# so all money moves at one point and an external custodian intervenes once; phase 7 calls it as
# a safety net for resumed runs (--from 7) that skipped 4.  Whichever runs second sees the
# balance and does nothing.  The amount is read from the JOINER's config.yml because that is the
# file convert_to_validator.sh bonds from: sponsored, it bonds exactly min-self-delegation, so
# sending anything else either strands QDN on the node or leaves its balance poll waiting.
ensure_self_bond() {
    local jaddr floor _bal
    jaddr=$(ssh "$JOINER" "${SUDO_J}~/qadena/bin/qadenad --home ~/qadena keys show $PIONEER_NAME -a --keyring-backend test 2>/dev/null" | tr -d '\r')
    [[ -n "$jaddr" ]] || fail "cannot resolve $PIONEER_NAME's address on $JOINER to fund its self-bond"
    floor=$(ssh "$JOINER" "dasel -f \$HOME/qadena/config/config.yml 'validators.first().app.min-self-delegation' 2>/dev/null" | tr -d '\r"')
    [[ "$floor" == <-> ]] \
        || fail "validators.first().app.min-self-delegation on $JOINER is \"$floor\", not a bare aqdn integer -- cannot size the self-bond"
    _bal=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena q bank balances $jaddr --output json 2>/dev/null" \
           | tr -d '\r' | jq -r '[.balances[]? | select(.denom=="aqdn") | .amount] | first // "0"' 2>/dev/null)
    _bal=${_bal:-0}
    if [[ "$_bal" != "0" ]] && (( $(print "$_bal >= $floor" | bc 2>/dev/null || print 0) )); then
        info "self-bond already present ($_bal aqdn >= ${floor}aqdn) -- not sending it again"
        return 0
    fi
    # THE --from 7 RESUME IS THE CASE THAT BITES.  A full-node run (no --convert-to-validator)
    # never sent a bond and never printed bond instructions -- phase 3 omits them by design.  So
    # when the operator later resumes with the flag, THIS is the first moment the money is
    # needed, and "go look at what phase 3 printed" points at output that does not exist.  An
    # external-custody granter cannot be signed for on the primary either, so print the complete
    # ceremony here and stop, rather than attempting a send that must fail.
    if [[ "$SPONSOR_GRANTER" == qadena1* ]]; then
        info "granter $SPONSOR_GRANTER is external custody -- the primary cannot sign the self-bond."
        print_funding_instructions "$jaddr"
        fail "deliver the ${floor}aqdn self-bond by the ceremony above, then re-run this phase --
       the delivered bond will be seen and not re-sent."
    fi
    info "sponsored: sending the ${floor}aqdn self-bond to $jaddr (fees stay on the grant)"
    # --bond-only: the fee grant is phase 4's (or the ceremony's); re-granting collides with it.
    # tail -12, not -4: the sponsor script prints its header first, and a short tail hid results.
    ssh "$PRIMARY" "${SUDO_P}~/qadena/scripts/foundation_sponsor_node.sh --node $jaddr --granter $SPONSOR_GRANTER --bond-only --self-bond ${floor}aqdn" \
        2>&1 | tail -12 | sed 's/^/    /'
    if (( ${pipestatus[1]} != 0 )); then
        print_funding_instructions "$jaddr"
        fail "could not send the self-bond to $jaddr from the primary.  Deliver it by the
       ceremony above (scripts/multisig_sign.sh) and re-run -- the delivered bond will be seen."
    fi
}

print_funding_instructions() {  # $1 = the joiner pioneer address
    local addr="$1"
    _chainid=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena status 2>/dev/null" \
               | tr -d '\r' | jq -r '.node_info.network // empty' 2>/dev/null)
    print ""
    print "  ---- IF PHASE 4 CANNOT SIGN FOR YOUR CUSTODY, SKIP IT ----"
    print "  Stop here (--until 3), fund $PIONEER_NAME by your own ceremony, then resume with --from 5."
    print ""
    if (( SPONSORED )); then
    print "  MODE: SPONSORED (--foundation-sponsored given).  Instructions below are for a fee grant."
    else
    print "  MODE: NOT SPONSORED.  Instructions below are for a plain transfer."
    print "        PASS --foundation-sponsored ON THIS RUN IF YOU MEANT TO SPONSOR.  It selects which"
    print "        instructions you get, so it is needed on the --until 3 run even though the phase it"
    print "        otherwise drives (4) is the one you are skipping.  Sign the wrong thing and you"
    print "        find out at phase 5, after the ceremony."
    fi
    print ""
    print "  joiner:   $addr"
    print "  chain-id: ${_chainid:-<primary is not answering>}"
    if (( SPONSORED )); then
    print "  needed:   a recurring FEE GRANT from $SPONSOR_GRANTER to the joiner."
    print "            No coins move.  It must NOT expire and must NOT be join-only: SS re-sharing"
    print "            recurs for the life of the node, and a lapsed grant stops it silently."
    if (( CONVERT )); then
    print "  ALSO:     a validator needs a REAL SELF-BOND -- a transfer, which no fee grant covers."
    # THE EXACT AMOUNT, SO BOTH TXS CAN BE SIGNED IN ONE SITTING.  config.yml ships with the release
    # package, so the floor is readable here -- long before phase 7, which is merely where the
    # unsponsored path happens to send it.  Printing it is what makes ONE ceremony possible: both
    # phase 4 (grant) and phase 7 (bond) skip work already on chain, so an operator who signs both
    # now is never asked again.  Saying "send the floor" without saying what it is forces two.
    _floor=$(ssh "$JOINER" "dasel -f \$HOME/qadena/config/config.yml 'validators.first().app.min-self-delegation' 2>/dev/null" | tr -d '\r"')
    if [[ "$_floor" == <-> ]]; then
    print "            SEND EXACTLY: ${_floor}aqdn   (min-self-delegation, from the joiner's config.yml)"
    print "            NOT ${VALIDATOR_STAKE}qdn -- that default is a DEVNET figure.  A sponsored node"
    print "            handed a large liquid balance can pay its own gas, which is not sponsorship."
    else
    print "            Send the MIN-SELF-DELEGATION FLOOR (could not read it from the joiner:"
    print "            validators.first().app.min-self-delegation was \"$_floor\")."
    fi
    print ""
    print "  DO BOTH NOW, IN ONE CEREMONY.  Phase 4 skips a grant already on chain and the bond"
    print "  delivery skips one already present, so signing both here means the multisig is never"
    print "  asked twice."
    else
    print "  NO SELF-BOND: --convert-to-validator was not given, so this run makes a FULL NODE and"
    print "  no stake should be sent.  (Coins sent to an unidentified address cannot come back.)"
    print "  If this node will validate, re-run --only 3 WITH --convert-to-validator to get the"
    print "  full ceremony, bond amount included."
    fi
    else
    print "  needed:   a transfer of ${FUND_QDN}qdn to the joiner."
    fi
    print ""
    print "  On the machine holding a member key (scripts/multisig_sign.sh):"
    print "    build-feegrant --granter <msig> --grantee $addr --msgs <LIFE_MSGS> --out grant.json"
    print "    build-send     --from <msig> --to $addr --amount <stake> --out bond.json"
    print "    sign  --tx grant.json --multisig <msig> --from <member> --out sigN.json   # once per member"
    print "    combine --tx grant.json --multisig <msig> --out signed.json sig1.json sig2.json ..."
    print "    broadcast --tx signed.json"
    print "  --sequence-offset 1 goes on SIGN, on every share of the SECOND tx -- the sequence is"
    print "  written when a share is signed, not when the tx is built.  Omit it and the second tx is"
    print "  invalid the instant the first lands.  Drop it if the first has ALREADY landed."
}


# ---------------------------------------------------------------------------- 1. preflight
if run_phase 1; then
phase "1. preflight"

for h in "$PRIMARY" "$JOINER"; do
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$h" true 2>/dev/null || fail "cannot ssh to $h"
done
for h in "$PRIMARY" "$JOINER"; do
    # Only a host whose devices are OUT OF REACH needs sudo.  A host where the login user is in the
    # sgx/sgx_prv groups needs none, and demanding it there would fail a perfectly good machine.
    if [[ $(sgx_state "$h") == 1 ]]; then
        ssh "$h" 'sudo -n true' 2>/dev/null \
            || fail "$h has SGX devices this user cannot open, so it needs passwordless sudo -- or, better, add the login user to the groups owning /dev/sgx_enclave and /dev/sgx_provision"
    fi
done
info "both nodes reachable"

PH=$(height "$PRIMARY")
[[ -n "$PH" ]] || fail "primary $PRIMARY is not answering on 26657 -- start it before joining"
info "primary at height $PH"

# Measurements MUST match, or the joiner is refused by attestation with an error that names the
# measurement rather than the cause (trap 6).
#
# READ TWO WAYS, because a debug enclave has a real identity too.  On SGX the measurement comes from
# `ego uniqueid`.  On a machine without SGX -- every ARM box, where ego ships as an amd64-only .deb
# and cannot be installed at all -- the enclave is a debug build whose uniqueID is a go:embed'ed
# string like "unique047", printed by the binary itself.  getEnclaveIdentity looks that string up in
# genesis exactly as it would a measurement, and a joiner whose ids differ is refused exactly the
# same way, so the check is the same shape either way and only the reader differs.  Asking ego for
# it on ARM yields nothing, which used to read as "no readable enclave measurement" -- a true
# statement about the wrong thing.
uid_of() {
    local h="$1" out
    local sp; sp=$(sudo_for "$h")
    out=$(ssh "$h" "${sp}ego uniqueid ~/qadena/bin/qadenad_enclave 2>/dev/null" | tr -d '\r')
    [[ "$out" =~ ^[0-9a-f]{64}$ ]] && { printf "%s" "$out"; return 0 }
    # debug path: the binary prints its embedded id.  -unique-id is qadenad_enclave's spelling.
    out=$(ssh "$h" "${sp}~/qadena/bin/qadenad_enclave -unique-id 2>/dev/null | tail -1" | tr -d '\r')
    [[ -n "$out" && "$out" != *[[:space:]]* ]] && { printf "%s" "$out"; return 0 }
    return 1
}
prim_uid=$(uid_of "$PRIMARY")
join_uid=$(uid_of "$JOINER")
# Genesis records whatever the enclave reports, so the pattern must not assume a 64-hex measurement.
gen_uid=$(ssh "$PRIMARY" "grep -o '\"uniqueID\": *\"[^\"]*\"' ~/qadena/config/genesis.json 2>/dev/null | head -1 | sed 's/.*: *\"//; s/\"//'" | tr -d '\r')

[[ -n "$prim_uid" ]] || fail "primary has no readable enclave identity (neither ego uniqueid nor -unique-id answered)"
info "primary  enclave $prim_uid"
info "joiner   enclave $join_uid"
info "genesis  records $gen_uid"

[[ "$join_uid" == "$prim_uid" ]] || fail "joiner's enclave measurement differs from the primary's.
Install the joiner from a package BUILT ON THE PRIMARY (buildscripts/package_release.sh), rather
than building locally: EnclaveIdentity is keyed by measurement, so anything else is refused."
# GENESIS NAMING A DIFFERENT MEASUREMENT IS NORMAL AFTER AN UPGRADE, and refusing it here was
# wrong -- it blocked exactly the case the trust split exists to support.
#
# Genesis is immutable: it names the measurement the chain LAUNCHED with, forever.  Once a chain
# upgrades its enclave, every node runs something else, and a joiner replaying genesis meets an
# identity that is not its own.  That used to be fatal (`code 1146` at InitChain, the bug fixed in
# 5f9b7dda), so this preflight refused the combination rather than let a joiner discover it after
# wiping and funding itself.  Now the enclave stores that row without trusting it, and both join
# paths are verified against an upgraded chain.
#
# What still matters is the check ABOVE: the joiner must run the SEED's measurement, because a
# joiner bootstraps its trusted set from a seed running its own build.  That is the real
# precondition; this one was a symptom of a bug that no longer exists.
if [[ "$gen_uid" != "$prim_uid" ]]; then
    info "genesis records $gen_uid while the chain runs $prim_uid -- an upgraded chain, which is fine"
    info "  (the joiner stores the genesis identity without trusting it; see docs/ENCLAVE-THREAT-MODEL.md)"
fi
info "measurements agree -- attestation can succeed"

# THE JOINER MUST NOT BE CARRYING A FOREIGN GENESIS.  A machine that was a node on a PREVIOUS chain
# still has that chain's genesis, data and pioneer key -- and the chain-id string is identical
# across rebuilds ("qadena_4828-1"), so nothing downstream notices.
#
# It gets through because phase 3 mints the key only when one is ABSENT, and the WIPE lives inside
# that same branch (add_full_node.sh does it under --stop-for-funding; the phase-4 resume
# deliberately skips it).  So a leftover pioneer key means: no mint, no wipe, and the joiner then
# "joins" while still running its old chain.  Observed exactly once, and it cost an hour: the
# joiner sat at height 7400 with earliest=2001 and peers=0 against a primary at 1572, reporting
# catching_up=true forever, while every check that names an identity -- measurement, chain-id --
# said the two machines agreed.
#
# COMPARED BY genesis_time + app_state, NOT by the file's bytes.
#
# The raw file is the obvious thing to hash and the wrong one: a joiner fetches genesis over the
# primary's RPC, and what comes back is re-serialized -- app_hash null becomes "", app_name and
# app_version are absent, the consensus block is reshaped.  Hashing the file therefore reports
# "different chain" for a node that joined perfectly (it did, on the first attempt at this check),
# and a preflight that fails valid setups is worse than no preflight.
#
# genesis_time is stamped once when the chain is created and survives the round trip, so it
# distinguishes two rebuilds that share a chain-id -- which is precisely the case here.  app_state
# is hashed with it because time alone would not notice a genesis edited in place.
gen_ident() {   # host -> "<genesis_time> <sha of sorted app_state>"
    ssh "$1" "jq -r '.genesis_time' ~/qadena/config/genesis.json 2>/dev/null; \
              jq -S -c '.app_state' ~/qadena/config/genesis.json 2>/dev/null | sha256sum | cut -d' ' -f1" \
        | tr -d '\r' | tr '\n' ' '
}
if ssh "$JOINER" 'test -f ~/qadena/config/genesis.json' 2>/dev/null; then
    prim_gen=$(gen_ident "$PRIMARY")
    join_gen=$(gen_ident "$JOINER")
    if [[ -n "${prim_gen// /}" && -n "${join_gen// /}" && "$prim_gen" != "$join_gen" ]]; then
        join_h=$(height "$JOINER")
        fail "the joiner is carrying a DIFFERENT chain's genesis (it was a node on an earlier chain).
       primary genesis_time + app_state  $prim_gen
       joiner  genesis_time + app_state  $join_gen${join_h:+
       joiner is serving its old chain at height $join_h}
       Joining would not wipe it: phase 3 mints (and wipes) only when the pioneer key is ABSENT,
       and this joiner still has one.  Clear it with add_full_node.sh's OWN list, which removes
       node state file by file and leaves PACKAGE state alone -- 'rm -rf ~/qadena/config' does not
       work: it also takes public.pem (the enclave signer's public key) and node_params.json, and
       nothing puts either back except another install.  Losing node_params.json fails the next
       join with the misleading 'Failed to copy genesis file' (it is setPioneerID.sh that failed).
           ssh $JOINER '~/qadena/scripts/stop_qadena.sh
               cd ~/qadena/config && rm -f *.toml *.1 genesis.json node_key.json priv_validator_key.json
               cd ~/qadena && rm -rf data keyring-test enclave_config enclave_data enclave_secrets'
       Or, simplest and safest: pass an unused --pioneer name, and let phase 3 do the wipe."
    fi
    info "joiner's genesis matches the primary's"
fi

# THE PIONEER NAME MUST BE UNUSED ON THE CHAIN.  add_full_node.sh refuses a name already in the
# IntervalPublicKeyID list ("The Pioneer <name> already exists, please choose a different Pioneer
# name") -- and it refuses it in phase 5, after the wipe, after the funding, several minutes in.
#
# The trap is that the name outlives the machine: wiping a joiner removes its key but the CHAIN
# still remembers the registration, so the default pioneer2 is burned by any previous join attempt
# that got as far as sync-enclave.  Asked here, it costs one query and names the fix.
registered=$(ssh "$PRIMARY" "~/qadena/bin/qadenad --home ~/qadena query qadena list-interval-public-key-id --output json 2>/dev/null \
    | jq -r '.intervalPublicKeyID[].nodeID' 2>/dev/null" | tr -d '\r')
if print -r -- "$registered" | grep -qx "$PIONEER_NAME"; then
    # Suggest the next free pioneerN, counting only pioneer names -- the list also holds jar1,
    # regulator1, treasury and the service providers, so a bare count suggests nonsense.
    suggest=2
    while print -r -- "$registered" | grep -qx "pioneer$suggest"; do (( suggest++ )); done
    fail "the pioneer name '$PIONEER_NAME' is ALREADY REGISTERED on this chain.
       add_full_node.sh will refuse it in phase 4, after wiping and funding the joiner.  The name
       outlives the machine: wiping a joiner clears its key, but the chain keeps the registration.
       Names already taken: $(print -r -- "$registered" | tr '\n' ' ')
       Pass an unused one:  --pioneer pioneer$suggest"
fi
info "pioneer name '$PIONEER_NAME' is free on this chain"
fi

# ---------------------------------------------------------------------------- 2. check/quiesce
#
# LOOKING IS THE DEFAULT; STOPPING THINGS IS OPT-IN (--quiesce).  This phase used to kill the
# primary's continuous-regression loop and then block for up to an hour waiting for the in-flight
# run to finish -- on every join, whether or not anything was running.  That is a lot of authority
# to exercise by default over a machine the operator did not ask us to change, and on an idle
# primary (the normal state before a join) it was pure latency.
#
# The SAFETY INFORMATION is what actually matters, so that is what stays unconditional: a
# regression run RESTARTS THE CHAIN, and a joiner cannot survive its primary's RPC vanishing
# mid-join.  So we always look, and we always say what we found -- loudly, because proceeding into
# a join while a suite is running is how a join fails in a way that looks like a joiner bug.
if run_phase 2; then
phase "2. check the primary$([[ $QUIESCE -eq 1 ]] && print " (--quiesce: will stop continuous regression)")"

# Kill the LOOP by PID, never by pattern (trap 1).  The in-flight regression run is left to finish:
# killing it mid-suite can leave the chain stopped by enclave-crash.
loop_pids=$(ssh "$PRIMARY" 'pgrep -f "[r]un_regression_continually" 2>/dev/null' | tr '\n' ' ')
if [[ $QUIESCE -eq 1 ]]; then
    if [[ -n "${loop_pids// /}" ]]; then
        info "stopping continuous regression (pids: $loop_pids)"
        for p in ${=loop_pids}; do ssh "$PRIMARY" "${SUDO_P}kill $p" 2>/dev/null; done
        sleep 3
    else
        info "continuous regression not running"
    fi

    if [[ $QUIESCE_NOW -eq 1 ]]; then
        # --quiesce-immediate: do not wait out the run in flight, end it now.
        #
        # SIGTERM FIRST, AND NOT OUT OF POLITENESS.  test_enclave_crash_recovery.sh SIGSTOPs the
        # enclave and resumes it from a `trap ... EXIT INT TERM`.  SIGTERM lets that trap run, so
        # the test resumes the enclave itself.  SIGKILL skips it and strands a STOPPED enclave with
        # the node frozen behind it -- manufacturing the very wedge this option exists to avoid.
        info "killing the in-flight regression run now (SIGTERM, then SIGKILL)"
        ssh "$PRIMARY" "${SUDO_P}pkill -TERM -f '[r]egression.sh' 2>/dev/null; true" >/dev/null 2>&1 || true
        for i in {1..10}; do
            n=$(ssh "$PRIMARY" 'pgrep -cf "[r]egression.sh" 2>/dev/null; true' | tr -d '\r' | head -1)
            [[ "${n:-0}" -eq 0 ]] && break
            sleep 2
        done
        if [[ "${n:-0}" -ne 0 ]]; then
            info "it did not exit on SIGTERM; SIGKILL"
            ssh "$PRIMARY" "${SUDO_P}pkill -KILL -f '[r]egression.sh' 2>/dev/null; true" >/dev/null 2>&1 || true
            sleep 2
        fi
        # THE BACKSTOP that makes this option safe to offer.  If the trap did not run -- SIGKILL, or
        # a suite that never installed one -- the enclave is still SIGSTOPped and the node is frozen
        # behind a healthy-looking process table.  Resume anything stopped; a SIGCONT to a process
        # that was never stopped costs nothing.
        stopped=$(ssh "$PRIMARY" 'ps -eo stat=,pid=,comm= 2>/dev/null | awk "\$1 ~ /^T/ && \$3 ~ /qadenad|enclave/ {print \$2}" | tr "\n" " "; true' 2>/dev/null | tr -d '\r')
        if [[ -n "${stopped// /}" ]]; then
            info "resuming STOPPED enclave process(es): ${stopped% }  (a killed test left them halted)"
            ssh "$PRIMARY" "${SUDO_P}kill -CONT ${stopped}" >/dev/null 2>&1 || true
        fi
        n=0
    else
    info "waiting for any in-flight regression run to finish (it restarts the chain; a joiner cannot survive that)"
    for i in {1..120}; do
        # `pgrep -c` PRINTS the count and EXITS NON-ZERO when it is zero, so `|| echo 0` appended a
        # second line and the arithmetic below saw "0\n0" -- "bad math expression: operator expected".
        # The effect was perverse: this loop worked while regression WAS running (one line, exit 0)
        # and crashed when the primary was already idle, which is the normal state before a join.
        n=$(ssh "$PRIMARY" 'pgrep -cf "[r]egression.sh" 2>/dev/null; true' | tr -d '\r' | head -1)
        [[ "${n:-0}" -eq 0 ]] && break
        sleep 30
    done
    fi
    [[ "${n:-0}" -eq 0 ]] || fail "regression still running after an hour; stop it before joining"

    for i in {1..40}; do
        PH=$(height "$PRIMARY"); [[ -n "$PH" ]] && break; sleep 15
    done
    [[ -n "$PH" ]] || fail "primary RPC did not come back after regression"
    info "primary quiescent and producing at $PH"
else
    # Report only.  Both findings are warnings rather than failures: a join against a busy primary
    # usually works, and the operator may know something we do not (a run that is nearly done, a
    # --skip list that omits the chain-restarting suites).  Refusing outright would be wrong; being
    # quiet about it would be worse.
    n=$(ssh "$PRIMARY" 'pgrep -cf "[r]egression.sh" 2>/dev/null; true' | tr -d '\r' | head -1)
    if [[ -n "${loop_pids// /}" || "${n:-0}" -ne 0 ]]; then
        info "WARNING: the primary is running regression${loop_pids:+ (continuous loop pids: ${loop_pids% })}"
        info "         enclave-rollback and enclave-crash RESTART the chain, and a"
        info "         joiner cannot survive its primary's RPC vanishing mid-join."
        info "         Re-run with --quiesce to stop the loop and wait it out, or --skip those suites."
    else
        info "no regression running on the primary"
    fi
    info "primary producing at $PH"
fi
fi

# NO PROMPT FEEDER ANY MORE.  A ~50-line zsh script used to be piped into a pseudo-terminal on
# the joiner, watching add_full_node.sh's transcript for question TEXT and printing an answer
# when it matched.  It answered by WORDING rather than by meaning, so rewording a prompt broke
# it silently; it had to be killed by hand afterwards because it kept looping for questions that
# would never come; and the pipeline meant a closed stdin could spin add_full_node.sh at 100% of
# a core (the EOF guards in that script exist because of exactly that).
#
# add_full_node.sh takes --yes / --on-existing / --funded / --no-start-node since 2026-09-02, so
# both call sites below pass ARGUMENTS instead.  Same answers, chosen by meaning, and nothing to
# clean up afterwards.

# ---------------------------------------------------------------------------- 3. mint
if run_phase 3; then
phase "3. mint the joiner's pioneer key"

# THIS PHASE MINTS THE KEY IT FUNDS, and that is the point.  Funding used to be ordered before the
# join, which cannot work on a first run: the key does not exist until add_full_node.sh creates it,
# and add_full_node.sh then BLOCKS waiting for that key to hold a balance.  So phase 3 no-opped,
# phase 4 polled 120x3s for money nobody was sending, and the documented way through was to run 4,
# then 3, then 4 again -- a cycle a linear phase list cannot express, and the reason --until 5 could
# not complete without someone funding from a second shell against a six-minute timer.
#
# add_full_node.sh --stop-for-funding breaks it: it mints the key, prints the address and exits,
# leaving the key on disk for the [c] resume branch that already existed.  Minting is therefore part
# of getting funded, and phase 4 goes back to being purely the join.
addr=$(ssh "$JOINER" "${SUDO_J}~/qadena/bin/qadenad --home ~/qadena keys show $PIONEER_NAME -a --keyring-backend test 2>/dev/null" | tr -d '\r')
if [[ ! "$addr" =~ ^qadena1 ]]; then
    info "no $PIONEER_NAME key yet -- minting it with --stop-for-funding"
    # ANSWERED BY FLAG, NOT BY A FEEDER.  add_full_node.sh takes --yes/--on-existing/--funded
    # since 2026-09-02, so the prompts are pre-answered as ARGUMENTS.  What this replaces was a
    # zsh script piped into a pseudo-terminal, watching the transcript for question TEXT and
    # printing an answer when it matched -- which answers by wording rather than by meaning,
    # breaks silently the moment a prompt is reworded, and leaves an orphan feeder looping for
    # questions that will never come (the kill below existed for exactly that).
    #
    # --on-existing s is correct HERE and only here: phase 3 mints, so any prior node state on
    # this machine is being deliberately replaced.  Phase 5 uses 'c' to KEEP the funded key.
    ssh "$JOINER" "rm -f /tmp/tnb_join.log; ${SUDO_J}nohup setsid zsh -c '~/qadena/scripts/add_full_node.sh \
  --pioneer $PIONEER_NAME \
  --advertise-ip-address $ADVERTISE_J \
  --genesis-pioneer-first-ip-address $ADVERTISE_P$SECOND_IP_ARG$TRUST_OFFSET_ARG \
  --yes --on-existing s --stop-for-funding' > /tmp/tnb_join.log 2>&1 & echo started" > /dev/null
    for i in {1..60}; do
        ssh "$JOINER" 'grep -aq "stopping for funding, as requested" /tmp/tnb_join.log' 2>/dev/null && break
        sleep 5
    done
    addr=$(ssh "$JOINER" "${SUDO_J}~/qadena/bin/qadenad --home ~/qadena keys show $PIONEER_NAME -a --keyring-backend test 2>/dev/null" | tr -d '\r')
    if [[ ! "$addr" =~ ^qadena1 ]]; then
        info "the key was not minted.  Last log lines:"
        ssh "$JOINER" 'tail -20 /tmp/tnb_join.log' 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^/      /'
        fail "could not mint $PIONEER_NAME on $JOINER"
    fi
    info "minted $PIONEER_NAME = $addr"

# WHAT TO SIGN, IF THE FUNDING IS NOT OURS TO DO.
#
# Phase 4 funds the joiner by signing ON THE PRIMARY.  That is right when the money is a single
# key the primary holds, and impossible when it is a multisig, an HSM, or a foundation
# elsewhere.  Rather than fail there, phase 3 ends by printing exactly what has to be signed, so
# an operator can skip phase 4 entirely and do it by their own ceremony.
#
# Printed unconditionally: a run that IS going on to phase 4 loses nothing by seeing what phase 4
# is about to do on its behalf.
print_funding_instructions "$addr"
print ""
fi
fi

# ---------------------------------------------------------------------------- 4. fund
# SPLIT OUT OF PHASE 3 on 2026-09-01.  Minting a key and PAYING for it are different jobs with
# different owners: the mint is mechanical and always identical, while the funding depends
# entirely on who holds the money.  Welded together, a custody model this script did not
# anticipate blocks the whole phase -- which is exactly what happened with a bucket held as a
# 3-of-5 multisig whose members are on a workstation, not on the primary: both branches below
# resolve the granter with `keys show` ON THE PRIMARY, so neither can sign for it.
#
# Split, `--until 3` mints and stops, the operator funds by whatever ceremony their custody
# requires, and `--from 5` carries on.  Nothing here changed except where the boundary sits.
if run_phase 4; then
phase "4. fund the joiner"
    # RESOLVE IT HERE TOO, because this phase must stand alone.  $addr is assigned in phase 3,
    # so `--from 4` (or 5, or 7) previously died on `addr: parameter not set` under `set -u` --
    # which defeats the phase-resumability this script exists to offer, and bites exactly when
    # something failed mid-run and you want to pick up where it stopped.
    if [[ -z "${addr:-}" ]]; then
        addr=$(ssh "$JOINER" "${SUDO_J}~/qadena/bin/qadenad --home ~/qadena keys show $PIONEER_NAME -a --keyring-backend test 2>/dev/null" | tr -d '\r')
        [[ "$addr" == qadena1* ]] \
            || fail "phase 4: $PIONEER_NAME has no key on $JOINER.  Run phase 3 first (it mints one)."
    fi
    info "joiner $PIONEER_NAME = $addr"
    if (( SPONSORED )); then
        # SPONSORED: no coins move.  Issue a fee grant from the granter to the joiner's pioneer key.
        # The grant is bounded (per-period budget + message allow-list) and recurring, because SS
        # rotation recurs for as long as the node runs -- a one-off grant would let the node join and
        # then quietly stop re-sharing SS keys.  See scripts/foundation_sponsor_node.sh.
        # AN ADDRESS IS A VALID GRANTER.  `keys show` can only answer for a key the PRIMARY
        # holds, which excludes every custody model where the money is not the primary's --
        # a multisig, an HSM, a foundation elsewhere.  Those grants are issued off-box and this
        # only needs the address to look the grant up, so accept one directly.
        if [[ "$SPONSOR_GRANTER" == qadena1* ]]; then
            gaddr="$SPONSOR_GRANTER"
        else
            gaddr=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena keys show $SPONSOR_GRANTER -a --keyring-backend test 2>/dev/null" | tr -d '\r')
        fi
        [[ -n "$gaddr" ]] || fail "granter '$SPONSOR_GRANTER' is not in the primary's keyring"
        existing=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena query feegrant grants-by-grantee $addr --output json 2>/dev/null | jq -r '.allowances[0].granter // \"\"'" | tr -d '\r')
        if [[ -n "$existing" ]]; then
            info "already sponsored by $existing -- nothing to do"
        else
            ssh "$PRIMARY" "test -x ~/qadena/scripts/foundation_sponsor_node.sh" \
                || fail "~/qadena/scripts/foundation_sponsor_node.sh is missing on the primary -- install the release package first"
            info "sponsoring $addr from $SPONSOR_GRANTER ($gaddr) -- no coins are sent"
            sp_out=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/scripts/foundation_sponsor_node.sh --node $addr --granter $SPONSOR_GRANTER" 2>&1) \
                || fail "sponsorship failed: $(print -r -- "$sp_out" | tail -3)"
            print -r -- "$sp_out" | grep -E "ok:|FAILED" | while read -r l; do info "  $l"; done
            got=""
            for _ in {1..20}; do
                sleep 3
                got=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena query feegrant grants-by-grantee $addr --output json 2>/dev/null | jq -r '.allowances[0].granter // \"\"'" | tr -d '\r')
                [[ -n "$got" ]] && break
            done
            [[ -n "$got" ]] || fail "the fee grant did not land for $addr -- $(print -r -- "$sp_out" | tail -3)"
            info "fee grant confirmed on chain, granter $got"
        fi
        # THE BOND MOVES HERE TOO, when a validator was declared.  One funding point, one
        # ceremony, one intervention for whoever holds the money.  Phase 7 then only converts.
        if (( CONVERT )); then
            ensure_self_bond
        fi
    elif true; then
    bal=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena query bank balances $addr --output json 2>/dev/null | jq -r '.balances[0].amount // \"0\"'" | tr -d '\r')
    # String test: aqdn balances overflow int64 (see the note on the wait loop below).
    if [[ -n "$bal" && "$bal" != "0" ]]; then
        info "already funded ($bal aqdn) -- nothing to do"
    else
        chainid=$(ssh "$PRIMARY" 'curl -s localhost:26657/status | jq -r ".result.node_info.network"' | tr -d '\r')
        amt="${FUND_QDN}000000000000000000"
        info "sending ${FUND_QDN}qdn from $FUNDER on chain $chainid"
        # KEEP THE BROADCAST REPLY AND READ ITS CODE.  This used to redirect the reply to /dev/null
        # and trust the exit status, but the CLI EXITS 0 EVEN WHEN THE JSON CARRIES A NON-ZERO
        # code -- a "gas prices too low" rejection (code 13) exits 0 just like a success does.  So a
        # REJECTED transfer was indistinguishable from a SLOW one, and the run always blamed the
        # slow case: it polled the balance, found nothing, and reported "funding did not land" for a
        # transfer the chain had refused outright and named its reason for.
        # PRICE THE TRANSFER FROM THE CHAIN'S CURRENT BASE FEE, NOT FROM A CONSTANT.
        #
        # This used to pay a hardcoded 0.025aqdn, which is wrong on a young chain and had never been
        # noticed.  Genesis sets base_fee = 1,000,000,000 aqdn and it decays 12.5% per empty block
        # (base_fee_change_denominator = 8), crossing below 0.025 at about HEIGHT 190.  Measured on
        # this fleet: h=125 -> 56.36, h=175 -> 0.071, h=200 -> 0.0025.
        #
        # Every path here used to go through a long wait first -- a state-sync bringup waits for the
        # primary to pass the snapshot interval, thousands of blocks -- so funding always ran on a
        # chain whose fee had decayed to ~1e-18 and the constant always worked.  --block-sync
        # removes that wait and funds at ~125, where the offered price is 2000x too low and the
        # chain rejects with code 13.  The constant was always wrong; the wait was hiding it.
        #
        # Twice the current fee, floored at the old constant: the fee is still falling while the
        # transfer is built and broadcast, so pricing exactly at it can be stale by the time it is
        # checked.
        base_fee=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena q feemarket params --output json 2>/dev/null" \
            | sed -n 's/.*"base_fee":"\([0-9.]*\)".*/\1/p' | head -1)
        gas_price=$(python3 -c "
from decimal import Decimal
bf = Decimal('${base_fee:-0}' or '0')
print(format(max(bf * 2, Decimal('0.025')), 'f'))
" 2>/dev/null)
        [[ -n "$gas_price" ]] || fail "could not read the chain's base fee to price the funding transfer"
        info "base fee ${base_fee:-?}aqdn -- funding at ${gas_price}aqdn"
        fund_out=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena tx bank send $FUNDER $addr ${amt}aqdn --keyring-backend test --chain-id $chainid --gas auto --gas-adjustment 1.5 --gas-prices ${gas_price}aqdn --yes --output json" 2>&1) \
            || fail "funding transfer failed to broadcast: $(print -r -- "$fund_out" | tail -3)"
        fund_code=$(print -r -- "$fund_out" | sed -n 's/.*"code":\([0-9]*\).*/\1/p' | head -1)
        if [[ -n "$fund_code" && "$fund_code" != "0" ]]; then
            fail "the chain REFUSED the funding transfer (code $fund_code): $(print -r -- "$fund_out" | sed -n 's/.*"raw_log":"\([^"]*\)".*/\1/p' | head -1)"
        fi
        fund_tx=$(print -r -- "$fund_out" | sed -n 's/.*"txhash":"\([A-F0-9]*\)".*/\1/p' | head -1)
        [[ -n "$fund_tx" ]] && info "funding tx $fund_tx broadcast; waiting for inclusion"
        # POLL FOR INCLUSION, DO NOT SLEEP A FIXED TWELVE SECONDS.  The broadcast above returns
        # height=0 -- accepted at CheckTx, not yet in a block -- and --gas auto spends a simulation
        # round trip before that.  On a chain seconds old, whose block cadence has not settled,
        # twelve seconds is regularly short, and the run then dies with "funding did not land" for a
        # transfer that lands moments later.
        #
        # This was masked for as long as this phase only ever ran against an established chain: a
        # state-sync bringup waits for the primary to pass the snapshot interval first, which is
        # tens of minutes.  --block-sync removes that wait and funds at height ~125, which is where
        # it surfaced.  The transfer was never the problem; the budget was.
        bal=0
        for _ in {1..20}; do
            sleep 6
            bal=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena query bank balances $addr --output json 2>/dev/null | jq -r '.balances[0].amount // \"0\"'" | tr -d '\r')
            # STRING TEST, NOT ARITHMETIC.  aqdn balances routinely exceed int64: 10,100 QDN is
            # 1.01e22 and zsh's -gt tops out near 9.2e18, so a real balance compares as ZERO and
            # the loop times out on money that arrived.  Measured 2026-09-02 -- the funding tx
            # was code 0 at height 36 and this still reported "did not land".  The devnet never
            # hit it because its test amounts are smaller.
            [[ -n "$bal" && "$bal" != "0" ]] && break
        done
        if [[ -z "$bal" || "$bal" == "0" ]]; then
            # ASK THE CHAIN WHAT BECAME OF IT rather than leaving the reader to.  CheckTx passed, so
            # the interesting answer is in DeliverTx -- and if the hash is simply unknown, the tx
            # never made it into a block at all, which is a different problem from one that ran and
            # failed.
            deliver=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena q tx ${fund_tx} --output json 2>&1" | tail -3)
            fail "funding did not land within 2 minutes.  Broadcast was accepted (code 0), so this is
         inclusion or execution.  The chain says of ${fund_tx:-the tx}:
         $deliver"
        fi
        info "funded: $bal aqdn"
    fi
fi
fi

# ---------------------------------------------------------------------------- 5. join
if run_phase 5; then
if (( STATE_SYNC )); then
    phase "5. join (STATE-SYNC)"
    # add_full_node.sh enables statesync only when BOTH genesis-pioneer IPs are given: it reads the
    # trust height and hash from the first, re-reads that exact height from the second, and refuses
    # unless they match.
    #
    # DEFAULTING SEED2 TO THE PRIMARY IS A DEGENERATE CROSS-CHECK -- it proves the primary agrees
    # with itself, which is the most a two-node chain can offer and is worth naming rather than
    # glossing.  From the third node onward, pass --seed2 <an existing peer>: the height and hash
    # are then corroborated by a source that could actually disagree, which is the check the
    # mechanism was designed for.
    [[ -n "$SEED2" ]] || info "no --seed2 given: using the primary for both trust sources (self-corroborating)"
    :
else
    phase "5. join (block-sync)"
fi

# WHICH SYNC IS CHOSEN BY THE NUMBER OF SEED ADDRESSES, not by a flag on add_full_node.sh: it turns
# statesync on only when a SECOND genesis-pioneer IP is supplied AND both report the same trust
# height and hash.  Block-sync is therefore the default here on purpose -- a first join should
# exercise the ordinary path so a failure is unambiguous -- and --state-sync opts into the other.
#
# Driven under script(1) for a real PTY (trap 2).  The feeder answers 'c' first when the node is
# already part-initialised -- the resume branch, which keeps the key that has already been funded;
# 's' would erase and mint a new one, stranding the funds.  The LAST answer is 'n': we start the
# node ourselves in phase 5 (trap 3).
# RESOLVE THE HOME DIRECTORY UNPRIVILEGED, then bake the absolute path in.  Writing
# /home/$(whoami) inside the script evaluates it ON THE JOINER, UNDER SUDO, where whoami is root --
# yielding /home/root/qadena/scripts/add_full_node.sh, which does not exist.  The failure is one
# line in a log on the other machine and looks like a bad install rather than a quoting bug.  This
# is the same trap repo_on() documents; it just was not applied here.
ssh "$JOINER" "test -x $JOINER_HOME/qadena/scripts/add_full_node.sh" \
    || fail "$JOINER_HOME/qadena/scripts/add_full_node.sh is missing -- install the release package first"

# SPONSORED JOIN: tell add_full_node.sh to wait for the FEE GRANT phase 3 issued, not for a
# balance that will never arrive.  The granter address is passed so the joiner pins it rather than
# accepting whatever grant happens to exist.
SPONSOR_ARG=""
if (( SPONSORED )); then
    # Resolve the granter HERE too.  gaddr is set in phase 3, but --only/--from let phase 4 run on
    # its own, and an unset gaddr would silently degrade to "any" -- accepting whatever grant
    # happened to exist rather than the one we issued.
    if [[ -z "${gaddr:-}" ]]; then
        # AN ADDRESS IS A VALID GRANTER.  `keys show` can only answer for a key the PRIMARY
        # holds, which excludes every custody model where the money is not the primary's --
        # a multisig, an HSM, a foundation elsewhere.  Those grants are issued off-box and this
        # only needs the address to look the grant up, so accept one directly.
        if [[ "$SPONSOR_GRANTER" == qadena1* ]]; then
            gaddr="$SPONSOR_GRANTER"
        else
            gaddr=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena keys show $SPONSOR_GRANTER -a --keyring-backend test 2>/dev/null" | tr -d '\r')
        fi
    fi
    [[ -n "${gaddr:-}" ]] || fail "--foundation-sponsored: cannot resolve granter '$SPONSOR_GRANTER' on the primary"
    SPONSOR_ARG=" --foundation-sponsored $gaddr"
    info "joiner will wait for a fee grant from $SPONSOR_GRANTER ($gaddr), not for a balance"
fi

# --on-existing c KEEPS the key phase 3 minted and the sponsor funded.  's' would erase it, and
# a funded pioneer address cannot send its coins back (AML 1159), so they would be stranded.
# --funded: the money is already on chain -- phases 4 and the ceremony saw to that -- so do not
# stop and ask.  --no-start-node because this script starts it in phase 6 and watches it.
info "driving add_full_node.sh (flags, no PTY); fetches genesis and runs sync-enclave"
ssh "$JOINER" "rm -f /tmp/tnb_join.log; ${SUDO_J}nohup setsid zsh -c '~/qadena/scripts/add_full_node.sh \
  --pioneer $PIONEER_NAME \
  --advertise-ip-address $ADVERTISE_J \
  --genesis-pioneer-first-ip-address $ADVERTISE_P$SECOND_IP_ARG$TRUST_OFFSET_ARG$SPONSOR_ARG \
  --yes --on-existing c --funded --no-start-node' > /tmp/tnb_join.log 2>&1 & echo started" > /dev/null

# SURFACE THE ADDRESS AND THE STAGE HERE, rather than leaving them in a log on the other machine.
# add_full_node.sh prints the pioneer address once and then polls silently for the balance; anyone
# watching has to ssh over and grep the transcript to learn what to fund -- and reading that file
# before this phase recreates it returns the PREVIOUS run's contents, which is a convincing way to
# be told the wrong thing.  (This phase does clear it, at the rm -f above; the trap is reading it
# from outside.)
announced=0
for i in {1..60}; do
    if ssh "$JOINER" 'grep -aq "SyncEnclave SUCCEEDED" /tmp/tnb_join.log' 2>/dev/null; then
        info "SyncEnclave SUCCEEDED -- params are on the joiner"
        break
    fi
    if (( ! announced )) && ssh "$JOINER" 'grep -aq "attempt to detect" /tmp/tnb_join.log' 2>/dev/null; then
        pa=$(ssh "$JOINER" "grep -a 'PIONEER ADDRESS' /tmp/tnb_join.log | tail -1 | awk '{print \$NF}'" 2>/dev/null | tr -d '\r')
        info "at the funding poll for ${PIONEER_NAME}${pa:+ = $pa}"
        info "  it polls 120x3s and then gives up -- fund it now with:"
        info "  ./testscripts/nth_node_bringup.sh --primary $PRIMARY --joiner $JOINER --pioneer $PIONEER_NAME --only 3"
        announced=1
    fi
    sleep 10
done
ssh "$JOINER" 'grep -aq "SyncEnclave SUCCEEDED" /tmp/tnb_join.log' 2>/dev/null \
    || fail "sync-enclave did not succeed; see /tmp/tnb_join.log on $JOINER"

# Params must be on disk BEFORE the node executes a block -- that is the whole reason a block-sync
# joiner works at all.
ssh "$JOINER" "${SUDO_J}ls ~/qadena/enclave_config/enclave_params_*.json" > /dev/null 2>&1 \
    || fail "sync-enclave reported success but wrote no enclave_params file"
info "enclave params persisted"

# Leave nothing holding a PTY open.  By PID (trap 1).
for p in $(ssh "$JOINER" 'pgrep -f "[t]nb_feed|[t]nb_join|[a]dd_full_node" 2>/dev/null'); do
    ssh "$JOINER" "${SUDO_J}kill -9 $p" 2>/dev/null
done
fi

# ---------------------------------------------------------------------------- 6. start
if run_phase 6; then
phase "6. start the joiner and catch up"

# Standalone, NOT from inside add_full_node.sh (trap 3).
# REDIRECT ON THE REMOTE SIDE, INSIDE THE QUOTES.  This used to end with `> /dev/null 2>&1` outside
# them, which only silences the ssh client here and leaves the node holding the ssh channel's
# stdout and stderr on the other end.  ssh does not exit while ANY process still has that channel
# open -- not merely the direct child -- so the node came up, synced normally, and this line blocked
# forever.  The symptom is the worst kind: the joiner is visibly healthy while the harness looks
# hung, so the natural conclusion is that the START failed, which is the one thing that did not.
#
# nohup does not save us: it redirects only when stdout is a TERMINAL, and over ssh without -t it is
# a pipe, so restart_qadena.sh's `nohup ... &` still inherits this channel.
# WHERE THIS RUN'S LOG BEGINS.  add_full_node.sh removes config, data, keyring-test and the three
# enclave directories -- but NOT logs/ -- so a re-joined node still carries the log of every previous
# attempt, including the failed ones.  Grepping the whole file would report those as this run's
# errors.  (1st_node_bringup has no such problem: init.sh does `rm -rf $QADENAHOME`, logs included.)
# Anchor to a byte offset taken before the node starts, and read only forward from here.
JOINER_LOG_OFFSET=$(ssh -n "$JOINER" "wc -c < $JOINER_HOME/qadena/logs/qadena.log 2>/dev/null || echo 0" | tr -d '\r ')
: ${JOINER_LOG_OFFSET:=0}

ssh -n "$JOINER" "${SUDO_J}zsh -lc 'cd $JOINER_HOME/qadena/scripts && ./start_qadena.sh' > /dev/null 2>&1 < /dev/null" \
    || fail "start_qadena.sh returned non-zero on $JOINER"
info "start_qadena.sh returned (it backgrounds run.sh and exits; the node comes up behind it)"

# jlog <n> -- the last n lines of the joiner's node log, ANSI stripped, indented.  Every failure
# below prints this, because 'check the logs on the other machine' is an instruction to do the
# debugging again rather than a report of what went wrong.
jlog() {
    ssh "$JOINER" "L=\$(ls -t $JOINER_HOME/qadena/logs/qadena-*.log 2>/dev/null | head -1); \
                   [[ -n \"\$L\" ]] && tail -${1:-25} \"\$L\"" 2>/dev/null \
        | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^/      /'
}

# STAGE 1: the processes.  Distinguished from 'RPC not answering' because they fail for different
# reasons -- a missing binary or a dead enclave here, a slow restore there.
for i in {1..30}; do
    np=$(ssh "$JOINER" 'pgrep -c qadenad 2>/dev/null; true' | tr -d '\r' | head -1)
    [[ "${np:-0}" -ge 1 ]] && break
    sleep 2
done
if [[ "${np:-0}" -lt 1 ]]; then
    info "no qadenad process appeared.  Last log lines:"
    jlog 30
    fail "the node did not start on $JOINER"
fi
# Report the count, not an assumption about which.  The enclave comes up first and the node a
# moment later, so "1" here is normal and "1 (qadenad + enclave)" was simply wrong.
info "qadenad processes up: $np"

# STAGE 2: the RPC.  A state-sync joiner can sit here for a while: it discovers snapshots, fetches
# chunks and restores them BEFORE serving status, so an empty reply is normal early and alarming
# late.  The old code slept 30s once and declared failure, which on a slow restore reported a
# healthy node as dead.
if (( STATE_SYNC )); then
    info "waiting for RPC (state-sync: the node discovers a snapshot and restores it before serving)"
else
    info "waiting for RPC"
fi
jh=""
for i in {1..60}; do
    jh=$(height "$JOINER")
    [[ -n "$jh" ]] && break
    if (( i % 5 == 0 )); then
        snap=$(ssh "$JOINER" "L=\$(ls -t $JOINER_HOME/qadena/logs/qadena-*.log 2>/dev/null | head -1); \
                              [[ -n \"\$L\" ]] && grep -a 'snapshot\|Snapshot' \"\$L\" | tail -1" 2>/dev/null \
               | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-120)
        info "  ... no RPC yet (${i}0s)${snap:+ -- $snap}"
    fi
    sleep 10
done
if [[ -z "$jh" ]]; then
    info "RPC never answered.  Last log lines:"
    jlog 30
    fail "joiner did not start serving RPC on $JOINER"
fi
info "joiner serving RPC at height $jh"

# STAGE 3: catch-up.  Report the MODE honestly -- the old text said 'block-syncing ... by executing
# each block', which is what state-sync exists to avoid, so a state-synced run narrated the wrong
# mechanism at exactly the moment someone would be reading it to understand a stall.
if (( STATE_SYNC )); then
    info "catching up from the restored snapshot (enclave-private tables are SEEDED and IMPORTED, not replayed)"
else
    info "block-syncing (rebuilds every enclave-private table by executing each block; slow and correct)"
fi
# TWO HOURS IS FOR A SLOW SYNC, NOT A DEAD ONE.  This loop only ever asked "is catching_up still
# true", so a joiner that had DIVERGED -- pinned at one height while the primary ran away -- was
# indistinguishable from one that was merely behind, and the run spent the full two hours before
# saying so.  Measured on the 2026-08-26 negative control: the joiner stopped at height 3 with
# "wrong Block.Header.AppHash" already in its log at 05:40, and the harness would not have reported
# it until 06:39.  For a CI gate that is the difference between usable and not.
#
# A DIVERGENCE IS FATAL IMMEDIATELY.  No amount of waiting resolves a block whose app hash does not
# reproduce, so the app-hash line is checked on the same cadence as the progress line -- no extra
# ssh -- and fails the moment it appears, quoting it.
#
# A STALL IS NOT, AT LEAST NOT AT ONCE.  A joiner's FIRST block can legitimately take minutes: a
# fresh enclave seeds its mirrored stores and may import private state from a peer, and height
# cannot advance while either is in flight.  That is why the deleted delayed_init_enclave.sh
# tolerated ten minutes of no progress before calling a sync dead, and why this requires the stall
# to PERSIST -- and to be a stall, not a pause, by insisting the PRIMARY moved while the joiner did
# not.  A fleet that is quiet everywhere is not this failure.
stall_since_h=""; stall_polls=0
for i in {1..480}; do
    cu=$(ssh "$JOINER" 'curl -s --max-time 5 localhost:26657/status 2>/dev/null | jq -r ".result.sync_info.catching_up"' | tr -d '\r')
    [[ "$cu" == "false" ]] && break
    if (( i % 8 == 0 )); then
        jn=$(height "$JOINER"); pn=$(height "$PRIMARY")
        info "  ... joiner ${jn:-?} / primary ${pn:-?}${jn:+ (behind by $(( ${pn:-0} - ${jn:-0} )))}"

        diverged=$(ssh -n "$JOINER" "tail -c +${JOINER_LOG_OFFSET} $JOINER_HOME/qadena/logs/qadena.log 2>/dev/null \
            | sed 's/\x1b\[[0-9;]*m//g' | grep -a 'wrong Block.Header.AppHash' | tail -1" | tr -d '\r')
        if [[ -n "$diverged" ]]; then
            info "$diverged"
            fail "the joiner DIVERGED at height ${jn:-?}: it computed a different app hash than the chain \
recorded, so no amount of catching up will resolve it.  Compare /block_results at that height on both \
nodes -- identical events with different gas_used means a store operation was added or removed, which \
is consensus-affecting and needs an upgrade height."
        fi

        # Only a stall if the joiner is frozen AND the chain is not.
        if [[ -n "$jn" && "$jn" == "$stall_since_h" && -n "$pn" && "$pn" -gt "$jn" ]]; then
            (( stall_polls++ ))
            if (( stall_polls >= 5 )); then      # 5 * 8 polls * 15s = 10 minutes
                info "still catching up, but the joiner has not advanced.  Last log lines:"
                jlog 30
                fail "the joiner has been stuck at height $jn for ten minutes while the primary reached \
$pn.  That is not a slow sync.  Nothing in its log names an app-hash mismatch, so look for a halt, a \
panic, or an enclave that stopped answering."
            fi
        else
            stall_since_h="$jn"; stall_polls=0
        fi
    fi
    sleep 15
done
if [[ "$cu" != "false" ]]; then
    info "still catching up after two hours.  Last log lines:"
    jlog 30
    fail "joiner did not catch up within two hours"
fi
info "caught up at $(height "$JOINER")"

# DID THE JOINER COMPLAIN?  Nothing here used to look, so both joins were reported PASS while 1,806
# and 410 ERROR lines were being written -- the same shape as the two-validator fork that was
# reported as "16 of 16 SUITES PASSED".  A bring-up that cannot see the node's own errors is not
# checking the thing it exists to check.
#
# The allow-list is deliberately SHORT and each entry is justified.  Anything unexplained fails the
# run: an error nobody has classified is exactly the one worth stopping for.
# THE BOUNDARY HALT IS NOT AN ERROR ON A MANAGED JOINER -- it is the mechanism working.  A node
# replaying history across a scheduled upgrade MUST stop at the plan height; x/upgrade says so at
# ERROR level, three lines' worth (the plan message, the FinalizeBlock wrapper, and the panic).
#
# Scoped deliberately, in two ways, because a blanket exemption would hide the failure this whole
# effort is about.  It applies only when the joiner is cosmovisor-MANAGED, and only to a halt whose
# plan name the node has since PERFORMED -- `current` points at that upgrade.  A halt for a plan
# that was never performed, or on an unmanaged node, still fails the run: that node is stuck, and
# stuck is exactly what must not be reported green.
CV_HALT_RE='__no_match_sentinel__'
cv_plan=$(ssh -n "$JOINER" 'readlink $HOME/qadena/cosmovisor/current 2>/dev/null' 2>/dev/null | tr -d '\r')
if [[ "$cv_plan" == upgrades/* ]]; then
    cv_name="${cv_plan#upgrades/}"
    # `.*` around the name rather than literal quotes: CometBFT re-logs the same message nested
    # inside err="...", where the quotes come through BACKSLASH-ESCAPED.  Matching on the plan
    # name and the word NEEDED covers both spellings without inviting a quoting bug.
    CV_HALT_RE="UPGRADE .*$cv_name.* NEEDED"
    info "cosmovisor-managed joiner: allowing the halt for '$cv_name', which it has since performed"
fi

info "checking the joiner's log for errors raised during this run"
joiner_errors=$(ssh -n "$JOINER" "tail -c +${JOINER_LOG_OFFSET} $JOINER_HOME/qadena/logs/qadena.log 2>/dev/null" \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -a " ERR " \
    | grep -avE "Failed to write response|error while stopping connection|use of closed network connection|Stopped accept routine|transport is closed" \
    | grep -avE "Stopping peer for error|Could not ping the enclave|dial unix /tmp/qadena_.*sock" \
    | grep -avE "PER-BLOCK ACC DIVERGENCE" \
    | grep -avE "codespace qadena code|refusing |ephemeral wallet is empty|Ephemeral.s destination wallet" \
    | grep -avE "credential hash (already )?(exists|belongs)|update rate limited|ScanTransaction failed" \
    | grep -avE "enclaveSynchronizeStores OUT-OF-SYNC|couldn't find an active enclave identity" \
    | grep -avE "SignerListener: Error accepting connection" \
    | grep -avE "failed to fetch block .*is not available, lowest height is" \
    | grep -avE "got an already committed block" \
    | grep -avE "ss-reconstruct: no address for pioneer" \
    `# A BLOCKSYNC PEER THAT WENT QUIET, not a node problem.  CometBFT's blocksync reactor gives a
     # peer 15s to answer a block request; if it does not, the reactor logs SendTimeout, DROPS that
     # peer and asks another.  Recovering from a slow peer is the mechanism working, and on a fleet
     # where three joiners catch up in sequence it is ordinary traffic -- M4 hit exactly one on
     # 2026-08-30 and failed an otherwise clean join.
     #
     # Scoped to the blocksync module and that reason string on purpose: a SendTimeout from
     # consensus, or any other reason text, still fails the run.  Peers going quiet during CONSENSUS
     # is the two-validator-fork shape this check exists to catch.` \
    | grep -avE 'SendTimeout module=blocksync .*peer did not send us anything' \
    | grep -avE "$CV_HALT_RE" \
      | grep -avE "ss-reconstruct: LAZY PATH")

# COUNTED, NOT MERELY FORGIVEN.  The enclave logs LAZY PATH at ERROR level on purpose and says so at
# the call site: "its COUNT is the metric that says whether the eager path is doing its job".
# Filtering it out of the failure list and saying nothing would discard exactly the signal the error
# level exists to carry, so it is reported here instead.
lazy_n=$(ssh -n "$JOINER" "tail -c +${JOINER_LOG_OFFSET} $JOINER_HOME/qadena/logs/qadena.log 2>/dev/null" \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -ac "ss-reconstruct: LAZY PATH" || true)
# COUNTED, NOT MERELY FORGIVEN -- same reasoning as LAZY PATH below.
#
# "no address for pioneer X" means an OWNER of a key could not be dialled for its share.  On a
# joiner this is expected and bounded: its owners map arrives CURRENT from sync-enclave, while its
# chain view is still catching up, so an owner that published its address after the snapshot looks
# unaddressable until replay reaches that block.  Widened deliberately by 1a149b4b, which returned
# first publication to updateIsValidator under IsProposer -- an address now means BONDED AND
# PROPOSED, so it lands later than it used to.
#
# NOT harmless in general, which is why it is reported rather than dropped: enclave_external_address.go
# exists because an owner nobody can dial makes the chain OVERSTATE custody.  The failures that
# matter -- INSUFFICIENT and EXHAUSTED, meaning the key could not be gathered at all -- are
# deliberately absent from the filter above and still fail the run.
noaddr_n=$(ssh -n "$JOINER" "tail -c +${JOINER_LOG_OFFSET} $JOINER_HOME/qadena/logs/qadena.log 2>/dev/null" \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -ac "ss-reconstruct: no address for pioneer" || true)
if [[ "${noaddr_n:-0}" -gt 0 ]] 2>/dev/null; then
    info "ss-reconstruct could not dial an owner ${noaddr_n} time(s) -- expected while catching up, as an"
    info "  owner that published after this node's snapshot looks unaddressable until replay reaches it."
    info "  A count that keeps growing once caught up is a node that never published: check its bonding."
fi
if [[ "${lazy_n:-0}" -gt 0 ]] 2>/dev/null; then
    info "ss-reconstruct took the LAZY PATH ${lazy_n} time(s) -- expected for a joiner reaching for"
    info "  history it never saw.  Watch the count; INSUFFICIENT/EXHAUSTED are NOT allowed and fail."
fi
#   THE ALLOW-LIST, and why each entry is not evidence of trouble:
#
#   p2p/websocket/rpc-server lines   shutdown noise from stop_qadena.sh; the enclave ping failures
#                                    are the socket disappearing during that stop.
#   PER-BLOCK ACC DIVERGENCE         the known, bounded catch-up window -- a joiner's enclave holds
#                                    its own keys before the chain records them (backlog 63).
#   transaction REJECTIONS           `codespace qadena code`, `refusing ...`, empty ephemeral
#                                    wallets, duplicate credential hashes, rate limits.  These are
#                                    the regression suite's DELIBERATE negative tests being
#                                    re-executed as the joiner replays history.  A rejected
#                                    transaction is consensus-visible: every node replaying that
#                                    chain logs the same line, so it cannot indicate node-local
#                                    trouble.  46 of them failed the first run of this check.
#   enclaveSynchronizeStores         a fresh enclave being seeded from the chain at startup.
#   couldn't find an active enclave  a replayed promotion attested by the PREVIOUS measurement,
#   identity                         which a joiner has no reason to trust; the row is recorded and
#                                    reconcileTrustOnGoingLive settles it.
#
#   SignerListener accept       CometBFT's privval listener, not ours.  The signer CONNECTS first
#   timeout                     ("SignerListener: Connected"), the listener then loops back to
#                               accept a second connection that never comes, and times out once.
#                               Verified on the SGX state-sync join: exactly one occurrence, after
#                               a successful connect.  A signer that never connected would fail the
#                               run at block production, not here.
#   evm indexer "height 1 is    the EVM indexer walking from block 1 on a STATE-SYNCED node whose
#   not available, lowest       history starts at the snapshot.  Structural to state-sync and
#   height is N"                cosmetic: the blocks below the snapshot do not exist by design.
#
#   "got an already committed    blocksync asked SEVERAL peers for overlapping ranges and a second
#   block #N (possibly from      copy of a block arrived after the first was committed.  Whichever
#   the slow peer ...)"          peer answers second loses the race; the loser's copy is discarded.
#                                CONSENSUS-NEUTRAL BY CONSTRUCTION: it is about which peer replied
#                                first, not about what the block contained -- a block whose CONTENT
#                                disagreed fails as a wrong-AppHash or a bad-commit line instead,
#                                and neither is allowed here.
#                                WHERE IN THE JOIN IT HAPPENS, checked rather than assumed: AFTER
#                                state-sync has restored the snapshot and handed over to blocksync
#                                to catch up to the tip.  On the 2026-08-26 run .52 restored at
#                                height 2001 and every one of these errors named a block between
#                                #2032 and #2202 -- above the snapshot, inside the catch-up window,
#                                tagged module=blocksync.  None occurred during state-sync itself,
#                                which is why this entry is safe to allow: it forgives duplicate
#                                DELIVERY during catch-up, not anything about restoring a snapshot.
#                                STRUCTURALLY INVISIBLE UNTIL THE THIRD NODE, which is why this
#                                arrived late: the first joiner has exactly one peer to ask, so no
#                                range can overlap.  pioneer2 (peers: M1) logged 0; pioneer3 (peers:
#                                M1 and M2) logged 17, from both .162 and .154 -- and the joiner was
#                                caught up and healthy at the moment the run was failed over them.
#
#   ss-reconstruct: LAZY PATH   a joiner reaching for an SS interval key from before it existed.
#                               getSSPrivK names this case itself -- "a node needing a HISTORICAL
#                               key it never saw ... has no such trigger, and this is the only way
#                               it can obtain one" -- and logs it at ERROR "on purpose ... A
#                               historical key legitimately lands here, so it is not automatically
#                               a defect".  Unlike the transaction rejections above this IS
#                               node-local: a node that already owns the key never takes this path.
#                               Allowed only because a joiner by definition lacks history, and
#                               COUNTED above rather than silently dropped.
#                               NOT allowed, and deliberately absent from the filter: INSUFFICIENT
#                               and EXHAUSTED.  Those mean the key could not be gathered at all,
#                               which backlog 90 says the caller must HALT on -- returning "" is a
#                               node-local answer a healthy peer will not produce, i.e. a fork.
#
#   What is deliberately NOT allowed: panics, halts, consensus failures, and divergence while LIVE.
#   Those are node-local and mean something.
if [[ -n "$joiner_errors" ]]; then
    info "UNEXPECTED errors in the joiner's log:"
    print -r -- "$joiner_errors" | head -20 | sed 's/^/      /'
    n=$(print -r -- "$joiner_errors" | wc -l | tr -d ' ')
    fail "the joiner logged $n unexplained error line(s) during this run -- \
a green bring-up over a complaining node is how a fork gets reported as a pass. \
If these are benign, add them to the allow-list in this script WITH the reason."
fi
info "no unexplained errors in the joiner's log"

# EARLIEST HEIGHT IS THE PROOF OF WHICH PATH RAN.  A state-synced node starts its store at the
# snapshot; a block-synced one has everything from 1.  Asserting it means --state-sync cannot
# silently degrade to block-sync -- which it has done before, when the trust height was too low.
eh=$(ssh "$JOINER" 'curl -s --max-time 5 localhost:26657/status 2>/dev/null | jq -r ".result.sync_info.earliest_block_height"' | tr -d '\r')
info "earliest block on the joiner: ${eh:-?}"
if (( STATE_SYNC )); then
    if [[ "${eh:-1}" == "1" ]]; then
        info "WARNING: earliest is 1, so this node BLOCK-SYNCED despite --state-sync."
        info "         add_full_node.sh silently falls back when the trust height is <= 1500 or the"
        info "         two seeds disagree.  The run is valid, but it did not test state-sync."
    else
        info "confirmed STATE-SYNCED: the store begins at the snapshot, not at genesis"
    fi
fi

ssh "$JOINER" "${SUDO_J}~/qadena/bin/qadenad --home ~/qadena enclave height" 2>/dev/null | sed 's/^/  /'
fi

# ---------------------------------------------------------------------------- 7. validator
if run_phase 7; then
if (( ! CONVERT )); then
    info "phase 7 skipped: no --convert-to-validator.  This run produced a FULL NODE, which is"
    info "add_full_node.sh's whole product; validating is a separate act.  Re-run with"
    info "  --convert-to-validator --from 7"
    info "when this node should bond (the self-bond is sent then, not before)."
else
phase "7. convert to validator and split the stake"

# THE SELF-BOND IS SENT BY THE FOUNDATION, because on this chain there is nowhere else it can come
# from -- QDN originates only from the foundation, so an operator's stake necessarily did too.
#
# It is a TRANSFER, not a grant, and that is what keeps the risk in the right place: once sent the
# tokens are the node's own, they are what gets bonded, and slashing burns them.  A fee grant could
# not do this job anyway -- it separates who signs from who pays FEES, and staked principal is
# neither.  foundation_sponsor_node.sh --self-bond owns this so the rule lives with the grant logic
# rather than being re-implemented here.
if (( SPONSORED )); then
    # Safety net for resumed runs (--from 7): phase 4 delivers the bond when the run declared a
    # validator, so this normally sees it and does nothing.  See ensure_self_bond.
    ensure_self_bond
    # convert_to_validator.sh polls for the balance to land, so nothing sleeps here.
fi

# ${pipestatus[1]}, NOT the pipeline's status.  A pipeline exits with its LAST command -- here sed,
# which always succeeds -- so convert_to_validator.sh's `exit 1` was thrown away and the phase
# reported success on a node that never bonded.  The run then spent its full twenty-minute
# wait_addressable timeout on a node that could never propose a block, and the real message
# ("Couldn't find balance") scrolled past five lines earlier.  Same trap fleet_bringup_with_tests.sh
# documents in run_scheduled.  Observed 2026-08-31 on pioneer2.
ssh "$JOINER" "${SUDO_J}zsh -lc 'cd $JOINER_HOME/qadena/scripts && ./convert_to_validator.sh --validator-stake $VALIDATOR_STAKE$SPONSOR_CV_ARG'" 2>&1 | tail -5 | sed 's/^/  /'
(( ${pipestatus[1]} == 0 )) || fail "phase 6: convert_to_validator.sh failed on $JOINER -- see the lines above. The node is NOT a validator, so it will never propose a block and never become addressable."
sleep 20

# setup_prerequisites splits the treasury delegation across ALL bonded validators, so it has to run
# AFTER the joiner bonds or the split does not include it.
info "re-running setup_prerequisites so the treasury delegation splits across the validators"
prep_repo=$(repo_on "$PRIMARY") || fail "cannot locate the checkout on $PRIMARY"
ssh "$PRIMARY" "${SUDO_P}zsh -lc $(printf '%q' "cd $prep_repo && ./testscripts/setup_prerequisites.sh")" > /dev/null 2>&1 \
    || info "  (setup_prerequisites returned non-zero -- check manually)"

info "voting power:"
ssh "$PRIMARY" 'curl -s localhost:26657/validators | jq -r ".result.validators[] | \"  \(.address) \(.voting_power)\""' 2>/dev/null | sed 's/^/  /'

# NO validator may reach 2/3, or "the peers disagree" can never be observed: one node would
# simply carry the chain regardless of the other.
tot=$(ssh "$PRIMARY" 'curl -s localhost:26657/validators | jq -r "[.result.validators[].voting_power|tonumber]|add"' | tr -d '\r')
mx=$(ssh "$PRIMARY" 'curl -s localhost:26657/validators | jq -r "[.result.validators[].voting_power|tonumber]|max"' | tr -d '\r')
if [[ -n "$tot" && -n "$mx" ]] && (( mx * 3 >= tot * 2 )); then
    info "WARNING: one validator holds $mx/$tot (>= 2/3).  A disagreement between the nodes"
    info "         cannot be observed at this split -- re-run setup_prerequisites or delegate more."
else
    info "no validator holds >= 2/3 ($mx of $tot) -- disagreement is observable"
fi
fi
fi

# ---------------------------------------------------------------------------- 8. agreement
if run_phase 8; then
phase "8. peer agreement"

# The first run of this that can compare anything: on a single node it prints NOTHING COMPARED and
# says to treat that as 'not tested'.
repo=$(repo_on "$PRIMARY") || fail "cannot locate the checkout on $PRIMARY"

# Capture the status of the SSH, not of the last element of a pipeline.  `cmd | tail | sed; rc=$?`
# reports sed's status -- which is always 0 -- so the suite announces success no matter what
# happened.  A harness that passes while testing nothing is worse than no harness.
out=$(ssh "$PRIMARY" "${SUDO_P}zsh -lc $(printf '%q' "cd $repo && ./testscripts/test_peer_agreement.sh")" 2>&1)
rc=$?
print -r -- "$out" | tail -20 | sed 's/^/  /'

# Belt and braces: the suite exits 0 when it has NO PEERS and says to treat that as 'not tested'.
# Passing on that would be the same false green in a different costume.
if print -r -- "$out" | grep -q "NOTHING COMPARED"; then
    rc=1
    print ""
    print "  NOT A PASS: the suite found no peers and compared nothing."
fi

print ""
print "======================================================================"
if [[ $rc -eq 0 ]]; then
    print "NTH-NODE BRING-UP COMPLETE ($PIONEER_NAME) -- the nodes agree on the same app hash at the same height)"
    print ""
    # SAY WHICH PATH ACTUALLY RAN.  This used to print the block-sync caveat unconditionally, so a
    # --state-sync run ended by announcing that state-sync was not covered -- in the same output
    # that had just state-synced a node.  The script knows the mode; the note must use it.
    if [[ $STATE_SYNC -eq 1 ]]; then
        print "This proves a STATE-SYNC joiner agrees: it restored a snapshot, imported the"
        print "enclave-private tables from the seed, and reached the same app hash."
        print ""
        print "Note what is still NOT covered: this run has no NEGATIVE CONTROL.  It shows the peers"
        print "AGREE with the private-state import working; it does not show the test would CATCH a"
        print "broken import.  Repeat with the import disabled and confirm the peers DO diverge, or"
        print "a pass cannot distinguish 'fixed' from 'the scenario never happened'."
    else
        print "Note what is still NOT covered: this proves a BLOCK-SYNC joiner agrees.  The state-sync"
        print "path -- and the private-state transfer it depends on -- is a separate exercise, and its"
        print "test needs a NEGATIVE CONTROL (repeat with the import disabled and confirm the peers DO"
        print "diverge), or it cannot distinguish 'fixed' from 'the scenario never happened'."
    fi
else
    print "PEER AGREEMENT FAILED -- the two nodes do not agree.  That is a fork; investigate before"
    print "running anything else."
fi
print "======================================================================"
exit $rc
fi
