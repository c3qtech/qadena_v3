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
ONLY=""
VALIDATOR_STAKE="110000"
FUND_QDN="200000"
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
        --from)    FROM="$2";    shift 2 ;;
        --only)    ONLY="$2";    shift 2 ;;
        --stake)   VALIDATOR_STAKE="$2"; shift 2 ;;
        --pioneer) PIONEER_NAME="$2"; shift 2 ;;
        --state-sync) STATE_SYNC=1; shift ;;
        --seed2)   SEED2="$2"; shift 2 ;;
        --help)
            print "Usage: nth_node_bringup.sh --primary <ip> --joiner <ip> [--from N] [--only N] [--stake qdn]"
            print "                          [--pioneer <name>] [--state-sync] [--seed2 <ip>]"
            print ""
            print "  --pioneer     the joiner's pioneer name (default pioneer2).  MUST BE UNUSED ON"
            print "                THE CHAIN: add_full_node.sh refuses a name already registered, so"
            print "                a re-join after a wipe needs a fresh one -- the key is gone"
            print "                locally but the chain still remembers it."
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
            print "  2 quiesce        stop continuous regression on the primary (it restarts the chain)"
            print "  3 fund           send qdn to the joiner's pioneer key"
            print "  4 join           drive add_full_node.sh over a PTY; does NOT start the node"
            print "  5 start          start the joiner separately and wait for catch-up"
            print "  6 validator      convert the joiner, re-split stake, verify neither node >= 2/3"
            print "  7 agreement      test_peer_agreement.sh -- the first run that compares anything"
            exit 0 ;;
        *) fail "unknown option $1" ;;
    esac
done

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

run_phase() { [[ -n "$ONLY" ]] && { [[ "$1" == "$ONLY" ]] && return 0 || return 1 }; [[ "$1" -ge "$FROM" ]] }

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
sudo_for() {
    local host="$1"
    if ssh -o ConnectTimeout=10 "$host" 'test -e /dev/sgx_enclave || test -e /dev/isgx' 2>/dev/null; then
        print "sudo "
    else
        print ""
    fi
}
SUDO_P=$(sudo_for "$PRIMARY")
SUDO_J=$(sudo_for "$JOINER")
[[ -n "$SUDO_P" ]] || info "primary has no SGX device: running unprivileged"
[[ -n "$SUDO_J" ]] || info "joiner has no SGX device: running unprivileged"

# ---------------------------------------------------------------------------- 1. preflight
if run_phase 1; then
phase "1. preflight"

for h in "$PRIMARY" "$JOINER"; do
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$h" true 2>/dev/null || fail "cannot ssh to $h"
done
for h in "$PRIMARY" "$JOINER"; do
    # Only an SGX host needs it; a debug node runs as the login user.
    if ssh "$h" 'test -e /dev/sgx_enclave || test -e /dev/isgx' 2>/dev/null; then
        ssh "$h" 'sudo -n true' 2>/dev/null || fail "$h has SGX and therefore needs passwordless sudo (the enclave opens /dev/sgx_enclave)"
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
[[ "$gen_uid" == "$prim_uid" ]] || fail "genesis records a different measurement than the running enclave"
info "measurements agree -- attestation can succeed"
fi

# ---------------------------------------------------------------------------- 2. quiesce
if run_phase 2; then
phase "2. quiesce the primary"

# Kill the LOOP by PID, never by pattern (trap 1).  The in-flight regression run is left to finish:
# killing it mid-suite can leave the chain stopped by enclave-crash.
loop_pids=$(ssh "$PRIMARY" 'pgrep -f "[r]un_regression_continually" 2>/dev/null' | tr '\n' ' ')
if [[ -n "${loop_pids// /}" ]]; then
    info "stopping continuous regression (pids: $loop_pids)"
    for p in ${=loop_pids}; do ssh "$PRIMARY" "${SUDO_P}kill $p" 2>/dev/null; done
    sleep 3
else
    info "continuous regression not running"
fi

info "waiting for any in-flight regression run to finish (it restarts the chain; a joiner cannot survive that)"
for i in {1..120}; do
    n=$(ssh "$PRIMARY" 'pgrep -cf "[r]egression.sh" 2>/dev/null || echo 0' | tr -d '\r')
    [[ "${n:-0}" -eq 0 ]] && break
    sleep 30
done
[[ "${n:-0}" -eq 0 ]] || fail "regression still running after an hour; stop it before joining"

for i in {1..40}; do
    PH=$(height "$PRIMARY"); [[ -n "$PH" ]] && break; sleep 15
done
[[ -n "$PH" ]] || fail "primary RPC did not come back after regression"
info "primary quiescent and producing at $PH"
fi

# ---------------------------------------------------------------------------- 3. fund
if run_phase 3; then
phase "3. fund the joiner's pioneer key"

# The joiner mints its key during the join, so on a FIRST run there is nothing to fund yet.  This
# phase is therefore a no-op the first time and does the work on the re-run -- which is why phase 4
# tolerates an unfunded start and phase 3 can be re-run after it.
addr=$(ssh "$JOINER" "${SUDO_J}~/qadena/bin/qadenad --home ~/qadena keys show $PIONEER_NAME -a --keyring-backend test 2>/dev/null" | tr -d '\r')
if [[ ! "$addr" =~ ^qadena1 ]]; then
    info "joiner has no $PIONEER_NAME key yet -- run phase 4 first, then re-run --only 3"
else
    info "joiner $PIONEER_NAME = $addr"
    bal=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena query bank balances $addr --output json 2>/dev/null | jq -r '.balances[0].amount // \"0\"'" | tr -d '\r')
    if [[ "${bal:-0}" -gt 0 ]] 2>/dev/null; then
        info "already funded ($bal aqdn) -- nothing to do"
    else
        chainid=$(ssh "$PRIMARY" 'curl -s localhost:26657/status | jq -r ".result.node_info.network"' | tr -d '\r')
        amt="${FUND_QDN}000000000000000000"
        info "sending ${FUND_QDN}qdn from treasury on chain $chainid"
        ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena tx bank send treasury $addr ${amt}aqdn --keyring-backend test --chain-id $chainid --gas auto --gas-adjustment 1.5 --gas-prices 0.025aqdn --yes --output json" > /dev/null 2>&1 \
            || fail "funding transfer failed"
        sleep 12
        bal=$(ssh "$PRIMARY" "${SUDO_P}~/qadena/bin/qadenad --home ~/qadena query bank balances $addr --output json 2>/dev/null | jq -r '.balances[0].amount // \"0\"'" | tr -d '\r')
        [[ "${bal:-0}" -gt 0 ]] 2>/dev/null || fail "funding did not land"
        info "funded: $bal aqdn"
    fi
fi
fi

# ---------------------------------------------------------------------------- 4. join
if run_phase 4; then
if (( STATE_SYNC )); then
    phase "4. join (STATE-SYNC)"
    # add_full_node.sh enables statesync only when BOTH genesis-pioneer IPs are given: it reads the
    # trust height and hash from the first, re-reads that exact height from the second, and refuses
    # unless they match.
    #
    # DEFAULTING SEED2 TO THE PRIMARY IS A DEGENERATE CROSS-CHECK -- it proves the primary agrees
    # with itself, which is the most a two-node chain can offer and is worth naming rather than
    # glossing.  From the third node onward, pass --seed2 <an existing peer>: the height and hash
    # are then corroborated by a source that could actually disagree, which is the check the
    # mechanism was designed for.
    seed2="${SEED2:-$PRIMARY}"
    [[ -n "$SEED2" ]] || info "no --seed2 given: using the primary for both trust sources (self-corroborating)"
    SECOND_IP_ARG=" --genesis-pioneer-second-ip-address $seed2"
else
    phase "4. join (block-sync)"
    SECOND_IP_ARG=""
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
cat > /tmp/tnb_feed.sh <<'FEED'
#!/bin/zsh
# PROMPT-DRIVEN, not timed.  This used to print c/y/y/y/n on three-second intervals and hope each
# landed on the right question.  It does not: the funding prompt polls for the balance for up to six
# minutes, so every answer had been written and echoed long before the LAST prompt appeared, and the
# final 'n' -- the one trap 3 exists to deliver -- was consumed by something else.  The node then
# started itself, several process layers under a PTY that exits moments later, which is precisely
# the failure trap 3 documents.
#
# So: watch the transcript, answer each prompt ONCE, when it actually appears.
LOG=/tmp/tnb_join.log
proceed=0 fork=0 final=0 funds=0 start=0

for i in {1..2400}; do
    [[ -f $LOG ]] || { sleep 1; continue }
    if (( ! proceed )) && grep -aq "Proceed? (y/n)" $LOG; then
        print y; proceed=1; sleep 2; continue
    fi
    # 'c' resumes a part-initialised node and KEEPS its already-funded key; 's' would erase and mint
    # a new one, stranding the funds.  Only one of the two spellings appears, depending on how far a
    # previous attempt got.
    if (( ! fork )) && grep -aqE "\[c\]ontinue" $LOG; then
        print c; fork=1; sleep 2; continue
    fi
    if (( ! fork )) && grep -aqE "\[s\]tart from scratch" $LOG; then
        print s; fork=1; sleep 2; continue
    fi
    if (( ! final )) && grep -aq "Are you really sure" $LOG; then
        print y; final=1; sleep 2; continue
    fi
    if (( ! funds )) && grep -aq "Are you done sending funds" $LOG; then
        print y; funds=1; sleep 2; continue
    fi
    # THE ONE THAT MATTERS: decline the in-script start, so phase 5 starts it standalone.
    if (( ! start )) && grep -aq "start the new qadena" $LOG; then
        print n; start=1; sleep 5; break
    fi
    sleep 1
done
sleep 30
FEED
# RESOLVE THE HOME DIRECTORY UNPRIVILEGED, then bake the absolute path in.  Writing
# /home/$(whoami) inside the script evaluates it ON THE JOINER, UNDER SUDO, where whoami is root --
# yielding /home/root/qadena/scripts/add_full_node.sh, which does not exist.  The failure is one
# line in a log on the other machine and looks like a bad install rather than a quoting bug.  This
# is the same trap repo_on() documents; it just was not applied here.
ssh "$JOINER" "test -x $JOINER_HOME/qadena/scripts/add_full_node.sh" \
    || fail "$JOINER_HOME/qadena/scripts/add_full_node.sh is missing -- install the release package first"

cat > /tmp/tnb_join.sh <<FEED
#!/bin/zsh
exec script -qec "$JOINER_HOME/qadena/scripts/add_full_node.sh \
  --pioneer $PIONEER_NAME \
  --advertise-ip-address $JOINER \
  --genesis-pioneer-first-ip-address $PRIMARY$SECOND_IP_ARG" /dev/null
FEED
scp -q /tmp/tnb_feed.sh /tmp/tnb_join.sh "$JOINER":/tmp/ || fail "cannot copy join drivers"
ssh "$JOINER" 'chmod +x /tmp/tnb_feed.sh /tmp/tnb_join.sh'

info "driving add_full_node.sh (PTY); this mints the key, fetches genesis and runs sync-enclave"
ssh "$JOINER" "rm -f /tmp/tnb_join.log; ${SUDO_J}nohup setsid zsh -c '/tmp/tnb_feed.sh | /tmp/tnb_join.sh' > /tmp/tnb_join.log 2>&1 & echo started" > /dev/null

for i in {1..60}; do
    if ssh "$JOINER" 'grep -aq "SyncEnclave SUCCEEDED" /tmp/tnb_join.log' 2>/dev/null; then
        info "SyncEnclave SUCCEEDED -- params are on the joiner"
        break
    fi
    if ssh "$JOINER" 'grep -aq "has enough funds\|attempt to detect" /tmp/tnb_join.log' 2>/dev/null && [[ $i -eq 12 ]]; then
        info "waiting at the funding poll -- run --only 3 in another shell if it is unfunded"
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

# ---------------------------------------------------------------------------- 5. start
if run_phase 5; then
phase "5. start the joiner and catch up"

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
    np=$(ssh "$JOINER" 'pgrep -c qadenad 2>/dev/null || echo 0' | tr -d '\r')
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
for i in {1..480}; do
    cu=$(ssh "$JOINER" 'curl -s --max-time 5 localhost:26657/status 2>/dev/null | jq -r ".result.sync_info.catching_up"' | tr -d '\r')
    [[ "$cu" == "false" ]] && break
    if (( i % 8 == 0 )); then
        jn=$(height "$JOINER"); pn=$(height "$PRIMARY")
        info "  ... joiner ${jn:-?} / primary ${pn:-?}${jn:+ (behind by $(( ${pn:-0} - ${jn:-0} )))}"
    fi
    sleep 15
done
if [[ "$cu" != "false" ]]; then
    info "still catching up after two hours.  Last log lines:"
    jlog 30
    fail "joiner did not catch up within two hours"
fi
info "caught up at $(height "$JOINER")"

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

# ---------------------------------------------------------------------------- 6. validator
if run_phase 6; then
phase "6. convert to validator and split the stake"

ssh "$JOINER" "${SUDO_J}zsh -lc 'cd $JOINER_HOME/qadena/scripts && ./convert_to_validator.sh --validator-stake $VALIDATOR_STAKE'" 2>&1 | tail -5 | sed 's/^/  /'
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

# ---------------------------------------------------------------------------- 7. agreement
if run_phase 7; then
phase "7. peer agreement"

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
    print "TWO-NODE BRING-UP COMPLETE"
    print ""
    print "Note what is still NOT covered: this proves a BLOCK-SYNC joiner agrees.  The state-sync"
    print "path -- and the private-state transfer it depends on -- is a separate exercise, and its"
    print "test needs a NEGATIVE CONTROL (repeat with the import disabled and confirm the peers DO"
    print "diverge), or it cannot distinguish 'fixed' from 'the scenario never happened'."
else
    print "PEER AGREEMENT FAILED -- the two nodes do not agree.  That is a fork; investigate before"
    print "running anything else."
fi
print "======================================================================"
exit $rc
fi
