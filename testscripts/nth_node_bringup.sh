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
#   7. ROOT IS REQUIRED for anything touching the enclave: /tmp/qadena_50051.sock is root-owned.
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
    for p in test/qadena_v3 qadena_v3 test/qv3; do
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

# ---------------------------------------------------------------------------- 1. preflight
if run_phase 1; then
phase "1. preflight"

for h in "$PRIMARY" "$JOINER"; do
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$h" true 2>/dev/null || fail "cannot ssh to $h"
    ssh "$h" 'sudo -n true' 2>/dev/null || fail "$h needs passwordless sudo (trap 7: the enclave socket is root-owned)"
done
info "both nodes reachable with passwordless sudo"

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
    out=$(ssh "$h" 'sudo ego uniqueid ~/qadena/bin/qadenad_enclave 2>/dev/null' | tr -d '\r')
    [[ "$out" =~ ^[0-9a-f]{64}$ ]] && { printf "%s" "$out"; return 0 }
    # debug path: the binary prints its embedded id.  -unique-id is qadenad_enclave's spelling.
    out=$(ssh "$h" 'sudo ~/qadena/bin/qadenad_enclave -unique-id 2>/dev/null | tail -1' | tr -d '\r')
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
    for p in ${=loop_pids}; do ssh "$PRIMARY" "sudo kill $p" 2>/dev/null; done
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
addr=$(ssh "$JOINER" "sudo ~/qadena/bin/qadenad --home ~/qadena keys show $PIONEER_NAME -a --keyring-backend test 2>/dev/null" | tr -d '\r')
if [[ ! "$addr" =~ ^qadena1 ]]; then
    info "joiner has no $PIONEER_NAME key yet -- run phase 4 first, then re-run --only 3"
else
    info "joiner $PIONEER_NAME = $addr"
    bal=$(ssh "$PRIMARY" "sudo ~/qadena/bin/qadenad --home ~/qadena query bank balances $addr --output json 2>/dev/null | jq -r '.balances[0].amount // \"0\"'" | tr -d '\r')
    if [[ "${bal:-0}" -gt 0 ]] 2>/dev/null; then
        info "already funded ($bal aqdn) -- nothing to do"
    else
        chainid=$(ssh "$PRIMARY" 'curl -s localhost:26657/status | jq -r ".result.node_info.network"' | tr -d '\r')
        amt="${FUND_QDN}000000000000000000"
        info "sending ${FUND_QDN}qdn from treasury on chain $chainid"
        ssh "$PRIMARY" "sudo ~/qadena/bin/qadenad --home ~/qadena tx bank send treasury $addr ${amt}aqdn --keyring-backend test --chain-id $chainid --gas auto --gas-adjustment 1.5 --gas-prices 0.025aqdn --yes --output json" > /dev/null 2>&1 \
            || fail "funding transfer failed"
        sleep 12
        bal=$(ssh "$PRIMARY" "sudo ~/qadena/bin/qadenad --home ~/qadena query bank balances $addr --output json 2>/dev/null | jq -r '.balances[0].amount // \"0\"'" | tr -d '\r')
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
# 'c' resumes a part-initialised node and keeps the funded key; 'y' covers the fresh path.
# Both are sent because which prompt appears depends on prior state, and the wrong one merely
# re-prompts.  The final 'n' declines the in-script node start on purpose.
print c
sleep 3
print y
sleep 3
print y
sleep 3
print y
sleep 3
print n
sleep 600
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
ssh "$JOINER" 'rm -f /tmp/tnb_join.log; sudo nohup setsid zsh -c "/tmp/tnb_feed.sh | /tmp/tnb_join.sh" > /tmp/tnb_join.log 2>&1 & echo started' > /dev/null

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
ssh "$JOINER" 'sudo ls ~/qadena/enclave_config/enclave_params_*.json' > /dev/null 2>&1 \
    || fail "sync-enclave reported success but wrote no enclave_params file"
info "enclave params persisted"

# Leave nothing holding a PTY open.  By PID (trap 1).
for p in $(ssh "$JOINER" 'pgrep -f "[t]nb_feed|[t]nb_join|[a]dd_full_node" 2>/dev/null'); do
    ssh "$JOINER" "sudo kill -9 $p" 2>/dev/null
done
fi

# ---------------------------------------------------------------------------- 5. start
if run_phase 5; then
phase "5. start the joiner and catch up"

# Standalone, NOT from inside add_full_node.sh (trap 3).
ssh "$JOINER" "sudo zsh -lc 'cd $JOINER_HOME/qadena/scripts && ./start_qadena.sh'" > /dev/null 2>&1
sleep 30
jh=$(height "$JOINER")
[[ -n "$jh" ]] || fail "joiner did not start; check ~/qadena/logs on $JOINER"
info "joiner started at height $jh"

info "block-syncing (rebuilds every enclave-private table by executing each block; this is slow and correct)"
for i in {1..480}; do
    cu=$(ssh "$JOINER" 'curl -s --max-time 5 localhost:26657/status 2>/dev/null | jq -r ".result.sync_info.catching_up"' | tr -d '\r')
    [[ "$cu" == "false" ]] && break
    [[ $((i % 20)) -eq 0 ]] && info "  ... joiner $(height "$JOINER") / primary $(height "$PRIMARY")"
    sleep 15
done
[[ "$cu" == "false" ]] || fail "joiner did not catch up within two hours"
info "caught up at $(height "$JOINER")"

ssh "$JOINER" 'sudo ~/qadena/bin/qadenad --home ~/qadena enclave height' 2>/dev/null | sed 's/^/  /'
fi

# ---------------------------------------------------------------------------- 6. validator
if run_phase 6; then
phase "6. convert to validator and split the stake"

ssh "$JOINER" "sudo zsh -lc 'cd $JOINER_HOME/qadena/scripts && ./convert_to_validator.sh --validator-stake $VALIDATOR_STAKE'" 2>&1 | tail -5 | sed 's/^/  /'
sleep 20

# setup_prerequisites splits the treasury delegation across ALL bonded validators, so it has to run
# AFTER the joiner bonds or the split does not include it.
info "re-running setup_prerequisites so the treasury delegation splits across the validators"
prep_repo=$(repo_on "$PRIMARY") || fail "cannot locate the checkout on $PRIMARY"
ssh "$PRIMARY" "sudo zsh -lc $(printf '%q' "cd $prep_repo && ./testscripts/setup_prerequisites.sh")" > /dev/null 2>&1 \
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
out=$(ssh "$PRIMARY" "sudo zsh -lc $(printf '%q' "cd $repo && ./testscripts/test_peer_agreement.sh")" 2>&1)
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
