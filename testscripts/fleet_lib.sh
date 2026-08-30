# Shared helpers for the fleet bringup scripts.  Sourced, never executed.
#
# WHY THIS FILE EXISTS.  It was factored out when there were two bringup scripts driving the same
# machines the same way, differing only in WHAT THEY RAN AND WHEN; two copies of this knowledge was
# two places for it to rot.  One of those scripts is gone and fleet_bringup_with_tests.sh is now the
# only caller, but the reason to keep this separate has not changed: each function below encodes a
# failure that has already cost a fleet run, and the next bringup-shaped script must inherit them
# rather than reinvent them.  A trap that drifts is one that has stopped protecting.
#
# WHAT THE CALLER MUST SET before calling into here:
#   RUN_DIR       directory for collected logs          (sync_log)
#   STATUS        append-only status file               (note)
#   STAGE_ORDER   array of stage labels, in order       (stage_index, run_stage)
#   FROM_INDEX    index of the first stage to run       (run_stage)
# Nothing here creates or validates those -- the scripts name their own stages and their own run
# directories, and a library that invented either would be guessing.
#
# NO SIDE EFFECTS AT LOAD.  Only definitions, so sourcing is safe at any point and the caller keeps
# control of ordering (RUN_DIR has to exist before the first sync_log, not before the source).

# NAMES THE CALLING SCRIPT, not this file.  ${(%):-%x} resolves to fleet_lib.sh once the
# helpers live here, so every failure started reporting the library as the thing that failed.
# Each script sets FLEET_NAME from its own $0 before sourcing.
fail()  { print -u2 "FAIL(${FLEET_NAME:-fleet}): $*"; note "FAILED: $*"; exit 1 }
info()  { print "  $*" }
# Tolerates STATUS being unset: these helpers are defined before the run directory exists, and a
# fail() during argument parsing must print its reason rather than die on an unbound variable.
note()  { [[ -n "${STATUS:-}" ]] && print "$(date -u +%Y-%m-%dT%H:%M:%SZ)  $*" >> "$STATUS"; return 0 }
stage() { print ""; print "###################################################################"; print "### $*"; print "###################################################################"; note "$*" }

rsh_user() {
    local host="$1"; shift
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"
}

# stage_index <label> -- 1-based position in STAGE_ORDER, or non-zero if unknown.
# run_stage <label>   -- true once we have reached --from.  Stages are labels rather than numbers
# because they are named that way everywhere else (logs, --help, the run directory).
stage_index() {
    local want="$1" i=1
    for s in "${STAGE_ORDER[@]}"; do
        [[ "$s" == "$want" ]] && { print $i; return 0 }
        (( i++ ))
    done
    return 1
}
run_stage() { [[ $(stage_index "$1") -ge $FROM_INDEX ]] }

# Trap 4: builds go through a LOGIN bash with the toolchain path prepended.  zsh -lc is not enough
# when the target's login shell is bash -- go is then absent and the failure names the enclave.
#
# Trap 5: ssh + nohup + & LEAKS THE CHANNEL -- the session stays open even with output redirected,
# so the local call never returns and reads as a hang.  Long-runners use ssh -f.
BUILD_PATH='export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH;'
rsh_build_detached() {   # host, remote-log, command
    local host="$1" rlog="$2"; shift 2
    ssh -f -o ConnectTimeout=10 -o BatchMode=yes "$host" \
        "cd \$HOME/qv3 && nohup bash -lc $(printf '%q' "$BUILD_PATH $*") > $rlog 2>&1 < /dev/null"
}

# Pull a remote log into the run directory.  Cheap, and it is what makes one-directory monitoring
# real rather than a claim -- the local copy is never more than a poll interval behind.
sync_log() {   # host, remote-path, local-name
    ssh -o ConnectTimeout=10 -o BatchMode=yes "$1" "cat $2" > "$RUN_DIR/$3" 2>/dev/null || true
}

# Trap 7: the height must ADVANCE.  Processes being up says nothing -- a halted two-validator chain
# looks perfectly healthy from ps.
height_of() {
    rsh_user "$1" 'curl -s --max-time 5 localhost:26657/status | jq -r ".result.sync_info.latest_block_height // empty"' 2>/dev/null | tr -d '\r'
}
assert_advancing() {   # host, label
    local h0 h1
    h0=$(height_of "$1")
    [[ -n "$h0" ]] || fail "$2: the RPC on $1 did not answer"
    sleep 12
    h1=$(height_of "$1")
    [[ -n "$h1" ]] || fail "$2: the RPC on $1 stopped answering"
    [[ "$h1" -gt "$h0" ]] || fail "$2: $1 is NOT advancing (height stuck at $h1). A halted chain keeps every process running -- check the enclave, and the peers' app hashes."
    info "$2: $1 advancing ($h0 -> $h1)"
}

# Same probe 1st_node_bringup uses: 0 = SGX usable, 1 = SGX present, needs root, 2 = no SGX.
SGX_PROBE='e=""; p=""
for d in /dev/sgx_enclave /dev/sgx/enclave;     do [ -e "$d" ] && { e="$d"; break; }; done
for d in /dev/sgx_provision /dev/sgx/provision; do [ -e "$d" ] && { p="$d"; break; }; done
[ -n "$e" ] && [ -n "$p" ] || exit 2
[ -r "$e" ] && [ -w "$e" ] && [ -r "$p" ] && [ -w "$p" ] || exit 1
exit 0'
sgx_state() { ssh -o ConnectTimeout=10 "$1" "$SGX_PROBE" >/dev/null 2>&1; print $? }

# READ THE MEASUREMENT FROM THE BINARY, TWO WAYS.  ego computes it on SGX; on ARM (no ego at all)
# and on debug builds the identity IS the embedded string.  Never `qadenad_enclave --unique-id` on
# SGX: it returns the embedded debug placeholder, which does not describe a signed enclave.
measurement_of() {   # host
    local h="$1" out
    out=$(rsh_user "$h" 'ego uniqueid $HOME/qadena/bin/qadenad_enclave 2>/dev/null | head -1' | tr -d '\r')
    [[ "$out" =~ ^[0-9a-f]{64}$ ]] && { print "$out"; return }
    rsh_user "$h" 'strings $HOME/qadena/bin/qadenad_enclave 2>/dev/null | grep -m1 -ohE "unique[0-9]+"' | tr -d '\r'
}

# --------------------------------------------------------------------------------------------
# Cosmovisor helpers.

# cosmovisor_managed_on <host> -- is that node converted?  Same definition as setup_env.sh's
# cosmovisor_managed (the `current` symlink), asked over ssh.
cosmovisor_managed_on() {
    rsh_user "$1" 'test -L $HOME/qadena/cosmovisor/current' >/dev/null 2>&1
}

# cosmovisor_current_of <host> -- the generation the node's `current` points at ("genesis",
# "upgrades/v1.1.23"...), empty if unmanaged.
cosmovisor_current_of() {
    rsh_user "$1" 'readlink $HOME/qadena/cosmovisor/current 2>/dev/null' | tr -d '\r'
}

# staged_sha_of <host> <plan> -- sha256 of the staged qadenad for <plan>, empty if not staged.
# The upgrade preflight compares this across the fleet and against the archive: a node whose
# staged bytes differ would fork at H, and "staged" alone does not prove "staged the same thing".
staged_sha_of() {
    rsh_user "$1" "sha256sum \$HOME/qadena/cosmovisor/upgrades/$2/bin/qadenad 2>/dev/null | cut -d' ' -f1" | tr -d '\r'
}

# require_live <host> <label> -- height rising AND catching_up false.  assert_advancing without
# the catching-up blind spot: after a fleet-wide swap at H every node restarts and REPLAYS
# briefly, and a replaying node's height rises fast while it contributes nothing to consensus --
# `catching_up == false` is the part that says the swap actually produced a live validator.
require_live() {
    local host="$1" label="$2" h0 h1 cu
    h0=$(height_of "$host"); [[ -n "$h0" ]] || fail "$label: the RPC on $host did not answer"
    sleep 12
    h1=$(height_of "$host"); [[ -n "$h1" ]] || fail "$label: the RPC on $host stopped answering"
    [[ "$h1" -gt "$h0" ]] || fail "$label: $host is NOT advancing (stuck at $h1)"
    cu=$(rsh_user "$host" 'curl -s --max-time 5 localhost:26657/status | jq -r ".result.sync_info.catching_up"' | tr -d '\r')
    [[ "$cu" == "false" ]] || fail "$label: $host is advancing but still catching up -- replaying, not participating"
    info "$label: $host live ($h0 -> $h1, caught up)"
}
