#!/bin/zsh
#
# Reading an enclave's identity correctly on BOTH a debug build and real SGX.  Source, do not run.
#
# THE TRAP THIS EXISTS FOR: `qadenad_enclave -unique-id` LIES ON SGX.
#
# It reports the //go:embed-ed label from cmd/qadenad_enclave/test_unique_id.txt -- "unique047" --
# because that string is compiled in regardless of how the binary is signed.  On a real enclave the
# identity that matters is MRENCLAVE, a 64-hex hash of the signed image, and that is what the chain
# registers, what the staged binaries are named after, and what the sealed params files are keyed by:
#
#   qadenad_enclave.ab35560151defd04fa0c1fc19e3b74970ae53dc0a0b3b1e04d506203bd0c0477
#   enclave_params_cc3518658aa8bf13de1b37533b8742a18c2685042a66aac20ed86657073b49e9.json
#
# Observed on SGX1 (2026-08-21): -unique-id said "unique047" while ego said
# cc3518658aa8bf13de1b37533b8742a18c2685042a66aac20ed86657073b49e9.  A script trusting -unique-id
# would compare a debug label against a chain full of hashes, find no match, and report a healthy
# node as running an unregistered measurement.
#
# THE RULE, and it is simple because the two cases do not overlap:
#   ego present  -> the build is ego-signed; `ego uniqueid` is authoritative
#   ego absent   -> the build is debug; the embedded label IS the identity, so -unique-id is right
#
# Deliberately no fallback to guessing from sibling filenames: for the LIVE binary that is a coin
# flip when several staged copies exist, and a wrong measurement is worse than none.

# 64 lowercase hex = a real MRENCLAVE.
enclave_is_measurement() { [[ "$1" =~ ^[0-9a-f]{64}$ ]] }

# enclave_measurement <binary> -- the identity that binary will present to the chain, bare (no
# "(debug)" suffix) so it can be compared against chain rows directly.
enclave_measurement() {
    local bin="$1" out
    [ -x "$bin" ] || return 1
    if command -v ego > /dev/null 2>&1; then
        out=$(ego uniqueid "$bin" 2>/dev/null | tail -1)
        if enclave_is_measurement "$out"; then printf "%s" "$out"; return 0; fi
    fi
    out=$("$bin" -unique-id 2>/dev/null | tail -1)
    [ -n "$out" ] && { printf "%s" "$out"; return 0 }
    return 1
}

# enclave_is_sgx -- is this an SGX host at all?  Only used to phrase messages; the logic above does
# not need to know.
enclave_is_sgx() { command -v ego > /dev/null 2>&1 }

# PROCESS DETECTION MUST HANDLE `ego run`.
#
# On SGX the enclave is launched as `ego run .../qadenad_enclave`, so the process COMM is "ego" and
# "ego-host" -- `pgrep -x qadenad_enclave` returns 0 on a perfectly healthy node.  That false
# negative made this library report "the enclave is NOT RUNNING" on SGX1 while it was serving
# happily on /tmp/qadena_50051.sock.
#
# `pgrep -f` is the other trap: it matches the full command line, so it matches the checking command
# itself.  Everything here reads `ps` and filters explicitly instead.

# enclave_running_binary -- path of the qadenad_enclave binary the running process was started from,
# for both launch styles.  Empty if nothing is running.
enclave_running_binary() {
    local line pid exe
    # SGX: `ego run <path> ...`.  Excluding awk/grep by name, since ps lists the filter too.
    line=$(ps -eo args --no-headers 2>/dev/null \
           | awk '/ego run/ && /qadenad_enclave/ && !/awk/ && !/grep/ {print; exit}')
    if [ -n "$line" ]; then
        line="${line#*ego run }"
        printf "%s" "${line%% *}"
        return 0
    fi
    # Debug: the binary is the executable itself.
    pid=$(pgrep -x qadenad_enclave 2>/dev/null | head -1)
    if [ -n "$pid" ]; then
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        [ -n "$exe" ] && { printf "%s" "$exe"; return 0 }
    fi
    return 1
}

# enclave_process_count -- how many enclave processes are up, counting the ego wrappers as one node.
enclave_process_count() {
    local n
    n=$(ps -eo args --no-headers 2>/dev/null \
        | awk '/qadenad_enclave/ && !/awk/ && !/grep/' | wc -l | tr -d ' ')
    printf "%s" "$n"
}

enclave_is_running() { [ "$(enclave_process_count)" != "0" ] }

# enclave_running_measurement -- what the RUNNING process is, not what is installed in bin/.
#
# Read from the binary the process was started from, which is correct on SGX where the startup log
# line prints the embedded debug label rather than MRENCLAVE.  Falls back to the log only on a debug
# build, where that line IS the identity -- scanning every rotated file, because rotatelogs rotates
# daily and an enclave up 17 hours has its startup line in yesterday's.
enclave_running_measurement() {
    local bin out l
    bin=$(enclave_running_binary)
    if [ -n "$bin" ] && [ -x "$bin" ]; then
        out=$(enclave_measurement "$bin") && [ -n "$out" ] && { printf "%s" "$out"; return 0 }
    fi
    enclave_is_sgx && return 1   # never trust the log line on SGX; it prints the debug label
    for l in "$QADENAHOME"/logs/qadena-*.log(Nom); do
        out=$(grep -a "Enclave starting" "$l" 2>/dev/null | tail -1 \
              | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/.*Enclave starting //' | awk '{print $3}')
        [ -n "$out" ] && { printf "%s" "$out"; return 0 }
    done
    return 1
}
