#!/bin/zsh
#
# One-shot health check for every Qadena component.
#
# Replaces "ps -eaf | grep qadena", which is unreliable in both directions: it matches the grep
# itself and any editor or log tail with "qadena" in the command line, while telling you nothing
# about whether the thing it found is actually WORKING.  A node can be running and stuck, an enclave
# can be up but unreachable on its socket, and the chain can be running but not producing blocks.
#
# Exits 0 only if every required component is up AND the chain is producing blocks, so this is
# usable as a gate in other scripts, not just for reading.
#
#   qadena_status.sh            full check
#   qadena_status.sh --quick    skip the block-production sample (no 6s wait)

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1

quick=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick) quick=1; shift ;;
        --help)
            echo "Usage: qadena_status.sh [--quick]"
            echo "  --quick   skip the block-production sample (up to 6s)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

rpc="http://localhost:26657"
problems=0

ok()   { printf "  \033[32m%-4s\033[0m %s\n" "OK" "$1" }
bad()  { printf "  \033[31m%-4s\033[0m %s\n" "DOWN" "$1"; problems=$((problems + 1)) }
warn() { printf "  \033[33m%-4s\033[0m %s\n" "WARN" "$1" }
info() { printf "       %s\n" "$1" }

# is_measurement -- a measurement is 32 bytes as 64 lowercase hex.  Used to reject ego's error
# output, which is NOT distinguishable by exit status alone (see below).
is_measurement() { [[ "$1" =~ ^[0-9a-f]{64}$ ]] }

# is_enclave_id -- a measurement OR a debug placeholder.
#
# A DEBUG BUILD'S IDENTITY IS NOT NOTHING.  It is a go:embed-ed label like "unique047" from
# cmd/qadenad_enclave/test_unique_id.txt, buildscripts/build_enclave.sh writes that same label into
# genesis.json's enclaveIdentityList, and getEnclaveIdentity looks it up by that exact string.  It is
# the debug analogue of MRENCLAVE and it fails closed the same way when two nodes disagree.
#
# So treating "not 64 hex" as "no identity" printed "(no measurement)" on exactly the machines where
# the question -- is this node running the binary the chain expects? -- has to be answered by hand.
# Shape-checked rather than pattern-matched to "unique*": the placeholder text is whatever the build
# tree says, and ego's failures announce themselves with ERROR.
is_enclave_id() { [[ -n "$1" && "$1" != *ERROR* && "$1" != *[[:space:]]* ]] }

# measurement_of <binary> -- the MRENCLAVE of an ego-signed binary, or a reason it is unavailable.
#
# Two ways to get it, in order of preference:
#
#   1. `ego uniqueid <binary>`.  EGO REPORTS FAILURE ON STDOUT and exits non-zero -- `ego uniqueid`
#      on an unsigned or missing file prints "ERROR: ..." where the answer would go.  A naive
#      capture therefore yields the error text AS the measurement, which is how a broken build once
#      got announced as a valid one.  Both the exit status and the SHAPE are checked.
#
#   2. The sibling filename a package install leaves behind: install.sh keeps
#      qadenad_enclave.<measurement> next to the live binary.  This needs no tooling at all, which
#      matters on a node installed from a release package -- those have no ego and no source tree.
#
#   3. Ask the binary: `<binary> -unique-id`.  This is the DEBUG answer -- the enclave prints its
#      embedded placeholder -- and it is tried after the sibling for a reason.  An ego-signed binary
#      invoked without -realenclave also prints the placeholder rather than its measurement, so
#      asking earlier would report a debug id for a real SGX enclave.  By the time we get here ego
#      has failed AND no 64-hex sibling exists, which on an SGX node one always would.
#
#   4. The sibling filename again, now accepting a debug placeholder -- for a binary that will not
#      answer for itself.  signer_enclave has no -unique-id flag, but install.sh still names its
#      copy signer_enclave.<placeholder>.
#
# NEVER NAME A LOCAL `path` IN ZSH.  `path` is tied to `PATH` as its array form, so `local path="$1"`
# REPLACES THE COMMAND SEARCH PATH with the binary's own name for the rest of the function, after
# which no external command resolves at all.  That is why route 1 could never have run: `command -v
# ego` was being asked on a PATH whose single entry was not a directory, so it answered "no" on a
# machine that had ego installed.  Routes 2 and 4 are pure shell and need no PATH, so the function
# still returned an answer and the breakage stayed invisible until route 3 tried to run `tail`.
measurement_of() {
    local bin="$1" out="" sib=""

    if command -v ego > /dev/null 2>&1; then
        out=$(ego uniqueid "$bin" 2>/dev/null)
        if [ $? -eq 0 ] && is_measurement "$out"; then
            printf "%s" "$out"
            return 0
        fi
    fi

    for sib in "$bin".*(N); do
        if is_measurement "${sib##*.}"; then
            printf "%s" "${sib##*.}"
            return 0
        fi
    done

    # Both spellings: qadenad_enclave takes -unique-id, signer_enclave takes -query-unique-id.  The
    # wrong one exits 2 with usage on stderr and produces no stdout, so a miss is unmistakable.
    if [ -x "$bin" ]; then
        for flg in -unique-id -query-unique-id; do
            out=$("$bin" "$flg" 2>/dev/null | tail -1)
            if is_enclave_id "$out" && ! is_measurement "$out"; then
                printf "%s (debug)" "$out"
                return 0
            fi
        done
    fi

    for sib in "$bin".*(N); do
        if is_enclave_id "${sib##*.}"; then
            printf "%s (debug)" "${sib##*.}"
            return 0
        fi
    done

    printf "(no identity -- not an ego-signed binary, and it would not report one)"
    return 1
}

# signer_id_of <public.pem> [enclave-binary] -- MRSIGNER, which unlike MRENCLAVE is stable across
# releases.  A node whose signer differs from the chain's is running somebody else's build entirely.
#
# On a debug build there is no signing key and public.pem answers nothing, but the enclave still has
# a signer identity -- the test_signer_id.txt placeholder, which genesis records alongside the unique
# id and getEnclaveIdentity checks.  Same fallback order and the same hazard as measurement_of: ask
# the binary only after ego has failed, since an ego-signed enclave invoked directly reports the
# placeholder too.
signer_id_of() {
    local out=""
    if command -v ego > /dev/null 2>&1; then
        out=$(ego signerid "$1" 2>/dev/null)
        if [ $? -eq 0 ] && is_measurement "$out"; then
            printf "%s" "$out"
            return 0
        fi
    fi
    if [ -n "$2" ] && [ -x "$2" ]; then
        for flg in -signer-id -query-signer-id; do
            out=$("$2" "$flg" 2>/dev/null | tail -1)
            if is_enclave_id "$out" && ! is_measurement "$out"; then
                printf "%s (debug)" "$out"
                return 0
            fi
        done
    fi
    printf "(unavailable -- ego not installed)"
    return 1
}

# pid_of <pattern> -- first PID matching, empty if none.  Excludes this script so a pattern like
# "qadenad" cannot match the checker itself, which is exactly how the grep approach goes wrong.
pid_of() {
    pgrep -f "$1" 2>/dev/null | grep -v "^$$\$" | head -1
}

# uptime_of <pid> -- elapsed wall time, as ps reports it (e.g. 01:23:45 or 2-03:14:00)
uptime_of() {
    ps -o etime= -p "$1" 2>/dev/null | tr -d ' '
}

echo "======================================================================"
echo "QADENA STATUS"
echo "======================================================================"
echo "home:  $QADENAHOME"
echo "bin:   $qadenabin"
echo ""

echo "PROCESSES"

# The chain node.  Matched on the installed path rather than the bare name so a build, an editor or
# a log tail holding the string cannot be mistaken for a running node.
chain_pid=$(pid_of "$qadenabin/qadenad .*start")
if [ -n "$chain_pid" ]; then
    ok "qadenad          pid $chain_pid   up $(uptime_of $chain_pid)"
else
    bad "qadenad          not running"
fi

# The enclave.  Under real SGX it runs under ego-host, so both spellings have to be tried -- looking
# only for the bare binary would report a healthy SGX node as down.
enclave_pid=$(pid_of "$qadenabin/qadenad_enclave")
[ -z "$enclave_pid" ] && enclave_pid=$(pid_of "ego-host.*qadenad_enclave")
if [ -n "$enclave_pid" ]; then
    ok "qadenad_enclave  pid $enclave_pid   up $(uptime_of $enclave_pid)"
else
    bad "qadenad_enclave  not running"
fi

signer_pid=$(pid_of "$qadenabin/signer_enclave")
[ -z "$signer_pid" ] && signer_pid=$(pid_of "ego-host.*signer_enclave")
if [ -n "$signer_pid" ]; then
    ok "signer_enclave   pid $signer_pid   up $(uptime_of $signer_pid)"
else
    bad "signer_enclave   not running"
fi

# Log rotation is convenience, not correctness: the node runs fine without it, so its absence is a
# warning rather than a failure.
rotate_pid=$(pgrep -x rotatelogs 2>/dev/null | head -1)
[ -z "$rotate_pid" ] && rotate_pid=$(pid_of "rotatelogs.*qadena")
if [ -n "$rotate_pid" ]; then
    ok "rotatelogs       pid $rotate_pid   up $(uptime_of $rotate_pid)"
else
    warn "rotatelogs       not running (logs will not rotate)"
fi

echo ""
echo "VERSIONS"
if [ -x "$qadenabin/qadenad" ]; then
    info "qadenad          $("$qadenabin/qadenad" version 2>&1 | head -1)"
else
    warn "qadenad          binary not found at $qadenabin/qadenad"
fi
if [ -x "$qadenabin/qadenad_enclave" ]; then
    info "qadenad_enclave  $("$qadenabin/qadenad_enclave" --version 2>&1 | head -1)  $(measurement_of "$qadenabin/qadenad_enclave")"
fi
if [ -x "$qadenabin/signer_enclave" ]; then
    info "signer_enclave   $("$qadenabin/signer_enclave" --version 2>&1 | head -1)  $(measurement_of "$qadenabin/signer_enclave")"
fi
if [ -f "$QADENAHOME/config/public.pem" ]; then
    info "signer id        $(signer_id_of "$QADENAHOME/config/public.pem" "$qadenabin/qadenad_enclave")"
fi

echo ""
echo "ENDPOINTS"

# HTTP endpoints are checked by actually asking them something, not by looking for a listening
# socket: a port can be open while the service behind it is not answering.
http_check() {
    local label="$1" url="$2" required="$3"
    if curl -s -f -m 3 "$url" > /dev/null 2>&1; then
        ok "$label"
    elif [ "$required" = "required" ]; then
        bad "$label  ($url)"
    else
        warn "$label  ($url) not responding"
    fi
}

http_check "RPC        26657" "$rpc/status" required
http_check "API        1317 " "http://localhost:1317/cosmos/base/tendermint/v1beta1/node_info" optional
# EVM JSON-RPC only answers POST, so a plain GET reports a perfectly healthy endpoint as down.
if curl -s -m 3 -X POST -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        http://localhost:8545 2>/dev/null | grep -q '"result"'; then
    ok "EVM JSON   8545 "
else
    warn "EVM JSON   8545  (http://localhost:8545) not responding"
fi

# The enclave listens on a unix socket, so there is no port to probe -- the socket file existing
# alongside a live process is the strongest signal available without speaking gRPC.
enclave_sock="/tmp/qadena_50051.sock"
if [ -S "$enclave_sock" ]; then
    ok "enclave socket   $enclave_sock"
elif [ -n "$enclave_pid" ]; then
    warn "enclave socket   $enclave_sock missing though the process is up"
else
    bad "enclave socket   $enclave_sock missing"
fi

echo ""
echo "CHAIN"

node_status=$(curl -s -m 3 "$rpc/status" 2>/dev/null)
if [ -z "$node_status" ]; then
    bad "no answer from $rpc -- cannot report chain state"
else
    chain_id=$(echo "$node_status" | jq -r '.result.node_info.network')
    moniker=$(echo "$node_status" | jq -r '.result.node_info.moniker')
    height=$(echo "$node_status"  | jq -r '.result.sync_info.latest_block_height')
    blocktime=$(echo "$node_status" | jq -r '.result.sync_info.latest_block_time')
    earliest=$(echo "$node_status" | jq -r '.result.sync_info.earliest_block_time')
    catching=$(echo "$node_status" | jq -r '.result.sync_info.catching_up')
    power=$(echo "$node_status"   | jq -r '.result.validator_info.voting_power')

    info "chain id         $chain_id"
    info "moniker          $moniker"
    info "height           $height"
    info "last block       $blocktime"
    info "voting power     $power"

    # Chain age is measured from the first block, which is the genesis moment -- distinct from how
    # long THIS process has been up, and the two differ after any restart.
    if [ "$earliest" != "null" ] && [ -n "$earliest" ]; then
        age=$(python3 -c "
from datetime import datetime, timezone
import sys
def parse(s):
    s = s.split('.')[0].rstrip('Z')
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
try:
    d = datetime.now(timezone.utc) - parse('$earliest')
    days, rem = divmod(int(d.total_seconds()), 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    print(f'{days}d {hours}h {mins}m')
except Exception:
    print('unknown')
" 2>/dev/null)
        info "chain age        $age (since first block)"
    fi

    if [ "$catching" = "true" ]; then
        warn "still catching up with the network"
    fi

    # Height moving is the difference between "running" and "working".  A node can hold an RPC port
    # open while consensus is stalled, and every check above would still pass.
    if [ $quick -eq 0 ]; then
        # POLL, DO NOT SLEEP-THEN-LOOK.  The question is "has the height moved",
        # and once it has there is nothing left to wait for -- so the window is a
        # CEILING, not a cost.  A healthy chain answers on the first or second
        # sample; only a stalled one pays the full six seconds, which is exactly
        # the case worth waiting longer on (block times drift under load, and a
        # three-second window called a busy-but-healthy node dead).
        #
        # The spinner is drawn only when stdout is a terminal.  This script exits
        # non-zero for a reason and gets run from other scripts and over ssh; a
        # carriage-return animation in a captured log is noise at best, and at
        # worst it hides the line it overwrites.
        sample_secs=6
        spin='|/-\'
        height2=""
        elapsed=0
        while [ $elapsed -lt $sample_secs ]; do
            if [ -t 1 ]; then
                printf "\r       watching for a new block %s (%ds/%ds)" \
                    "${spin[$(( elapsed % 4 + 1 ))]}" "$elapsed" "$sample_secs"
            fi
            sleep 1
            elapsed=$((elapsed + 1))
            sample=$(curl -s -m 3 "$rpc/status" 2>/dev/null | jq -r '.result.sync_info.latest_block_height')
            if [ -n "$sample" ] && [ "$sample" != "null" ] && [ "$sample" -gt "$height" ] 2>/dev/null; then
                height2=$sample
                break
            fi
        done
        [ -t 1 ] && printf "\r\033[K"

        if [ -n "$height2" ]; then
            ok "producing blocks ($height -> $height2 in ${elapsed}s)"
        else
            bad "NOT producing blocks (still at $height after ${sample_secs}s)"
        fi
    else
        info "block production not sampled (--quick)"
    fi
fi

echo ""
echo "======================================================================"
if [ $problems -eq 0 ]; then
    echo "ALL COMPONENTS UP"
else
    echo "$problems PROBLEM(S) FOUND"
fi
echo "======================================================================"

exit $((problems > 0))
