#!/bin/zsh
#
# Measure a running chain's seconds-per-block, for build_genesis.py --block-time.
#
#   ./measure_block_time.sh [--node tcp://host:26657] [--samples 40] [--interval 3]
#
# WHY MEASURE RATHER THAN READ timeout_commit.  timeout_commit is a FLOOR, not a rate.  A
# single-validator chain hits it almost exactly; a real validator set is dominated by
# propagation latency and runs slower.  Either way the configured target is a prediction
# and the chain is the fact.
#
# WHY IT MATTERS.  x/mint pays annual_provisions / blocks_per_year on EVERY block.  Set
# blocks_per_year BELOW the true rate and each block pays too much AND there are more
# blocks than assumed -- the error compounds twice, silently, for the life of the chain.
# The devnet's configured 21,024,000 against a measured 1.467s/block is ~2% of over-mint:
# a "1%" inflation that is really 1.02%.
#
# Sample over minutes, not seconds: block times are noisy and one slow block in a short
# window moves the answer more than the effect being measured.

SCRIPT_DIR="${0:A:h}"
NODE=""; SAMPLES=40; INTERVAL=3
while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)     NODE="$2"; shift 2 ;;
        --samples)  SAMPLES="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [--node tcp://host:26657] [--samples 40] [--interval 3]"
            echo "Prints seconds-per-block and the blocks_per_year to pass to build_genesis.py."
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

source "$SCRIPT_DIR/../scripts/setup_env.sh" >/dev/null 2>&1
qd() { "$qadenabin/qadenad" --home "$QADENAHOME" ${NODE:+--node "$NODE"} "$@" }

# WHAT IS SAMPLED: latest_block_height and latest_block_TIME -- the BLOCK HEADER timestamp
# (the median of validator clocks), not this machine's wall clock.  That is the right
# quantity: x/mint's "year" is chain time, so blocks_per_year must be blocks per chain-second.
read_pos() {
    qd status 2>/dev/null | jq -r '[(.sync_info//.SyncInfo).latest_block_height,
                                    (.sync_info//.SyncInfo).latest_block_time,
                                    ((.sync_info//.SyncInfo).catching_up|tostring)] | @tsv'
}

# A CATCHING-UP NODE REPLAYS HISTORY, and header timestamps then advance at replay speed --
# thousands of chain-seconds per wall-second.  Measuring one gives the rate the chain ran at
# historically, which is not the question, and it looks like a perfectly good answer.
#
# A HALTED NODE IS WORSE: catching_up reports false and the node answers queries normally,
# so it reads as healthy.  The only reliable tell is comparing the block timestamp to WALL
# CLOCK -- if the chain has stopped, that gap grows without bound.
check_live() {
    local pos="$1" label="$2"
    local cu=${pos##*$'\t'}
    if [[ "$cu" == "true" ]]; then
        echo "REFUSING: the node is CATCHING UP.  Header timestamps advance at replay speed,"
        echo "          so any block time measured now describes history, not production."
        exit 1
    fi
    local bt=$(echo "$pos" | cut -f2)
    local skew=$(python3 - "$bt" <<'PY'
import sys
from datetime import datetime, timezone
s = sys.argv[1].replace('Z', '+00:00')
if '.' in s and '+' in s:
    head, rest = s.split('.', 1); frac, tz = rest.split('+', 1)
    s = f"{head}.{frac[:6]:<06}+{tz}"
print(int((datetime.now(timezone.utc) - datetime.fromisoformat(s)).total_seconds()))
PY
)
    if (( skew > 60 )); then
        echo "REFUSING: the newest block is ${skew}s behind wall clock ($label)."
        echo "          The chain is halted or stalled -- catching_up says false either way."
        exit 1
    fi
}

first=$(read_pos) || { echo "cannot reach the node"; exit 1 }
[[ -n "$first" ]] || { echo "cannot reach the node${NODE:+ at $NODE}"; exit 1 }
check_live "$first" "at the start"
h0=$(echo "$first" | cut -f1); t0=$(echo "$first" | cut -f2)
echo "sampling from height $h0 for $((SAMPLES*INTERVAL))s ..."

for i in $(seq 1 $SAMPLES); do sleep $INTERVAL; done

last=$(read_pos)
check_live "$last" "at the end"
h1=$(echo "$last" | cut -f1); t1=$(echo "$last" | cut -f2)
[[ "$h1" -gt "$h0" ]] || { echo "the chain did not advance ($h0 -> $h1) -- is it halted?"; exit 1 }

python3 - "$h0" "$t0" "$h1" "$t1" <<'PY'
import sys
from datetime import datetime
def p(s):
    s = s.replace('Z', '+00:00')
    if '.' in s and '+' in s:                      # trim ns -> us, which fromisoformat takes
        head, rest = s.split('.', 1)
        frac, tz = rest.split('+', 1)
        s = f"{head}.{frac[:6]:<06}+{tz}"
    return datetime.fromisoformat(s)
h0, t0, h1, t1 = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
blocks = int(h1) - int(h0)
secs = (p(t1) - p(t0)).total_seconds()
bt = secs / blocks
bpy = int(31_536_000 / bt)
print(f"  {blocks} blocks over {secs:.1f}s")
print(f"  block time     {bt:.3f}s")
print(f"  blocks_per_year {bpy:,}")
print()
print(f"  ./build_genesis.py --block-time {bt:.3f} ...")
PY
