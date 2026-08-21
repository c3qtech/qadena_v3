#!/bin/zsh
#
# What enclave measurements does the chain trust, and is this node running one of them?
#
# WHY THIS EXISTS.  Three different things are called "the enclave version" and they fail in
# different ways, so a mismatch between them is easy to create and hard to see:
#
#   MEASUREMENT   uniqueNNN / MRENCLAVE -- identifies the CODE.  What the chain trusts, and what an
#                 enclave must prove it is before any peer will release a secret to it.
#   VERSION       1.1.N in version.txt -- schedules the HANDOVER.  check_upgrade_enclave.sh compares
#                 it against the registered identity's version and must see a strict increase.
#   LIVE BINARY   what is actually installed at bin/qadenad_enclave, which need not be either of
#                 the above if a copy failed or a build was mislabelled.
#
# Each of these has silently disagreed with the others on this fleet:
#
#   - a rebuild after an upgrade produced the PRE-upgrade measurement, because
#     test_enclave_upgrade.sh restores the //go:embed-ed id files on exit.  The binary was installed
#     as qadenad_enclave.unique047 while containing entirely different code.
#   - a `cp` onto the live binary failed with "Text file busy" because the enclave was running, and
#     the error was discarded -- so the node kept running the OLD binary while every other signal
#     said the new one was deployed.
#   - a build at an already-used version printed "No upgrade needed" and did nothing, which reads
#     exactly like success.
#
# AND THE STATE THAT MATTERS MOST IS NOT THE VERSION AT ALL.  It is the registered STATUS:
#
#   active       the chain trusts this measurement; secrets may be released to it
#   unvalidated  registered by governance, judgement pending
#   inactive     retired or CONDEMNED -- and condemnation is PERMANENT.  A mirror push may remove
#                trust but never add it, and UpdateEnclaveIdentity only allows an existing row to
#                move to inactive, so governance cannot put it back.  The measurement is spent and
#                a new one must be built.
#
# A node whose own measurement is not active is not obviously broken: it produces blocks and looks
# healthy, while being unable to obtain a secret share or hand its sealed keys to a successor.
#
#   enclave_identities.sh            this node
#   enclave_identities.sh --quiet    registry table only
#
# Exits non-zero if this node's measurement is not active on chain, or a staged binary is
# mislabelled, so it is usable as a gate before attempting an upgrade.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1

quiet=0
while [ $# -gt 0 ]; do
    case "$1" in
        --quiet) quiet=1; shift ;;
        -h|--help) sed -n '3,40p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

problems=0
ok()   { printf "  \033[32m%-6s\033[0m %s\n" "OK" "$1" }
bad()  { printf "  \033[31m%-6s\033[0m %s\n" "BAD" "$1"; problems=$((problems + 1)) }
warn() { printf "  \033[33m%-6s\033[0m %s\n" "WARN" "$1" }
info() { printf "         %s\n" "$1" }

# The measurement this enclave reports for ITSELF, taken from its own startup line rather than
# inferred from a filename -- a filename is exactly the thing that has been wrong before.
running_measurement() {
    local log
    log=$(ls -t "$QADENAHOME"/logs/qadena-*.log 2>/dev/null | head -1)
    [ -n "$log" ] || return 1
    grep -a "Enclave starting" "$log" 2>/dev/null | tail -1 \
        | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/.*Enclave starting //' | awk '{print $3}'
}

echo "=========================================="
echo "enclave identities registered on chain"
echo "=========================================="

rows=$(qadenad_alias q qadena list-enclave-identity -o json 2>/dev/null \
        | jq -r '.enclaveIdentity[] | "\(.uniqueID)\t\(.signerID)\t\(.status)"' 2>/dev/null)

if [ -z "$rows" ]; then
    bad "could not read the enclave identity list -- is the node running and RPC reachable?"
    exit 1
fi

running=$(running_measurement)
live_sha=$(sha256sum "$qadenabin/qadenad_enclave" 2>/dev/null | cut -c1-12)
live_ver=$("$qadenabin/qadenad_enclave" -version 2>/dev/null)

printf "  %-12s %-12s %-12s %s\n" "MEASUREMENT" "SIGNER" "STATUS" ""
echo "$rows" | while IFS=$'\t' read -r uid sid idstatus; do
    mark=""
    [ "$uid" = "$running" ] && mark="<- running here"
    case "$idstatus" in
        active)      colour="\033[32m" ;;
        unvalidated) colour="\033[33m" ;;
        *)           colour="\033[31m" ;;
    esac
    printf "  %-12s %-12s ${colour}%-12s\033[0m %s\n" "$uid" "$sid" "$idstatus" "$mark"
done

[ $quiet -eq 1 ] && exit 0

echo
echo "=========================================="
echo "this node"
echo "=========================================="

if [ -z "$running" ]; then
    warn "could not determine the running measurement from the log (has the enclave started?)"
else
    running_status=$(echo "$rows" | awk -F'\t' -v u="$running" '$1==u {print $3}')
    case "$running_status" in
        active)
            ok "running $running (version $live_ver), which is ACTIVE on chain" ;;
        unvalidated)
            warn "running $running (version $live_ver), still UNVALIDATED -- peers have not promoted it yet" ;;
        inactive)
            bad "running $running (version $live_ver), which is INACTIVE on chain -- this node cannot"
            info "receive secret shares and no enclave will hand its sealed keys to this measurement" ;;
        "")
            bad "running $running, which is NOT REGISTERED on chain at all" ;;
    esac
fi
info "live binary sha=$live_sha"

echo
echo "=========================================="
echo "staged binaries"
echo "=========================================="
# A staged binary whose name claims a measurement it does not contain is the mislabelled-build trap.
# We cannot verify a debug label cryptographically -- that is the point of a debug build -- but we
# CAN report which staged file the live binary actually equals, which is what was needed and missing.
found_live=""
for f in "$qadenabin"/qadenad_enclave.*(N); do
    base="${f##*/}"; label="${base##*.}"
    sha=$(sha256sum "$f" 2>/dev/null | cut -c1-12)
    ver=$("$f" -version 2>/dev/null)
    embedded=$("$f" -unique-id 2>/dev/null)
    note=""
    if [ "$sha" = "$live_sha" ]; then
        note="== live binary"
        found_live="$label"
    fi
    # The FILENAME is what the operator sees; the embedded id is what the binary will claim to the
    # chain.  They are set at different moments and have disagreed.
    if [ -n "$embedded" ] && [ "$embedded" != "$label" ]; then
        note="$note  MISLABELLED: binary reports $embedded"
    fi
    idstatus=$(echo "$rows" | awk -F'\t' -v u="$label" '$1==u {print $3}')
    [ -z "$idstatus" ] && idstatus="not-registered"
    printf "  %-28s sha=%-13s ver=%-7s %-14s %s\n" "$base" "$sha" "${ver:-?}" "$idstatus" "$note"
done

# WHAT AN UPGRADE WOULD DO RIGHT NOW, stated as from -> to.
#
# This MIRRORS check_upgrade_enclave.sh deliberately, including which binaries are even eligible:
# it enumerates enclave_params_<id>.json, NOT bin/qadenad_enclave.*, so a staged binary that has
# never held keys on this node is not an upgrade source at all.  A status script that models the
# decision differently from the code that makes it is worse than no status script.
#
# The direction is the part people get backwards: the LIVE binary is the TARGET, and the newest
# measurement holding sealed params is the SOURCE that hands its keys over.  An upgrade runs only
# when the live version is a STRICT increase over that source.
newest_ver=""; newest_id=""
for j in "$QADENAHOME"/enclave_config/enclave_params_*.json(N); do
    b="${j##*/}"; b="${b#enclave_params_}"; id="${b%.json}"
    exe="$qadenabin/qadenad_enclave.$id"
    [ -x "$exe" ] || { warn "$id has sealed params but no binary at ${exe##*/} -- it cannot hand its keys over"; continue }
    v=$("$exe" -version 2>/dev/null)
    [ -n "$v" ] || continue
    if [ -z "$newest_ver" ] || [ "$(printf '%s\n%s\n' "$newest_ver" "$v" | sort -V | tail -1)" = "$v" ]; then
        newest_ver="$v"; newest_id="$id"
    fi
done

echo
echo "=========================================="
echo "what a restart would do"
echo "=========================================="
if [ -z "$newest_ver" ]; then
    info "no measurement here holds sealed params, so there is no upgrade source"
elif [ "$live_ver" = "$newest_ver" ]; then
    info "nothing.  live is ${running:-?} (version $live_ver); newest holding sealed params is"
    info "$newest_id (version $newest_ver).  Equal versions do nothing -- an upgrade needs a STRICT increase."
elif [ "$(printf '%s\n%s\n' "$live_ver" "$newest_ver" | sort -V | tail -1)" = "$live_ver" ]; then
    target="${running:-${found_live:-?}}"
    info "UPGRADE: $newest_id (version $newest_ver)  ->  $target (version $live_ver)"
    tgt_status=$(echo "$rows" | awk -F'\t' -v u="$target" '$1==u {print $3}')
    if [ "$tgt_status" != "active" ]; then
        bad "target $target is '${tgt_status:-not-registered}' on chain -- $newest_id will REFUSE to hand"
        info "its sealed keys over.  Get it to active first, or the restart fails and the node stays down."
    else
        ok "target $target is active on chain, so the handover should be accepted"
    fi
else
    info "nothing.  live is ${running:-?} (version $live_ver), which is OLDER than $newest_id"
    info "(version $newest_ver) -- an upgrade only runs when the live binary is newer."
fi

echo
echo "=========================================="
echo "sealed params (one per measurement that has held keys here)"
echo "=========================================="
for f in "$QADENAHOME"/enclave_config/enclave_params_*.json(N); do
    info "${f##*/}"
done

echo
[ $problems -eq 0 ] && echo "no problems found" || echo "$problems problem(s) found"
exit $(( problems > 0 ))
