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
#   enclave_identities.sh                  this node, plus what to deploy next
#   enclave_identities.sh --quiet          registry table only
#   enclave_identities.sh --build-dir DIR  point at a source checkout explicitly
#
# Runs from the DEPLOYED copy ($QADENAHOME/scripts) or from a source checkout; it finds the checkout
# itself so the deploy advice works either way.
#
# Exits non-zero if this node's measurement is not active on chain, or a staged binary is
# mislabelled, so it is usable as a gate before attempting an upgrade.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/enclave_lib.sh"

quiet=0
explicit_build_dir=""
while [ $# -gt 0 ]; do
    case "$1" in
        --quiet) quiet=1; shift ;;
        --build-dir) explicit_build_dir="$2"; shift 2 ;;
        -h|--help) sed -n '3,44p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

problems=0
ok()   { printf "  \033[32m%-6s\033[0m %s\n" "OK" "$1" }
bad()  { printf "  \033[31m%-6s\033[0m %s\n" "BAD" "$1"; problems=$((problems + 1)) }
warn() { printf "  \033[33m%-6s\033[0m %s\n" "WARN" "$1" }
info() { printf "         %s\n" "$1" }

# Which measurement is running, and which one a binary carries, both come from enclave_lib.sh --
# because `-unique-id` reports the embedded DEBUG LABEL on an SGX build, not MRENCLAVE.  See the
# header there; getting this wrong makes a healthy SGX node look like it runs an unregistered
# measurement.
running_measurement() { enclave_running_measurement }

# What the SOURCE TREE would build, read without building anything.  On a debug build the
# measurement is just the //go:embed-ed label in test_unique_id.txt, so it is known before the
# compiler runs -- which is what makes it possible to register the identity BEFORE building, and
# that ordering is the whole point (see the suggested flow at the end).
#
# FINDING THE CHECKOUT IS ITS OWN PROBLEM.  setup_env.sh only sets $qadenabuild when the script it
# is sourced from lives INSIDE a checkout (it tests for ../cmd and ../x).  This script is normally
# run from the DEPLOYED copy at $QADENAHOME/scripts, where that test fails and $qadenabuild is unset
# -- so keying off it alone made the advice appear only when run from the source tree, which is the
# one place an operator does not need it.  Search the usual places, and let --build-dir override.
build_tree=""
find_build_tree() {
    local d
    for d in "$explicit_build_dir" "$QADENA_BUILD_DIR" "$qadenabuild" ~/qv3 ~/qadena_v3 ~/qadena-build; do
        [ -n "$d" ] || continue
        if [ -r "$d/cmd/qadenad_enclave/test_unique_id.txt" ]; then
            build_tree="${d:A}"
            return 0
        fi
    done
    return 1
}
# WHAT THE TREE WOULD BUILD, and on SGX that is NOT test_unique_id.txt.
#
# The label in test_unique_id.txt is the identity only on a debug build.  On SGX the measurement is
# MRENCLAVE, a hash of the signed image, which does not exist until the build runs -- build_enclave.sh
# writes it to reproducible_build_unique_id.txt afterwards, and install.sh prefers that file for the
# staged filename for exactly this reason.  Mirror that order, or this advises registering
# "unique050" on a chain whose identities are all 64-hex hashes.
source_measurement() {
    [ -n "$build_tree" ] || return 1
    local repro="$build_tree/cmd/qadenad_enclave/reproducible_build_unique_id.txt"
    if [ -r "$repro" ]; then
        local id
        id=$(cat "$repro" 2>/dev/null)
        if enclave_is_measurement "$id"; then printf "%s" "$id"; return 0; fi
    fi
    # No reproducible id.  On an SGX host that means "not built yet", and the answer is unknowable
    # rather than the debug label -- say nothing and let the caller explain.
    enclave_is_sgx && return 1
    cat "$build_tree/cmd/qadenad_enclave/test_unique_id.txt" 2>/dev/null
}
source_version()     { [ -n "$build_tree" ] && cat "$build_tree/cmd/qadenad_enclave/version.txt" 2>/dev/null }

echo "=========================================="
echo "enclave identities registered on chain"
echo "=========================================="

rows=$(qadenad_alias q qadena list-enclave-identity --output json 2>/dev/null \
        | jq -r '.enclaveIdentity[] | "\(.uniqueID)\t\(.signerID)\t\(.status)"' 2>/dev/null)

if [ -z "$rows" ]; then
    bad "could not read the enclave identity list -- is the node running and RPC reachable?"
    exit 1
fi

running=$(running_measurement)
live_sha=$(sha256sum "$qadenabin/qadenad_enclave" 2>/dev/null | cut -c1-12)
live_ver=$("$qadenabin/qadenad_enclave" -version 2>/dev/null)
live_measurement=$(enclave_measurement "$qadenabin/qadenad_enclave")

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
    if ! enclave_is_running; then
        bad "the enclave process is NOT RUNNING, so this node has no measurement in service."
        info "an upgrade handover needs the OLD enclave to start and hand its sealed keys across,"
        info "so fix this before attempting one.  Start it with scripts/start_qadena.sh"
    else
        warn "the enclave is running but its measurement could not be read"
    fi
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
    embedded=$(enclave_measurement "$f")
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
    info "nothing.  live binary is ${running:-${live_measurement:-?}} (version $live_ver); newest holding sealed params is"
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
echo "=========================================="
echo "source tree, and what to do next"
echo "=========================================="
# THE ORDER MATTERS AND IS NOT THE OBVIOUS ONE.  The instinct after `git pull` is to build.  Do not:
# build.sh installs the new binary as the LIVE one and (since install.sh was fixed) stops the node
# to do it, so if the new measurement is not yet ACTIVE on chain the old enclave refuses to hand its
# sealed keys over, the upgrade fails, and the node stays DOWN.
#
# Registering first is possible because on a debug build the measurement is the //go:embed-ed label
# in test_unique_id.txt -- readable straight from the source tree, before anything is compiled.
find_build_tree
src=$(source_measurement)
srcver=$(source_version)

if [ -z "$src" ] && [ -n "$build_tree" ] && enclave_is_sgx; then
    info "checkout                : $build_tree"
    warn "this is an SGX host and the tree has not been built yet, so the measurement it would"
    info "produce is NOT KNOWABLE: MRENCLAVE is a hash of the signed image.  Build it first --"
    info "  1.  ./buildscripts/build.sh --build-sgx --hold   # stages it; live binary untouched"
    info "  2.  re-run this script; it will read the measurement from"
    info "      cmd/qadenad_enclave/reproducible_build_unique_id.txt and advise from there"
elif [ -z "$src" ]; then
    info "no source checkout found -- looked in \$QADENA_BUILD_DIR, \$qadenabuild, ~/qv3,"
    info "~/qadena_v3, ~/qadena-build.  Point at one with:  --build-dir <path>"
    info "(this section only advises on deploys; everything above is already accurate)"
elif [ "$src" = "$running" ]; then
    ok "source tree ($build_tree) is $src (version $srcver) -- already what this node runs, nothing to deploy"
else
    info "checkout                : $build_tree"
    info "source tree would build : $src (version $srcver)"
    info "this node is running    : ${running:-unknown} (version $live_ver)"
    src_status=$(echo "$rows" | awk -F'\t' -v u="$src" '$1==u {print $3}')
    echo
    case "$src_status" in
        active)
            ok "$src is ACTIVE on chain -- safe to deploy"
            info "  1.  ./buildscripts/build.sh --hold      # stage $src; node keeps running"
            info "  2.  scripts/activate_enclave.sh $src    # stop, swap, start -- performs the handover"
            info "  (or plain ./buildscripts/build.sh, which stops the node and swaps in one step --"
            info "   safe here only because $src is already active)"
            if [ -n "$newest_ver" ] && [ "$srcver" = "$newest_ver" ]; then
                warn "but version $srcver equals the newest measurement holding sealed params ($newest_id)."
                info "  An upgrade needs a STRICT increase, so the handover will NOT run.  Bump"
                info "  cmd/qadenad_enclave/version.txt before building."
            fi ;;
        unvalidated)
            warn "$src is registered but still UNVALIDATED -- wait for the peer quorum to promote it"
            info "  re-run this script; do NOT build until it reads active" ;;
        inactive)
            bad "$src is INACTIVE on chain -- it was condemned or retired, and that is PERMANENT"
            info "  governance cannot move an existing row back to unvalidated.  Pick a NEW"
            info "  measurement: edit cmd/qadenad_enclave/test_unique_id.txt and version.txt." ;;
        "")
            warn "$src is NOT REGISTERED on chain yet."
            info "  1.  ./buildscripts/build.sh --hold      # stage it; live binary untouched, node keeps running"
            info "  2.  scripts/gov_register_enclave_identity.sh $src <signerID>"
            info "  3.  re-run this script until $src reads active"
            info "  4.  scripts/activate_enclave.sh $src    # stop, swap, start -- performs the handover"
            echo
            info "  --hold matters because the ORDER is forced: the old enclave will not hand its"
            info "  sealed keys to a measurement the chain has not made active, so swapping the live"
            info "  binary in first leaves the node DOWN.  On a debug build you could register before"
            info "  building (the measurement is just the label in test_unique_id.txt), but on SGX"
            info "  MRENCLAVE is a hash of the built image and is not knowable until step 1 is done."
            info "  Read it there with:  ego uniqueid \$qadenabin/qadenad_enclave.<id>"
            echo
            info "  If you already swapped a binary in and the node will not start, nothing is lost --"
            info "  the old binary and its enclave_params are untouched.  Recover with:"
            info "      scripts/activate_enclave.sh ${running:-<old-measurement>}" ;;
    esac
fi

echo
[ $problems -eq 0 ] && echo "no problems found" || echo "$problems problem(s) found"
exit $(( problems > 0 ))
