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

# A measurement is either a 64-hex MRENCLAVE (SGX) or a short label like unique051 (debug), and
# they want opposite treatment in a fixed-width column: the hash is unreadable whole and identified
# perfectly well by its tail, while the label is already short and loses its meaning if trimmed --
# "unique051" cut to 7 becomes "ique051", which is narrower and tells you less. So the hash is cut
# and the label is not; both fit the same 9-wide column either way.
short_uid() {
    case "$1" in
        "" ) printf "?" ;;
        *) if [[ "$1" =~ ^[0-9a-f]{64}$ ]]; then printf "%s" "${1: -7}"; else printf "%s" "$1"; fi ;;
    esac
}

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
# a log tail holding the string cannot be mistaken for a running node -- but "the installed path"
# is TWO paths now.  On a cosmovisor-managed node the supervisor execs the RESOLVED binary, so
# argv reads $QADENAHOME/cosmovisor/<generation>/bin/qadenad, never $qadenabin/qadenad; and the
# enclaves are spawned as SIBLINGS of the running qadenad, so their argv moves the same way even
# though cosmovisor is not their parent.  Anchoring on $QADENAHOME keeps the original property
# (a build tree or editor elsewhere cannot match) while accepting both layouts.
chain_pid=$(pid_of "$qadenabin/qadenad .*start")
[ -z "$chain_pid" ] && chain_pid=$(pid_of "$QADENAHOME/cosmovisor/.*/bin/qadenad .*start")
if [ -n "$chain_pid" ]; then
    ok "qadenad          pid $chain_pid   up $(uptime_of $chain_pid)"
else
    bad "qadenad          not running"
fi

# On a managed node, say which generation is live and whether a swap is pending -- the two
# questions an operator actually has mid-upgrade.
if [ -L "$QADENAHOME/cosmovisor/current" ]; then
    cv_pid=$(pid_of "cosmovisor run")
    if [ -n "$cv_pid" ]; then
        ok "cosmovisor       pid $cv_pid   current -> $(readlink "$QADENAHOME/cosmovisor/current")"
    else
        bad "cosmovisor       not running (managed node launched without it?)"
    fi
    if [ -f "$QADENAHOME/data/upgrade-info.json" ]; then
        info "  pending/applied upgrade: $(tr -d '\n' < "$QADENAHOME/data/upgrade-info.json" | head -c 120)"
    fi
fi

# The enclave.  Under real SGX it runs under ego-host, so both spellings have to be tried -- looking
# only for the bare binary would report a healthy SGX node as down.
enclave_pid=$(pid_of "$qadenabin/qadenad_enclave")
[ -z "$enclave_pid" ] && enclave_pid=$(pid_of "$QADENAHOME/cosmovisor/.*/bin/qadenad_enclave")
[ -z "$enclave_pid" ] && enclave_pid=$(pid_of "ego-host.*qadenad_enclave")
if [ -n "$enclave_pid" ]; then
    ok "qadenad_enclave  pid $enclave_pid   up $(uptime_of $enclave_pid)"
else
    bad "qadenad_enclave  not running"
fi

signer_pid=$(pid_of "$qadenabin/signer_enclave")
[ -z "$signer_pid" ] && signer_pid=$(pid_of "$QADENAHOME/cosmovisor/.*/bin/signer_enclave")
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

    # ---------------------------------------------------------------------------------------
    # THE FLEET, AS EACH NODE SEES ITSELF.
    #
    # Two questions an operator has before touching anything, neither answerable from this node
    # alone:
    #
    #   1. "If I stop this one, does the chain keep producing?"  CometBFT needs MORE than 2/3 of
    #      voting power online, so the answer is (total - this one)/total per validator -- not
    #      visible from a stake list.  On 2026-08-21 a build stopped the primary while it held
    #      47% and the chain halted ~25 minutes, because nothing said THAT node was the unsafe
    #      one while the other three were fine.
    #
    #   2. "Is everyone actually keeping up?"  A node can hold its RPC open, report
    #      catching_up=false, and still be thousands of blocks behind -- CometBFT reports
    #      caught-up once it leaves blocksync, not once it is current.  So height is asked of
    #      EACH peer and shown as a lag against the furthest ahead.
    #
    # Peers come from the chain's own IntervalPublicKeyID rows, the same source getSSPrivK uses
    # to find them, so this reports the set the enclave would actually try to reach.
    myaddr=$(echo "$node_status" | jq -r '.result.validator_info.address // empty')
    vals=$(curl -s -m 5 "$rpc/validators?per_page=100" 2>/dev/null)
    if [ -n "$vals" ] && [ "$(echo "$vals" | jq -r '.result.validators // empty')" != "" ]; then
        echo ""
        echo "VALIDATORS"
        total=$(echo "$vals" | jq -r '[.result.validators[].voting_power|tonumber] | add')
        count=$(echo "$vals" | jq -r '.result.validators | length')
        info "$count active, total voting power $total"

        # EVERY PIONEER, INCLUDING THOSE WITH NO PUBLISHED ADDRESS.  This filter used to carry
        # `and .externalIPAddress!=""`, which silently DROPPED a pioneer that had not published
        # yet -- so a freshly bonded validator counted toward "N active" above but had no row
        # here, and the only hint was the two numbers disagreeing.  That is the state an operator
        # most needs named: it is voting in consensus, yet invisible to the re-share audit, which
        # filters on exactly this field (see getAddressablePioneers).  A missing row reads as
        # "nothing to see"; the honest answer is "here, and here is what is wrong with it".
        peers=$(qadenad_alias q qadena list-interval-public-key-id -o json 2>/dev/null \
            | jq -r '.intervalPublicKeyID[] | select(.nodeType=="pioneer")
                     | .nodeID+"\t"+(if .externalIPAddress=="" then "-" else .externalIPAddress end)+"\t"+.pubKID' 2>/dev/null)
            # THE "-" IS LOad-BEARING, not cosmetic.  Tab is an IFS *whitespace* character, so
            # `read` collapses a run of them into ONE separator: an empty middle field simply
            # vanishes and every later field shifts left.  Emitting "" for an unpublished address
            # therefore put the pubKID into $pip, and the row rendered as "unreachable at
            # qadena1...".  A non-empty placeholder keeps the columns aligned.

        # THE STAKING SET, so a pioneer with no published address is not a blank row.  A pioneer's
        # registry pubKID and its validator operator address are THE SAME 20 BYTES in different
        # bech32 clothing -- qadena1<data><csum> and qadenavaloper1<data><csum> share <data>
        # exactly.  That gives a DERIVED, not guessed, link from a pioneer to its consensus
        # identity, so power/share/priority can be filled in for a node we cannot dial.
        stakejson=$(qadenad_alias q staking validators --output json 2>/dev/null)

        # Ask every peer where it is, then work out the furthest ahead so the rest can be shown
        # as a lag rather than as a bare number nobody can compare.
        rows=""; best=0
        while IFS=$'\t' read -r pid pip pubkid; do
            [ -z "$pid" ] && continue
            # Registered but never published.  Nothing to dial, so the columns that come from the
            # node's own RPC -- height, catching-up, version, enclave measurement -- stay "-";
            # those are genuinely unknown and inventing them would be worse than a blank.
            #
            # But power and the consensus address are NOT unknown: they are on chain, reachable
            # through the pubKID -> valoper -> staking -> consensus_pubkey chain described above.
            # Filling them is the difference between "this node is a mystery" and "this node is a
            # bonded validator that has not published an address yet", which is the whole point.
            if [ "$pip" = "-" ]; then
                vpower="-"; vaddr="-"
                if [ -n "$pubkid" ] && [ -n "$stakejson" ]; then
                    # bech32: strip the "qadena1" HRP and the 6-char checksum to get the shared data
                    data=${pubkid#qadena1}; data=${data%??????}
                    tokens=$(echo "$stakejson" | jq -r --arg d "$data" \
                        '.validators[] | select(.operator_address | startswith("qadenavaloper1"+$d)) | .tokens' 2>/dev/null | head -1)
                    if [ -n "$tokens" ] && [ "$tokens" != "null" ]; then
                        # tokens are aqdn, exactly 1e18 per unit of voting power -- so DROP 18
                        # DIGITS rather than dividing.  awk (and jq) compute in doubles, which
                        # carry ~15-16 significant digits; a stake of 1e23 aqdn divided by 1e18
                        # came back as 99999 instead of 100000, and that off-by-one then failed
                        # the voting_power match below and left the address as "?".  Integer
                        # string surgery has no such rounding.
                        if [ ${#tokens} -gt 18 ]; then
                            vpower=${tokens%??????????????????}
                        else
                            vpower="0"
                        fi
                        # and the consensus address is whichever /validators row carries that power
                        vaddr=$(echo "$vals" | jq -r --arg p "$vpower" \
                            '[.result.validators[] | select(.voting_power==$p)] | if length==1 then .[0].address else "" end' 2>/dev/null)
                        [ -z "$vaddr" ] && vaddr="?"
                    fi
                fi
                # "NOTHING TO DIAL" IS ONLY TRUE FROM SOMEWHERE ELSE.  If the unpublished pioneer
                # is THIS node, its RPC is on localhost and none of these columns is unknown --
                # height, catching-up, version and measurement are all one curl away.  Leaving them
                # blank is exactly the case an operator hits: you run this ON the node you are
                # wondering about, precisely BECAUSE it has not published, and the row about
                # yourself is the emptiest one on the screen.
                #
                # Its own /status also carries voting_power and the consensus address directly, so
                # they are read rather than derived through the pubKID -> valoper -> staking chain
                # above -- same answer, one hop instead of three, and no bech32 surgery to get wrong.
                if [ -n "$moniker" ] && [ "$pid" = "$moniker" ] && [ -n "$node_status" ]; then
                    sh=$(echo "$node_status"  | jq -r '.result.sync_info.latest_block_height // "?"')
                    scu=$(echo "$node_status" | jq -r '.result.sync_info.catching_up // "?"')
                    spw=$(echo "$node_status" | jq -r '.result.validator_info.voting_power // "0"')
                    sad=$(echo "$node_status" | jq -r '.result.validator_info.address // ""')
                    sver=$(curl -s -m 3 "$rpc/abci_info" 2>/dev/null \
                           | jq -r '.result.response.version // "?"')
                    [ -z "$sver" ] && sver="?"
                    suid=$(timeout 6 "$qadenabin/qadenad" --home "$QADENAHOME" q qadena enclave-measurement \
                             --node "$rpc" -o json 2>/dev/null | jq -r '.uniqueID // empty')
                    [ -z "$suid" ] && suid="?"
                    [ "$sh" != "?" ] && [ "$sh" -gt "$best" ] 2>/dev/null && best=$sh
                    rows="$rows$pid\t(unpublished, self)\t$sh\t$scu\t$spw\t$sad\t$sver\t$suid\n"
                    continue
                fi
                rows="$rows$pid\t(unpublished)\t-\t-\t$vpower\t$vaddr\t-\t-\n"
                continue
            fi
            st=$(curl -s -m 3 "http://$pip:26657/status" 2>/dev/null)
            if [ -z "$st" ]; then
                rows="$rows$pid\t$pip\t?\t?\t?\tNO RPC\t?\t?\n"
                continue
            fi
            h=$(echo "$st"  | jq -r '.result.sync_info.latest_block_height // "?"')
            cu=$(echo "$st" | jq -r '.result.sync_info.catching_up // "?"')
            pw=$(echo "$st" | jq -r '.result.validator_info.voting_power // "0"')
            ad=$(echo "$st" | jq -r '.result.validator_info.address // ""')
            # WHAT EACH PEER IS ACTUALLY RUNNING, asked of the peer rather than assumed from this
            # node.  Upgrades swap every node at the same height, so the fleet should be uniform --
            # which makes a node that ISN'T the thing worth seeing, and this table is where you
            # see it.  "Did M4 come back on the new enclave" has no answer without these columns.  /abci_info carries the app
            # version; enclave-measurement is a normal chain query, so both work against a remote
            # node with no ssh.  Neither is fatal if it fails: a "?" costs nothing, and blocking
            # the whole table on one slow peer would.
            ver=$(curl -s -m 3 "http://$pip:26657/abci_info" 2>/dev/null \
                  | jq -r '.result.response.version // "?"')
            [ -z "$ver" ] && ver="?"
            uid=$(timeout 6 "$qadenabin/qadenad" --home "$QADENAHOME" q qadena enclave-measurement \
                    --node "tcp://$pip:26657" -o json 2>/dev/null | jq -r '.uniqueID // empty')
            [ -z "$uid" ] && uid="?"
            [ "$h" != "?" ] && [ "$h" -gt "$best" ] 2>/dev/null && best=$h
            rows="$rows$pid\t$pip\t$h\t$cu\t$pw\t$ad\t$ver\t$uid\n"
        done < <(echo "$peers")

        info ""
        info "  node       ip                address        ver      enclave    height      lag   power        share  if stopped  state"
        unsafe=0
        printf "$rows" | while IFS=$'\t' read -r pid pip h cu pw ad ver uid; do
            [ -z "$pid" ] && continue
            mark="  "; [ -n "$ad" ] && [ "$ad" = "$myaddr" ] && mark="=>"
            # NOT the same as unreachable, and the difference is the whole point of the row.
            # Unreachable means "it should answer and does not"; this means "it has never told
            # anyone where it is".  updateIsValidator publishes the address only under IsProposer
            # -- on the node's FIRST PROPOSED BLOCK after bonding -- so a validator with a small
            # stake can sit here for a while, voting normally, while the re-share audit cannot
            # count it and every audit tick is a no-op.
            # SELF, UNPUBLISHED.  Everything except the address is known, because the node is this
            # one -- so render a full row and let the state column carry the one thing that is
            # actually wrong.  The blank-row treatment below is for OTHER nodes, where the missing
            # columns really are unreachable.
            if [ "$pip" = "(unpublished, self)" ]; then
                slag=$((best - h))
                sshare="-"; srest="-"
                if [ -n "$total" ] && [ "$total" != "0" ]; then
                    sshare=$(echo "$pw $total" | awk '{printf "%.1f", $1*100/$2}')
                    srest=$(echo "$pw $total"  | awk '{printf "%.1f", ($2-$1)*100/$2}')
                fi
                saddr="${ad:0:12}"; [ -z "$saddr" ] && saddr="-"
                warn "$mark $(printf %-9s "$pid") $(printf %-17s "no address (self)") $(printf %-13s "$saddr") $(printf %-8s "$ver") $(printf %-10s "$(short_uid "$uid")") $(printf %-10s "$h") $(printf %5s "$slag")  $(printf %-12s "$pw") $(printf %5s "$sshare")%  $(printf %6s "$srest")%   NOT PUBLISHED"
                continue
            fi
            if [ "$pip" = "(unpublished)" ]; then
                # A REAL ROW, not a footnote.  Everything the chain knows is shown; only the
                # columns that require dialling the node are "-".  A reader can then see at a
                # glance that this is a bonded validator carrying real stake which the re-share
                # audit still cannot count -- rather than an anomaly they have to go and explain.
                ushare="-"; urest="-"
                if [ "$pw" != "-" ] && [ "$pw" != "?" ] && [ -n "$total" ] && [ "$total" != "0" ]; then
                    ushare=$(echo "$pw $total" | awk '{printf "%.1f", $1*100/$2}')
                    urest=$(echo "$pw $total"  | awk '{printf "%.1f", ($2-$1)*100/$2}')
                fi
                uaddr="${ad:0:12}"; [ -z "$uaddr" ] && uaddr="-"
                warn "$mark $(printf %-9s "$pid") $(printf %-17s "no address") $(printf %-13s "$uaddr") $(printf %-8s "-") $(printf %-10s "-") $(printf %-10s "-") $(printf %5s "-")  $(printf %-12s "$pw") $(printf %5s "$ushare")%  $(printf %6s "$urest")%   NOT PUBLISHED"
                continue
            fi
            if [ "$h" = "?" ]; then
                bad "$mark $(printf %-10s "$pid") unreachable at $pip"
                continue
            fi
            lag=$((best - h))
            share=$(echo "$pw $total" | awk '{printf "%.1f", $1*100/$2}')
            rest=$(echo "$pw $total"  | awk '{printf "%.1f", ($2-$1)*100/$2}')
            state="ok"; [ "$cu" = "true" ] && state="CATCHING UP"
            [ "$lag" -gt 20 ] && state="BEHIND"
            # Both names, because they answer different questions.  The pioneer id is what the
            # scripts, the owner lists and the ss-reconstruct: log lines use; the consensus
            # address is what /validators, the block headers and a CONSENSUS FAILURE report use.
            # Having only one of them means translating by hand at exactly the wrong moment.
            addr="${ad:0:12}"; [ -z "$addr" ] && addr="-"
            # The IP is the third name this node answers to, and it is the one you need to reach
            # it -- to ssh in, to curl its RPC, or to see which box a BEHIND row actually is.
            # It comes from the chain's own IntervalPublicKeyID row, so it is also exactly the
            # address the enclave would dial for a secret share.
            line="$mark $(printf %-9s "$pid") $(printf %-17s "$pip") $(printf %-13s "$addr") $(printf %-8s "$ver") $(printf %-10s "$(short_uid "$uid")") $(printf %-10s "$h") $(printf %5s "$lag")  $(printf %-12s "$pw") $(printf %5s "$share")%  $(printf %6s "$rest")%   $state"
            if [ "$(echo "$rest" | awk '{print ($1 > 66.67) ? 1 : 0}')" = "1" ] && [ "$state" = "ok" ]; then
                info "$line"
            else
                warn "$line"
            fi
        done

        # The safety verdict is recomputed here rather than inside the loop above: that loop runs
        # in a subshell (it is the right-hand side of a pipe), so a counter incremented there does
        # not survive it.
        unsafe=$(echo "$vals" | jq -r --argjson t "$total" \
            '[.result.validators[] | select((($t - (.voting_power|tonumber)) / $t * 100) <= 66.67)] | length')
        info ""

        # RECONCILE THE TWO COUNTS OUT LOUD.  "N active" is CometBFT's consensus set; the table is
        # the chain's pioneer list.  They measure different things and are ROUTINELY different --
        # a bonded validator that has not published yet, or a stale pioneer row left by an aborted
        # join, both make them diverge.  Left unstated, the reader either misses it or assumes a
        # bug in the table.  The number that actually governs re-sharing is the third one: how many
        # pioneers have an address, because that is what getAddressablePioneers counts and what the
        # audit uses as its target.
        pio_total=$(qadenad_alias q qadena list-interval-public-key-id -o json 2>/dev/null \
            | jq -r '[.intervalPublicKeyID[] | select(.nodeType=="pioneer")] | length' 2>/dev/null)
        pio_addr=$(qadenad_alias q qadena list-interval-public-key-id -o json 2>/dev/null \
            | jq -r '[.intervalPublicKeyID[] | select(.nodeType=="pioneer" and .externalIPAddress!="")] | length' 2>/dev/null)
        if [ -n "$pio_total" ] && [ -n "$pio_addr" ]; then
            info "$count validator(s) in consensus; $pio_total pioneer(s) registered; $pio_addr with a published address"
            if [ "$pio_addr" != "$pio_total" ]; then
                info "  the re-share audit targets $pio_addr owners -- the unpublished ones above cannot be counted"
            fi
        fi
        info ""
        if [ "$unsafe" = "0" ]; then
            info "every validator can be stopped one at a time without halting the chain"
        else
            info "$unsafe validator(s) hold more than 1/3 -- STOPPING ONE HALTS THE CHAIN"
            info "until stake is spread so that no one validator exceeds 33.33%"
        fi
        info "(=> marks this node; consensus needs MORE than 66.67% online)"
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
