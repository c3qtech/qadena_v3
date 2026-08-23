#!/bin/zsh
# A SIMPLE rolling upgrade of a running fleet: one node at a time, no downtime for the chain.
#
#   ./rolling_upgrade.sh --node m1 --node m2 --node m3 --node m4 \
#                        --archive ~/qadena-full-1.1.14-abc1234.tar.gz
#
# USE THIS WHEN THE RELEASE IS ENCLAVE-ONLY -- no new chain message type, no change to how a block
# is validated.  Then old and new nodes speak the same protocol, a mixed fleet is fine at every
# instant, and the nodes can simply be replaced in turn.
#
# USE split_roll_upgrade.sh INSTEAD IF THE RELEASE ADDS A CHAIN MESSAGE TYPE.  An old qadenad cannot
# decode one it was not built with, so a block carrying it is invalid to that node -- it halts or
# forks.  That case needs the chain binaries everywhere BEFORE any enclave that produces the new
# message goes live, which is a different (two-phase) shape.  If you are unsure which you have:
# did x/qadena/types/tx.proto gain a message?  Then it is the split roll.
#
# WHAT THIS SCRIPT DOES NOT DO: build, or package.  Build ONCE on one node and package there --
# the build is not reproducible and a debug enclave takes its identity from an embedded text file,
# so two builds of one commit are two different binaries claiming the same measurement (backlog
# 105).  Distribute the ONE artifact and verify it by sha256 on arrival, which this does.
#
# THE ORDER MATTERS AND IS NOT OBVIOUS:
#
#   1. REGISTER the new measurement by governance, and get it PROMOTED to active, BEFORE touching
#      any node.  install_release.sh only cuts over to an ACTIVE identity; with --wait-active it
#      waits, but it cannot create the promotion.
#   2. QUORUM IS NOT ONE VOTE.  Governance quorum here is 33.4% and four equal validators are 25%
#      each, so a proposal voted by the submitter alone is REJECTED for want of quorum, with a
#      tally showing zero NO votes -- which reads as a rejection on merit and is not.  At least two
#      validators must vote.  This script votes from every node it is given.
#   3. PROMOTION IS TRIGGERED BY A RESTART.  validateEnclaveIdentities runs when
#      unvalidatedEnclaveIdentitiesCheckCounter hits zero; it starts at 1, so the first UpdateHeight
#      after a restart runs it, and otherwise it is up to keyUpdateFrequency ticks away.  So one
#      node is restarted (on its OLD enclave -- harmless, nothing is installed yet) to make the
#      promotion happen now instead of hours from now.
#   4. ONE NODE AT A TIME, and the height must be ADVANCING before the next.  Processes being up is
#      not health: on four equal validators one down leaves 75% and the chain moves, two down
#      leaves 50% and it halts with every process still running.  A node that is BEHIND when a
#      measurement is promoted can never trust it (backlog 99), which is why this waits rather than
#      pipelining.
#
# ALSO: install_release.sh refuses to overwrite a versioned binary whose bytes differ, and the
# signer enclave keeps its name across a non-reproducible rebuild -- so signer_enclave.<unique> is
# moved aside before installing.  It is MOVED, never deleted: the old enclave has to stay on disk
# for the --upgrade-mode handover.

set -u
setopt ERR_EXIT PIPE_FAIL

NODES=(); ARCHIVE=""; NEW_UNIQUE=""; NEW_SIGNER=""; WAIT_SECS=1800; DRY=0; SKIP_GOV=0

while (( $# )); do
    case "$1" in
        --node)       NODES+=("$2"); shift 2 ;;
        --archive)    ARCHIVE="$2"; shift 2 ;;
        --unique)     NEW_UNIQUE="$2"; shift 2 ;;
        --signer)     NEW_SIGNER="$2"; shift 2 ;;
        --wait-secs)  WAIT_SECS="$2"; shift 2 ;;
        --skip-governance) SKIP_GOV=1; shift ;;   # already registered and active
        --dry-run)    DRY=1; shift ;;
        --help|-h)    sed -n '2,48p' "$0"; exit 0 ;;
        *) print -u2 "FAIL: unknown flag $1"; exit 1 ;;
    esac
done

(( ${#NODES} >= 1 )) || { print -u2 "FAIL: --node is required (repeatable)"; exit 1 }
[[ -n "$ARCHIVE" ]] || { print -u2 "FAIL: --archive is required"; exit 1 }

say()  { print -- "$(date '+%H:%M:%S')  $*" }
step() { print ""; print -- "=== $* ===" }
die()  { print -u2 "FAIL: $*"; exit 1 }
rsh()  { local h="$1"; shift; ssh -o ConnectTimeout=10 -o BatchMode=yes "$h" "bash -lc $(printf '%q' "$*")" }
run()  { local h="$1"; shift; if (( DRY )); then print -- "    [dry-run] $h: $*"; else rsh "$h" "$@"; fi }

height_of() { rsh "$1" '~/qadena/bin/qadenad status 2>/dev/null' 2>/dev/null \
                | tr ',' '\n' | grep -oE '"latest_block_height":"[0-9]+"' | grep -oE '[0-9]+' | head -1 }
measure_of() { rsh "$1" '~/qadena/bin/qadenad q qadena enclave-measurement -o json 2>/dev/null' 2>/dev/null \
                | grep -oE 'unique[0-9]+' | head -1 }
identity_status() { rsh "${NODES[1]}" "~/qadena/bin/qadenad q qadena show-enclave-identity $1 -o json 2>/dev/null" 2>/dev/null \
                | grep -oE '"status":"[a-z]+"' | head -1 | cut -d'"' -f4 }

require_advancing() {
    local h1 h2
    h1=$(height_of "$1") || true; [[ -n "$h1" ]] || die "$1: no height -- is qadenad running?"
    sleep 12
    h2=$(height_of "$1") || true; [[ -n "$h2" ]] || die "$1: stopped answering"
    (( h2 > h1 )) || die "$1: height stuck at $h1 -- chain not advancing, refusing to continue"
    say "  $1 advancing $h1 -> $h2"
}

step "0. preflight"
for n in "${NODES[@]}"; do
    rsh "$n" 'true' || die "$n unreachable"
    say "$n  enclave=$(measure_of $n)  height=$(height_of $n)"
done
for n in "${NODES[@]}"; do require_advancing "$n"; done

[[ -f "$ARCHIVE" ]] || die "archive not found: $ARCHIVE"
LOCAL_SHA=$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
say "archive sha256 $LOCAL_SHA"

step "1. distribute (one artifact, verified by content on every node)"
REMOTE="/tmp/$(basename $ARCHIVE)"
for n in "${NODES[@]}"; do
    if (( DRY )); then print -- "    [dry-run] scp -> $n"; continue; fi
    scp -q "$ARCHIVE" "$n:$REMOTE" || die "$n: copy failed"
    got=$(rsh "$n" "sha256sum $REMOTE" | cut -d' ' -f1)
    [[ "$got" == "$LOCAL_SHA" ]] || die "$n: sha256 $got != $LOCAL_SHA"
    say "  $n verified"
done

if (( ! SKIP_GOV )); then
    [[ -n "$NEW_UNIQUE" && -n "$NEW_SIGNER" ]] || die "--unique and --signer are required unless --skip-governance"
    step "2. register $NEW_UNIQUE by governance, and get it promoted"
    say "submitting from ${NODES[1]} (it also votes)"
    run "${NODES[1]}" "cd ~/qv3 && ./testscripts/test_update_enclave_identity.sh $NEW_UNIQUE $NEW_SIGNER unvalidated" >/dev/null
    # NEWEST PROPOSAL, VIA REVERSE PAGING -- not a filtered list.  `q gov proposals` PAGINATES at
    # 100 and this chain already holds over a thousand, so listing and taking the last entry finds
    # the hundredth-oldest proposal, or nothing at all.  (The same default silently truncated a
    # list-public-key reading during the last rollout and made an owner-count report wrong.)
    # --page-reverse --page-limit 1 asks the chain for exactly the newest one, which is immune to
    # how many exist.  Note the id is a quoted STRING with a space after the colon in the
    # pretty-printed output, so parse the JSON rather than grepping for `"id":"N"`.
    PROP=$(rsh "${NODES[1]}" '~/qadena/bin/qadenad q gov proposals --page-reverse --page-limit 1 -o json 2>/dev/null' \
           | python3 -c 'import json,sys; print(json.load(sys.stdin)["proposals"][0]["id"])' 2>/dev/null)
    [[ -n "$PROP" ]] || die "could not find the proposal just submitted"
    # It must actually be OURS and still open -- a stale newest proposal would otherwise be voted on.
    PSTAT=$(rsh "${NODES[1]}" "~/qadena/bin/qadenad q gov proposal $PROP -o json 2>/dev/null" \
            | grep -oE 'PROPOSAL_STATUS_[A-Z_]+' | head -1)
    [[ "$PSTAT" == "PROPOSAL_STATUS_VOTING_PERIOD" ]] \
        || die "newest proposal $PROP is $PSTAT, not in its voting period -- did the submit fail?"
    say "  proposal $PROP"
    CHAIN=$(rsh "${NODES[1]}" '~/qadena/bin/qadenad status 2>/dev/null' | tr ',' '\n' | grep -oE '"network":"[^"]+"' | cut -d'"' -f4)
    # QUORUM: one validator is 25% against a 33.4% quorum.  Every node votes.
    for n in "${NODES[@]:1}"; do
        k=$(rsh "$n" '~/qadena/bin/qadenad keys list --keyring-backend test 2>/dev/null' | grep -oE 'pioneer[0-9]+' | head -1)
        [[ -n "$k" ]] || { say "  $n: no pioneer key, skipping vote"; continue }
        say "  voting yes from $k on $n"
        run "$n" "~/qadena/bin/qadenad tx gov vote $PROP yes --from $k --keyring-backend test --chain-id $CHAIN --gas auto --gas-adjustment 1.4 --gas-prices 100000000aqdn -y" >/dev/null
    done

    say "restarting ${NODES[1]} on its OLD enclave to trigger the identity check"
    run "${NODES[1]}" '~/qadena/scripts/stop_qadena.sh --all' >/dev/null 2>&1 || true
    (( DRY )) || sleep 5
    (( DRY )) || ssh -f -o BatchMode=yes "${NODES[1]}" "bash -lc 'nohup ~/qadena/scripts/start_qadena.sh >/tmp/rolling_start.log 2>&1 &'"

    say "waiting for $NEW_UNIQUE to become active (up to ${WAIT_SECS}s)"
    if (( ! DRY )); then
        waited=0
        while [[ "$(identity_status $NEW_UNIQUE)" != "active" && $waited -lt $WAIT_SECS ]]; do
            sleep 15; waited=$(( waited + 15 ))
            printf "    %4ds  status=%s\n" "$waited" "$(identity_status $NEW_UNIQUE)"
        done
        [[ "$(identity_status $NEW_UNIQUE)" == "active" ]] || die "$NEW_UNIQUE never became active"
        say "  ACTIVE"
    fi
fi

step "3. roll the fleet, one node at a time"
for n in "${NODES[@]}"; do
    say "$n: activating"
    # DO NOT HAND-ROLL THIS LOOP.  require_advancing below is the only thing standing between a
    # rolling upgrade and a halted chain: on four equal validators, taking a SECOND node down
    # before the first is back leaves 50%, which is under the two-thirds threshold, and the chain
    # stops with every process still running and no error anywhere.  That happened on 2026-08-23
    # doing exactly this by hand -- see backlog 108.
    # The signer keeps its name across a non-reproducible rebuild; move it aside (never delete --
    # the old enclave must stay on disk for the handover).
    run "$n" 'mkdir -p ~/qadena/bin/superseded; for f in ~/qadena/bin/signer_enclave.unique*; do [ -e "$f" ] && mv -f "$f" ~/qadena/bin/superseded/ ; done; true' >/dev/null 2>&1 || true
    run "$n" "~/qadena/scripts/install_release.sh $REMOTE --wait-active=$WAIT_SECS --restart"
    (( DRY )) || sleep 20
    (( DRY )) || require_advancing "$n"
    say "  $n now on $(measure_of $n)"
done

step "4. final state"
for n in "${NODES[@]}"; do say "$n  enclave=$(measure_of $n)  height=$(height_of $n)"; done
print ""
say "Watch the next rotation tick for the audit:  grep 'ss-reshare: AUDIT' ~/qadena/logs/qadena.log"
