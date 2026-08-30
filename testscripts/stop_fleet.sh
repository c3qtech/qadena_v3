#!/bin/zsh
#
# Stop a whole fleet, and optionally remove what it left behind.
#
#   ./testscripts/stop_fleet.sh --node m1 --node m2 --node m3 --node m4
#   ./testscripts/stop_fleet.sh --node m1 ... --purge --reap-archives
#
# WHAT THIS REPLACES.  Tearing a fleet down was an ad-hoc loop typed out per run: stop the soak,
# stop the node, check nothing survived, delete the archives, look at the disk.  Every step has a
# trap under it, they are the same traps every time, and a half-finished teardown is not obvious --
# a node that came back under systemd looks exactly like one that never stopped.
#
# NOTHING IS DELETED BY DEFAULT.  Stopping is safe and repeatable; deleting is neither.  ~/qadena
# holds the KEYRING as well as chain data, and on a joiner it is the only copy of that node's
# pioneer key.  So removal is opt-in per kind:
#
#   (default)         stop everything, verify it stayed stopped, report disk
#   --purge           ALSO remove ~/qadena entirely -- chain data AND keyring
#   --reap-archives   ALSO remove ~/qadena.pre-bringup.*.bak left by previous bringups
#   --clean-logs      ALSO empty ~/<repo>/logs -- the suite logs AND regression-history
#
# --clean-logs TAKES THE CROSS-RUN TALLY WITH IT.  logs/regression-history holds suites.tsv and
# history.tsv, which is where "no failures in 147 scored run(s)" comes from -- a soak's entire
# accumulated verdict, not just noise.  Deleting it is usually right before a clean-chain run and
# always wrong if you have not read the last result yet.  ~/<repo>/logs is gitignored, so emptying
# it does not dirty the checkout (which the bringup preflight refuses).  The node's own logs live
# under ~/qadena/logs and go with --purge instead -- those are the large ones, hundreds of MB.
#
# --reap-archives is worth reaching for on its own.  The bringup ARCHIVES a joiner's old ~/qadena
# rather than deleting it, and nothing ever reaps those: three runs once left 67G of them and took
# two joiners to 94% full.
#
# ---------------------------------------------------------------------------------------------
# THE TRAPS THIS ENCODES, all of which have cost a run:
#
#   1. PREFLIGHT EVERY HOST BEFORE STOPPING ANY.  The bringup learned this the hard way: a joiner
#      was archived and only then did the primary turn out to be unreachable, leaving the fleet in
#      a state neither up nor down.  Nothing here is touched until every host answers.
#
#   2. THE SOAK GOES FIRST.  A continuous regression left running through a teardown does not stop,
#      it starts FAILING -- issuing transactions at a chain being deleted underneath it -- and its
#      failures then look like chain bugs in the next run's logs.
#
#   3. ASK SYSTEMD WHERE THERE IS A UNIT.  "Nothing is running" is not "nothing will run":
#      Restart=on-failure brings a node back seconds after a direct kill appeared to work.
#      stop_qadena.sh handles this, so it is preferred over killing by hand wherever it exists.
#
#   4. CLEAR THE START-LIMIT LOCKOUT.  A node that crash-looped leaves its unit `failed`, and
#      StartLimitBurst=5 means the NEXT start is refused with "Start request repeated too quickly"
#      -- a bringup then fails to start a node that is perfectly fine.  `systemctl reset-failed`
#      costs nothing when the unit is healthy.  M1 needed exactly this on 2026-08-30.
#
#   5. NEVER rm -rf A LIVE NODE'S HOME.  Removal happens only after this script has SEEN zero
#      node and enclave processes on that host.  Deleting under a running node leaves processes
#      whose binaries no longer exist, and every later diagnosis describes a machine that cannot
#      be reasoned about.
#
#   6. BRACKET-CLASS EVERY PATTERN.  `pkill -f` and `pgrep -f` test the WHOLE command line of every
#      process, including the ssh command carrying the pattern.  Unbracketed patterns have twice
#      killed the thing doing the killing -- most recently upgrade_enclave.sh SIGINTing itself and
#      halting a fleet for three hours on an upgrade that had succeeded.

set -u
SCRIPT_DIR="${0:A:h}"
ME="${0:t}"

NODES=(); PURGE=0; REAP=0; CLEAN_LOGS=0; IMMEDIATE=""
REPO_DIR="qv3"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)           NODES+=("$2"); shift 2 ;;
        --purge)          PURGE=1; shift ;;
        --reap-archives)  REAP=1; shift ;;
        --clean-logs)     CLEAN_LOGS=1; shift ;;
        --repo)           REPO_DIR="$2"; shift 2 ;;
        --immediate)      IMMEDIATE="--immediate"; shift ;;
        --help)
            print "Usage: $ME --node <[user@]host> [--node ...]"
            print "                     [--purge] [--reap-archives] [--clean-logs] [--repo DIR] [--immediate]"
            print ""
            print "  Stops the continuous regression and the node on every host, then verifies"
            print "  nothing survived.  Deletes nothing unless asked."
            print ""
            print "  --node            REPEATABLE.  Every host is preflighted before any is touched."
            print "  --purge           ALSO remove ~/qadena -- chain data AND THE KEYRING.  Only"
            print "                    after that host is verified stopped."
            print "  --reap-archives   ALSO remove ~/qadena.pre-bringup.*.bak from earlier bringups."
            print "                    Nothing else ever reaps these and they fill disks."
            print "  --clean-logs      ALSO empty ~/<repo>/logs.  INCLUDES regression-history --"
            print "                    the cross-run tally behind \"no failures in N runs\".  The"
            print "                    node's own (much larger) logs are under ~/qadena/logs and"
            print "                    go with --purge."
            print "  --repo DIR        checkout directory under \$HOME (default qv3), for --clean-logs."
            print "  --immediate       end an in-flight regression run now rather than waiting it"
            print "                    out (passed through to stop_regression.sh)."
            print ""
            print "  Exit 0 when every host ended up stopped (and purged, if asked); 1 otherwise."
            exit 0 ;;
        *) print -u2 "$ME: unknown option $1  (--help)"; exit 1 ;;
    esac
done
(( ${#NODES[@]} > 0 )) || { print -u2 -- "--node is required (repeatable)"; exit 1 }

rsh() { ssh -o ConnectTimeout=10 -o BatchMode=yes "$1" "$2" 2>/dev/null }

# Trap 6: bracket-classed, so this can never count or kill the ssh command carrying it.
PROCPAT='qaden[a]d|cosmoviso[r] run|eg[o] run|ego-hos[t]|signer_enclav[e]'
live_count() { rsh "$1" "ps -eo pid,cmd | grep -E '$PROCPAT' | grep -v grep | wc -l" | tr -d '[:space:]' }

# ---------------------------------------------------------------------------------------------
# Trap 1: everything is checked before anything is changed.
print "$ME: preflighting ${#NODES[@]} host(s)"
for n in "${NODES[@]}"; do
    rsh "$n" 'true' >/dev/null || { print -u2 "$ME: FAILED: cannot ssh to $n -- nothing has been stopped"; exit 1 }
done
print "$ME: all hosts reachable"
(( PURGE )) && print "$ME: --purge: ~/qadena WILL BE REMOVED on every host once it is verified stopped"
(( REAP ))  && print "$ME: --reap-archives: qadena.pre-bringup.*.bak will be removed"
(( CLEAN_LOGS )) && print "$ME: --clean-logs: ~/$REPO_DIR/logs will be emptied, INCLUDING regression-history"

failed=0
for n in "${NODES[@]}"; do
    print ""
    print "=== $n ==="
    before=$(rsh "$n" 'df -h ~ | tail -1 | awk "{print \$4}"' | tr -d '\r')

    # Trap 2: the soak first, or it transacts against a chain being torn down.
    "$SCRIPT_DIR/stop_regression.sh" --host "$n" $IMMEDIATE 2>&1 | sed 's/^/  /'

    # Trap 3: stop_qadena.sh asks systemd when a unit exists; prefer it over killing by hand.
    if rsh "$n" 'test -x $HOME/qadena/scripts/stop_qadena.sh'; then
        rsh "$n" 'zsh -lc "$HOME/qadena/scripts/stop_qadena.sh --all"' | tail -3 | sed 's/^/  /'
    else
        print "  no ~/qadena/scripts/stop_qadena.sh -- killing by pattern instead"
        rsh "$n" "pkill -INT -f '[c]osmovisor run'; sleep 3; pkill -KILL -f '[c]osmovisor run'; true" >/dev/null
    fi

    # Trap 4: a crash-looped unit is left `failed`, and the NEXT start is refused.  Harmless when
    # the unit is healthy, so it is unconditional rather than guarded by a state check.
    if rsh "$n" 'test -f /etc/systemd/system/qadena.service'; then
        rsh "$n" 'sudo systemctl reset-failed qadena' >/dev/null
        print "  systemd: unit state cleared (was $(rsh "$n" 'systemctl is-active qadena' | tr -d "\r"))"
    fi

    left=$(live_count "$n")
    if [[ "${left:-1}" != "0" ]]; then
        print -u2 "  FAILED: $left node/enclave process(es) still running -- kill them BY PID and re-run"
        rsh "$n" "ps -eo pid,cmd | grep -E '$PROCPAT' | grep -v grep | cut -c1-100" | sed 's/^/    /'
        failed=1
        # Trap 5: nothing is removed on a host we could not prove is stopped.
        (( PURGE )) && print -u2 "  NOT PURGING $n: refusing to remove ~/qadena under live processes"
        continue
    fi
    print "  stopped: no node or enclave processes remain"

    if (( REAP )); then
        arch=$(rsh "$n" 'du -shc ~/qadena.pre-bringup.*.bak 2>/dev/null | tail -1 | cut -f1' | tr -d '\r')
        if [[ -n "$arch" && "$arch" != "0" ]]; then
            rsh "$n" 'rm -rf ~/qadena.pre-bringup.*.bak'
            print "  reaped archives ($arch)"
        else
            print "  no archives to reap"
        fi
    fi

    if (( CLEAN_LOGS )); then
        if rsh "$n" "test -d \$HOME/$REPO_DIR/logs"; then
            lsz=$(rsh "$n" "du -sh \$HOME/$REPO_DIR/logs 2>/dev/null | cut -f1" | tr -d '\r')
            hist=$(rsh "$n" "test -d \$HOME/$REPO_DIR/logs/regression-history && echo yes || echo no" | tr -d '\r')
            # CONTENTS, NOT THE DIRECTORY: the suites redirect into logs/ without creating it, so a
            # missing logs/ turns the next run's first write into "No such file or directory".
            #
            # `find -mindepth 1 -delete` rather than a glob.  `rm -rf logs/{,.[!.]}*` expands in
            # WHOSE shell is not knowable from here -- ssh runs the remote login shell -- and under
            # zsh an unmatched glob is a FATAL NOMATCH, so emptying an already-empty logs/ would
            # abort the teardown.  find needs no globbing, handles dotfiles, and is silent on empty.
            rsh "$n" "find \$HOME/$REPO_DIR/logs -mindepth 1 -delete 2>/dev/null; true"
            print "  cleaned ~/$REPO_DIR/logs ($lsz$( [[ "$hist" == yes ]] && print ", regression-history included"))"
        else
            print "  no ~/$REPO_DIR/logs to clean"
        fi
    fi

    if (( PURGE )); then
        if rsh "$n" 'test -d $HOME/qadena'; then
            sz=$(rsh "$n" 'du -sh ~/qadena 2>/dev/null | cut -f1' | tr -d '\r')
            rsh "$n" 'rm -rf $HOME/qadena'
            if rsh "$n" 'test -d $HOME/qadena'; then
                print -u2 "  FAILED: ~/qadena still present after rm -rf (permissions? root-owned files from a sudo run?)"
                failed=1
            else
                print "  purged ~/qadena ($sz) -- chain data and keyring are gone"
            fi
        else
            print "  no ~/qadena to purge"
        fi
    fi

    after=$(rsh "$n" 'df -h ~ | tail -1 | awk "{print \$4}"' | tr -d '\r')
    print "  disk free: $before -> $after"
done

print ""
if (( failed )); then
    print -u2 "$ME: FAILED -- see the host(s) above"
    exit 1
fi
print "$ME: done -- ${#NODES[@]} host(s) stopped$( (( PURGE )) && print " and purged")$( (( CLEAN_LOGS )) && print ", logs cleaned")"
exit 0
