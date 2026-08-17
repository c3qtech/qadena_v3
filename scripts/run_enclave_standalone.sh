#!/bin/zsh

# Starts the chain enclave ALONE -- no chain, no respawn loop, foreground.
#
# The normal path does not use this: `qadenad start` spawns and supervises its own enclave
# processes (x/qadena/keeper/enclave_supervisor.go).  This script exists for the flows that need
# an enclave with no chain attached:
#
#   promotion    add_full_node.sh starts the enclave alone to mint/fund the pioneer key and run
#                `qadenad enclave sync-enclave` (the attested key fetch from a peer enclave)
#                BEFORE the node's first start.
#   debugging    run this under a debugger, then start the node with
#                    qadenad start --external-enclave     (or run.sh --external-enclave)
#                which dials instead of spawning.  For the debugger itself:
#                    dlv exec $QADENAHOME/bin/qadenad_enclave -- --home=$QADENAHOME --chain-id=...
#                    gdb --args $QADENAHOME/bin/qadenad_enclave --home=$QADENAHOME --chain-id=...
#                (a REAL enclave runs under `ego run` and is not debuggable this way; use a debug
#                build for source-level debugging.)
#   upgrades     upgrade_enclave.sh execs the binaries directly with --upgrade-mode flags; it does
#                not use this script, but it is the same standalone pattern.
#
# Single shot, deliberately: the old run_enclave.sh/run_realenclave.sh respawn loops are gone --
# under `qadenad start` an enclave death now takes the node down for the process supervisor to
# restart, and a standalone enclave that dies should return control to whoever started it.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

# The same gate the spawn preflight applies in-process: a real enclave must be able to open the
# SGX devices, and the message names the exact fix (group membership preferred over root).
needs_root_if_real_enclave "run_enclave_standalone.sh" "$qadenabin/qadenad_enclave"

for d in enclave_config enclave_data enclave_secrets ; do
    [[ -d "$QADENAHOME/$d" ]] || mkdir "$QADENAHOME/$d"
done

CHAINID=$(jq -r '.chain_id' "$QADENAHOME/config/genesis.json")

# enable core dumps
ulimit -c unlimited

# Same log-level and pruning derivations the supervisor uses, so a standalone enclave behaves
# exactly like a spawned one.  The pruning window matters even standalone: the enclave must retain
# at least as much history as the chain, or a rollback the chain accepts fails on the enclave.
log_level=$(grep "log_level" $QADENAHOME/config/config.toml | awk '{print $3}' | tr -d '"' | tr -d "'")
[[ $log_level == "debug" ]] || log_level="info"

toml_value() {
    grep "^$2[[:space:]]*=" "$1" 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' "'"'"''
}
pruning_strategy=$(toml_value "$QADENAHOME/config/app.toml" "pruning")
pruning_keep_recent=$(toml_value "$QADENAHOME/config/app.toml" "pruning-keep-recent")
pruning_interval=$(toml_value "$QADENAHOME/config/app.toml" "pruning-interval")
[[ -z $pruning_strategy ]] && pruning_strategy="default"
[[ -z $pruning_keep_recent ]] && pruning_keep_recent=0
[[ -z $pruning_interval ]] && pruning_interval=0
echo "$(basename $0): chain pruning: $pruning_strategy keep-recent=$pruning_keep_recent interval=$pruning_interval"

if use_real_enclave "$qadenabin/qadenad_enclave" ; then
    "$qadenascripts/ensure_sgx_attestation.sh" || exit 1
    enclave_cmd=(ego run $qadenabin/qadenad_enclave --realenclave)
else
    enclave_cmd=($qadenabin/qadenad_enclave)
fi
enclave_cmd+=(--home=$QADENAHOME --chain-id=$CHAINID --log-level $log_level --pruning=$pruning_strategy --pruning-keep-recent=$pruning_keep_recent --pruning-interval=$pruning_interval)

# START IT IN ITS OWN PROCESS GROUP AND RECORD THE GROUP, instead of exec'ing and leaving the
# stopper to find it by name.
#
# This script used to `exec`, which made the enclave -- or, on SGX, the `ego run` LAUNCHER, with the
# real work in a forked ego-host -- a member of whatever group the caller happened to be in.  Nobody
# could then signal "the enclave" as a unit: stop_qadena.sh had to match two different command lines
# and hope, and add_full_node.sh --stop-for-funding once left an ego-host alive holding
# /tmp/qadena_50051.sock, so the next run's enclave unlinked the socket underneath a client that had
# already probed the OLD one -- surfacing as an unexplained
#     rpc error: code = Unavailable desc = error reading from server: EOF
# in the middle of sync-enclave.  A recorded pgid makes the whole tree addressable, which is what
# the in-process supervisor gets from Setpgid.
#
# The script stays alive as the group's anchor rather than exec'ing away, so it can clean the file
# up and forward signals -- a debugger user pressing ^C should still stop the enclave.
run_in_new_process_group "${enclave_cmd[@]}" &
enclave_pgid=$!

print -r -- "$enclave_pgid" > "$qadena_enclave_pgidfile" 2>/dev/null \
    || echo "$(basename $0): WARNING: could not write $qadena_enclave_pgidfile -- stopping will fall back to pattern matching"

cleanup() {
    # Only remove OUR file: a second standalone enclave under a different home writes a different
    # path, and one under the same home would have overwritten this one, in which case the newer
    # pgid is the correct one to leave behind.
    [[ $(cat "$qadena_enclave_pgidfile" 2>/dev/null) == $enclave_pgid ]] && rm -f "$qadena_enclave_pgidfile"
}
forward() {
    kill -INT -- -$enclave_pgid 2>/dev/null
    wait $enclave_pgid 2>/dev/null
    cleanup
    exit 130
}
trap forward INT TERM
trap cleanup EXIT

echo "$(basename $0): enclave process group $enclave_pgid (recorded in $qadena_enclave_pgidfile)"
wait $enclave_pgid
exit $?
