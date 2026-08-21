#!/bin/zsh
#
# Swap a held-back enclave binary in as the live one, once its measurement is ACTIVE on chain.
#
#   activate_enclave.sh <uniqueID>       stop, swap, and start
#   activate_enclave.sh <uniqueID> --no-start   stop and swap only
#
# This is the second half of the deploy that `build.sh --hold` deliberately does not do.  The split
# exists because of an ordering constraint that is not obvious and is unforgiving:
#
#   the old enclave will not hand its sealed keys to a measurement the chain has not made ACTIVE
#
# and the sealed keys are the jar and regulator private keys, which exist nowhere else. Swapping the
# binary in before the identity is active does not corrupt anything, but the upgrade fails and the
# node stays DOWN until you put the old binary back.
#
# On SGX this ordering is forced: MRENCLAVE is a hash of the built image, so the measurement cannot
# be registered until after the build. build --hold, read it with `ego uniqueid`, register, wait,
# then run this.
#
# Refuses to swap unless the chain says the target is active, so the failure happens here -- with an
# explanation -- rather than as a node that will not start.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1
source "$SCRIPT_DIR/gov_lib.sh"

uid="$1"; shift 2>/dev/null
no_start=0
[[ "$1" == "--no-start" ]] && no_start=1

if [ -z "$uid" ]; then
    echo "Usage: activate_enclave.sh <uniqueID> [--no-start]"
    echo "  staged binaries available:"
    for f in "$qadenabin"/qadenad_enclave.*(N); do echo "    ${${f##*/}##*.}"; done
    exit 1
fi

staged="$qadenabin/qadenad_enclave.$uid"
[ -x "$staged" ] || { echo "no staged binary at $staged"; exit 1 }

st=$(qq q qadena show-enclave-identity "$uid" --output json 2>/dev/null | jq -r '.enclaveIdentity.status // empty')
case "$st" in
    active) echo "$uid is active on chain -- proceeding" ;;
    unvalidated)
        echo "$uid is registered but still UNVALIDATED -- the peer quorum has not promoted it."
        echo "Swapping now would fail the handover and leave this node down.  Wait and re-run."
        exit 1 ;;
    inactive)
        echo "$uid is INACTIVE on chain -- condemned or retired, and permanently so."
        echo "Build a new measurement; this one cannot be revived."
        exit 1 ;;
    *)
        echo "$uid is NOT REGISTERED on chain."
        echo "Register it first:  scripts/gov_register_enclave_identity.sh $uid <signerID>"
        exit 1 ;;
esac

current=$("$qadenabin/qadenad_enclave" -unique-id 2>/dev/null)
newver=$("$staged" -version 2>/dev/null)
oldver=$("$qadenabin/qadenad_enclave" -version 2>/dev/null)
echo "  live now : ${current:-unknown} (version $oldver)"
echo "  swapping : $uid (version $newver)"

if [ "$newver" = "$oldver" ]; then
    echo "  WARNING: versions are equal, so run.sh will NOT perform a handover on start."
    echo "  An upgrade requires a STRICT version increase.  Bump version.txt and rebuild."
fi

# Keep a labelled copy of what is being replaced, so a rollback is a single cp.
if [ -n "$current" ] && [ ! -x "$qadenabin/qadenad_enclave.$current" ]; then
    cp -p "$qadenabin/qadenad_enclave" "$qadenabin/qadenad_enclave.$current" \
      && echo "  preserved the outgoing binary as qadenad_enclave.$current"
fi

echo "  stopping the node (a running binary cannot be replaced)"
"$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1
alive=$(( $(pgrep -cx qadenad) + $(pgrep -cx qadenad_enclave) + $(pgrep -cx signer_enclave) ))
[ "$alive" -ne 0 ] && { echo "  $alive process(es) still running -- refusing to swap"; exit 1 }

cp "$staged" "$qadenabin/qadenad_enclave" || { echo "  copy failed"; exit 1 }
echo "  live is now $("$qadenabin/qadenad_enclave" -unique-id) (version $("$qadenabin/qadenad_enclave" -version))"

if [ $no_start -eq 1 ]; then
    echo "  --no-start: the node is stopped.  Start it with scripts/start_qadena.sh"
    exit 0
fi

echo "  starting -- run.sh performs the handover on the way up"
"$qadenascripts/start_qadena.sh"
echo
echo "  verify with:  scripts/enclave_identities.sh"
echo "  a successful handover logs 'Upgrade successful' and creates"
echo "  enclave_config/enclave_params_$uid.json"
