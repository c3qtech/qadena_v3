#!/bin/zsh
#
# recover_enclave_after_cpu_move.sh -- bring back a node whose SEALED STATE belongs to another CPU.
#
#   scripts/recover_enclave_after_cpu_move.sh --seed tcp://<healthy peer>:26657 [--yes]
#
# WHEN.  check_sgx_platform.sh refused to start (exit 3), or the enclaves fail with
#     cipher: message authentication failed
# after the VM moved to another physical host (Azure deallocate, resize, redeploy, service healing).
# Sealing is bound to the physical CPU, so every sealed file this node wrote is now unreadable.
#
# WHAT IT DOES, with the node stopped:
#   1. moves ONLY the sealed params file (enclave_config/enclave_params_<uid>.json) into a dated
#      backup directory -- nothing is deleted.  That file is the one thing a CPU move actually
#      breaks: it is sealed with the SGX unique key, bound to this build AND this CPU.  The stores
#      stay put (see below);
#   2. starts the enclave alone and runs sync-enclave against --seed.  The seed hands over the shared
#      params and the SS owner map over an attested channel.  The escrow is encrypted to an SS
#      interval key, so the enclave gathers that key's shares from its OTHER owners (attested
#      queries, no transaction), opens the escrow, checks the escrowed enclave key against the one
#      the CHAIN records for this pioneer, and re-seals it all for this CPU.  Nothing is broadcast,
#      so this works while the chain is halted -- which it is, if this node holds most of the stake;
#   3. re-records this platform for check_sgx_platform.sh.
#
# WHY THE STORES STAY.  enclave_data/ and enclave_secrets/ hold row keys that are stable-sealed and
# row values that are AES-GCM -- both under SealedTableSharedSecret, a software key the escrow
# restores.  Nothing there is CPU-bound any more, so the private tables and this node's SS shares
# are readable again as soon as the escrow opens.  This script used to move all three directories
# aside, which discarded usable state and forced a needless refetch of the private tables from a
# peer.  signer_state.json rides along inside enclave_data/, so the double-sign watermark is kept
# without copying anything.
#
# On the next start the node comes back with its own private state (case A, not case F), and
# signer_enclave re-seals the validator key from config/priv_validator_key.json by itself.
#
# NEEDS ENOUGH OF THE SS KEY'S OTHER OWNERS REACHABLE: one, below four owners; the Shamir threshold
# above that.  This node's own share cannot count -- it decrypts only with the key being recovered.
#
# REQUIRES: enclave_config/private_params_escrow.json, written by a build that has the escrow, from
# before the move; config/priv_validator_key.json (or your offline copy of it) for a validator; and
# a seed running THIS node's enclave measurement.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1

me="recover_enclave_after_cpu_move.sh"
SEED=""
ASSUME_YES=0
while (( $# )); do
    case "$1" in
        --seed) SEED="$2"; shift 2 ;;
        --yes)  ASSUME_YES=1; shift ;;
        -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "$me: unknown argument $1" >&2; exit 2 ;;
    esac
done

fail() { echo "$me: $*" >&2; exit 1 }

[[ -n "$SEED" ]] || fail "--seed tcp://<healthy peer>:26657 is required"
[[ "$SEED" == *://* ]] || SEED="tcp://$SEED"

PIONEER=$(jq -r '.pioneer_id // empty' "$QADENAHOME/config/node_params.json" 2>/dev/null)
[[ -n "$PIONEER" ]] || fail "cannot read pioneer_id from $QADENAHOME/config/node_params.json"
ADVERTISE=$("$qadenascripts/get_external_address.sh" 2>/dev/null)
[[ -n "$ADVERTISE" ]] || fail "cannot read external_address from $QADENAHOME/config/config.toml"

escrow="$QADENAHOME/enclave_config/private_params_escrow.json"
[[ -s "$escrow" ]] || fail "no escrow at $escrow.  Without it this pioneer's enclave key cannot be recovered; it must be retired and re-joined as a new pioneer."
escrow_pioneer=$(jq -r '.PioneerID // empty' "$escrow")
[[ "$escrow_pioneer" == "$PIONEER" ]] || fail "the escrow belongs to '$escrow_pioneer', this node is '$PIONEER'"

if [[ -f "$QADENAHOME/enclave_config/priv_validator_key.json" && ! -f "$QADENAHOME/config/priv_validator_key.json" ]]; then
    fail "the validator key is sealed (enclave_config/priv_validator_key.json) and there is no plaintext config/priv_validator_key.json to re-seal from.  Restore it from your offline backup into config/ first."
fi

if pgrep -x qadenad > /dev/null || pgrep -f qadenad_enclave > /dev/null; then
    fail "qadena is running -- stop it first ($qadenascripts/stop_qadena.sh)"
fi

if ! curl -s --max-time 10 "${SEED/tcp:/http:}/status" > /dev/null; then
    fail "the seed $SEED does not answer"
fi

backup="$QADENAHOME/cpu-move-backup-$(date -u +%Y%m%dT%H%M%SZ)"
cat <<EOF
$me:
  pioneer        $PIONEER (advertises $ADVERTISE)
  seed           $SEED
  escrow         $escrow (enclave key $(jq -r '.EnclavePubK' "$escrow" | cut -c1-16)...)
  moved aside    $backup/enclave_config/enclave_params_*.json  (sealed to the old CPU)
  kept in place  enclave_data/  enclave_secrets/  (not CPU-bound; the escrow restores their key)
EOF
if (( ! ASSUME_YES )); then
    read "REPLY?Proceed? (y/n) " || exit 1
    [[ "$REPLY" == "y" ]] || exit 1
fi

mkdir -p "$backup" || fail "cannot create $backup"

# ONLY THE PARAMS FILE MOVES ASIDE.  It is the single thing a CPU move actually breaks: it is sealed
# with the SGX unique key, which is bound to BOTH this build and this CPU.
#
# enclave_data/ and enclave_secrets/ STAY.  Their row keys are stable-sealed and their row values
# are AES-GCM, both under SealedTableSharedSecret -- a software key that the escrow restores (see
# cmd/qadenad_enclave/enclave_value_seal.go).  None of it is CPU-bound any more, so the private
# tables AND this node's SS shares are readable again the moment the escrow is opened.  This used to
# move all three directories aside, which threw away perfectly good state and forced the node to
# refetch its private tables from a peer (the case-F transfer) for no reason.
#
# enclave_data/signer_state.json stays with them, so the double-sign watermark is preserved without
# the copy-back this script used to need.  The sealed validator key stays too: it cannot be opened
# on this CPU either, but signer_enclave now falls back to config/priv_validator_key.json and
# re-seals, so there is nothing to do by hand.
params_moved=0
for f in "$QADENAHOME"/enclave_config/enclave_params_*.json(N); do
    mkdir -p "$backup/enclave_config"
    mv "$f" "$backup/enclave_config/${f:t}" || fail "could not move ${f:t} aside"
    echo "$me: moved aside ${f:t} (sealed to the old CPU)"
    params_moved=1
done
(( params_moved )) || echo "$me: no sealed params file to move aside (already recovered?)"

restore_layout() {
    echo "$me: restoring the original layout from $backup" >&2
    for f in "$backup"/enclave_config/enclave_params_*.json(N); do
        mv "$f" "$QADENAHOME/enclave_config/${f:t}" 2>/dev/null
    done
}

# The enclave alone, as add_full_node.sh does for a first join.  Output to a file: a pipe would be
# held open by the enclave.
log="$QADENAHOME/logs/recover_enclave.$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "${log:h}"
"$qadenascripts/run_enclave_standalone.sh" > "$log" 2>&1 &

up=0
for i in {1..90}; do
    if [[ -S /tmp/qadena_50051.sock ]] && qadenad_alias enclave check-enclave > /dev/null 2>&1; then
        up=1; break
    fi
    sleep 1
done
if (( ! up )); then
    "$qadenascripts/stop_qadena.sh" --enclave > /dev/null 2>&1
    restore_layout
    fail "the enclave did not come up; see $log"
fi

echo "$me: sync-enclave $PIONEER $ADVERTISE $SEED"
qadenad_alias enclave sync-enclave "$PIONEER" "$ADVERTISE" "$SEED"
rc=$?
"$qadenascripts/stop_qadena.sh" --enclave > /dev/null 2>&1

params=("$QADENAHOME"/enclave_config/enclave_params_*.json(N.L+0))
if (( rc != 0 || ${#params} == 0 )); then
    restore_layout
    fail "sync-enclave did not restore this pioneer (exit $rc).  Its log says why: grep -i escrow $log"
fi

QADENA_ACCEPT_PLATFORM_CHANGE=1 "$qadenascripts/check_sgx_platform.sh"

cat <<EOF
$me: RESTORED.  Pioneer $PIONEER has its original enclave key, re-sealed for this CPU.
  Start the node:   $qadenascripts/start_qadena.sh
  At first start the enclave fetches its private tables from a peer before executing a block, and
  signer_enclave re-seals config/priv_validator_key.json.  This node holds no secret-sharing shares
  until a re-share.  The old, unreadable state is kept in $backup.
EOF
