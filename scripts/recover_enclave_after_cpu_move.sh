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
#   1. moves enclave_config/, enclave_data/ and enclave_secrets/ into a dated backup directory --
#      nothing is deleted -- keeping the two things in them that are not CPU-bound: the private-
#      params ESCROW and the signer's double-sign state (enclave_data/signer_state.json);
#   2. starts the enclave alone and runs sync-enclave against --seed.  The seed hands over the shared
#      params and the SS owner map over an attested channel.  The escrow is encrypted to an SS
#      interval key, so the enclave gathers that key's shares from its OTHER owners (attested
#      queries, no transaction), opens the escrow, checks the escrowed enclave key against the one
#      the CHAIN records for this pioneer, and re-seals it all for this CPU.  Nothing is broadcast,
#      so this works while the chain is halted -- which it is, if this node holds most of the stake;
#   3. re-records this platform for check_sgx_platform.sh.
# On the next start, the validator key is re-sealed from config/priv_validator_key.json by
# signer_enclave, the chain re-delivers this node's SS shares (each PublicKey row carries them
# encrypted to the enclave key just restored), and the enclave, holding no private state on a chain
# with history, fetches it from a peer (the case-F transfer) before executing a block.
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
  moved aside to $backup:
                 enclave_config/  enclave_data/  enclave_secrets/
EOF
if (( ! ASSUME_YES )); then
    read "REPLY?Proceed? (y/n) " || exit 1
    [[ "$REPLY" == "y" ]] || exit 1
fi

mkdir -p "$backup" || fail "cannot create $backup"
for d in enclave_config enclave_data enclave_secrets; do
    [[ -e "$QADENAHOME/$d" ]] && { mv "$QADENAHOME/$d" "$backup/$d" || fail "could not move $d aside"; }
done
mkdir -p "$QADENAHOME/enclave_config"
cp -p "$backup/enclave_config/private_params_escrow.json" "$escrow" || fail "could not put the escrow back"

# THE VALIDATOR'S DOUBLE-SIGN STATE COMES ACROSS TOO.  signer_state.json records the last height,
# round and step the signer signed, and the signer refuses anything at or behind it.  It is plain
# JSON, not sealed, so the move did not touch it -- dropping it with the rest of enclave_data/ would
# restart double-sign protection from nothing on the very node most likely to have signed
# something just before it went down.
if [[ -f "$backup/enclave_data/signer_state.json" ]]; then
    mkdir -p "$QADENAHOME/enclave_data"
    cp -p "$backup/enclave_data/signer_state.json" "$QADENAHOME/enclave_data/signer_state.json" \
        || fail "could not carry the signer's double-sign state across"
    echo "$me: carried the signer's double-sign state across ($(jq -r '.height' "$QADENAHOME/enclave_data/signer_state.json" 2>/dev/null) last signed)"
else
    echo "$me: WARNING: no enclave_data/signer_state.json to carry across -- the signer starts double-sign protection from nothing" >&2
fi

restore_layout() {
    echo "$me: restoring the original layout from $backup" >&2
    rm -rf "$QADENAHOME/enclave_config" "$QADENAHOME/enclave_data" "$QADENAHOME/enclave_secrets"
    for d in enclave_config enclave_data enclave_secrets; do
        [[ -e "$backup/$d" ]] && mv "$backup/$d" "$QADENAHOME/$d"
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
