#!/bin/zsh
# The at-height hook: cosmovisor runs this AFTER the old qadenad halts with UPGRADE "<name>"
# NEEDED and BEFORE it flips the `current` symlink.  argv is `<plan-name> <height>` (verified
# against the pinned cosmovisor source, process.go doCustomPreUpgrade).  A non-zero exit ABORTS
# the swap: cosmovisor stops, the node stays down on the OLD binaries with history intact, and the
# operator gets a named cause -- which is the correct failure mode, so nothing here retries.
#
# WHY THE HOOK EXISTS AT ALL, in two parts:
#
#   TEARDOWN.  The upgrade-height halt is a panic; it signals nobody.  Both enclaves are spawned
#   into their own process groups with no Pdeathsig, so they survive as orphans -- still serving
#   /tmp/qadena_50051.sock and :26661.  Left alone, the NEW qadenad would find a live socket and
#   adopt the OLD build's enclave (the in-process adoption guard panics on exactly that; this hook
#   is what makes the guard unreachable in the normal flow).
#
#   HANDOFF.  Across an enclave-measurement change, the one piece of enclave state that does not
#   survive is enclave_config/enclave_params_<uniqueID>.json -- keyed by measurement.  The
#   existing attested upgrade flow ferries it: old enclave in --upgrade-mode, new enclave with
#   --upgrade-from-enclave-unique-id, secrets released only if the new measurement is ACTIVE on
#   chain (which --via-governance guarantees happened before H).  Chain-only upgrades skip this --
#   same measurement, nothing to ferry.
#
# PLACEMENT: cosmovisor requires the hook AT $DAEMON_HOME/cosmovisor/<name>.  cosmovisor_setup.sh
# installs a shim there that execs THIS file, so scripts/ stays the single source of truth and
# install_release.sh --scripts keeps it updated like everything else.
#
# ORDER-OF-SYMLINK FACT this file depends on: at hook time `current` STILL POINTS AT THE OLD
# DIRECTORY.  That is why the old enclave binary is current/bin's and the new one is
# upgrades/<plan>/bin's, and why upgrade_enclave.sh is called with explicit --old-bin/--new-bin
# rather than its default name resolution (which reads the live names -- the OLD build, both).

PLAN_NAME="${1:-}"
PLAN_HEIGHT="${2:-}"

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/setup_env.sh"

say() { echo "cosmovisor_preupgrade.sh: $*" }
die() { echo "cosmovisor_preupgrade.sh: FAIL: $*" >&2; exit 1 }

[[ -n "$PLAN_NAME" ]] || die "no plan name in argv -- cosmovisor should pass <name> <height>"
say "upgrade '$PLAN_NAME' at height ${PLAN_HEIGHT:-?}: preparing the enclave side"

CUR_BIN="$QADENAHOME/cosmovisor/current/bin"
NEW_BIN_DIR="$QADENAHOME/cosmovisor/upgrades/$PLAN_NAME/bin"
[[ -x "$NEW_BIN_DIR/qadenad" ]] || die "no staged qadenad at $NEW_BIN_DIR -- was install_release.sh --stage-upgrade $PLAN_NAME run on this node?"
[[ -x "$NEW_BIN_DIR/qadenad_enclave" ]] || die "no staged qadenad_enclave at $NEW_BIN_DIR -- the upgrade dir must carry ALL binaries (the supervisor spawns siblings)"
[[ -x "$NEW_BIN_DIR/signer_enclave" ]] || die "no staged signer_enclave at $NEW_BIN_DIR"

# ---------------------------------------------------------------------------------------------
say "tearing down the orphaned enclaves"
"$qadenascripts/stop_qadena.sh" --enclaves-only || die "enclave teardown failed -- refusing to swap over live orphans"

# The socket must actually be gone before any handoff starts an enclave of its own.
for i in {30..1}; do
    [[ -S /tmp/qadena_50051.sock ]] || break
    sleep 1
done
[[ -S /tmp/qadena_50051.sock ]] && die "/tmp/qadena_50051.sock still present after teardown"

# ---------------------------------------------------------------------------------------------
# Measurement comparison decides whether a handoff is needed.  Debug enclaves answer -unique-id;
# signed ones are measured with ego.  Same probe install_release.sh's debug_id_of uses.
id_of() {
    local bin="$1" id=""
    if use_real_enclave "$bin"; then
        id=$(ego uniqueid "$bin" 2>/dev/null | head -1)
    else
        id=$("$bin" -unique-id 2>/dev/null | head -1)
        [[ -n "$id" ]] || id=$("$bin" -query-unique-id 2>/dev/null | head -1)
    fi
    print -r -- "$id"
}

OLD_ID=$(id_of "$CUR_BIN/qadenad_enclave")
NEW_ID=$(id_of "$NEW_BIN_DIR/qadenad_enclave")
[[ -n "$OLD_ID" ]] || die "cannot read the old enclave's measurement from $CUR_BIN/qadenad_enclave"
[[ -n "$NEW_ID" ]] || die "cannot read the new enclave's measurement from $NEW_BIN_DIR/qadenad_enclave"

if [[ "$OLD_ID" == "$NEW_ID" ]]; then
    say "chain-only upgrade (enclave measurement $OLD_ID unchanged) -- no handoff needed"
    say "done; cosmovisor will now flip current -> upgrades/$PLAN_NAME"
    exit 0
fi

# ---------------------------------------------------------------------------------------------
say "enclave measurement changes $OLD_ID -> $NEW_ID: running the attested params handoff"
if ! "$qadenascripts/upgrade_enclave.sh" --from-enclave-unique-id "$OLD_ID" \
        --old-bin "$CUR_BIN/qadenad_enclave" --new-bin "$NEW_BIN_DIR/qadenad_enclave"; then
    die "the params handoff failed.  The node stays DOWN on the old binaries; nothing was swapped. \
Fix the cause (is the new measurement ACTIVE on chain?) and restart -- run.sh's \
check_upgrade_enclave preflight retries the handoff."
fi

# The handoff runs enclaves of its own; leave nothing behind for the new node to mis-adopt.
"$qadenascripts/stop_qadena.sh" --enclaves-only >/dev/null 2>&1
rm -f /tmp/qadena_*.sock 2>/dev/null

say "handoff complete (enclave_params_${NEW_ID}.json ferried)"
say "done; cosmovisor will now flip current -> upgrades/$PLAN_NAME"
exit 0
