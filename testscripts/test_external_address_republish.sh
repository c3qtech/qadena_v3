#!/bin/zsh
#
# End-to-end test for RE-PUBLISHING A PIONEER'S EXTERNAL ADDRESS after the node moves.
#
# WHAT WAS BROKEN.  A pioneer's externalIPAddress reached the chain exactly once: updateIsValidator
# was the only writer and it sits behind a latch that fires on the first proposed block and never
# re-arms.  The value came from sealed enclave params, restored from the seal on every start.  So
# after an IP change the chain advertised the old address forever -- restart, re-bond, rotation and
# audit all left it alone.  This was only ever established by reading the code; nothing exercised
# it, which is what TESTING-BACKLOG item 109 asks for first.
#
# WHY IT MATTERS.  getAddressablePioneers tests the field for EMPTINESS, not reachability, so a
# moved node keeps counting toward the re-share audit's owner target while being undialable.  The
# chain then overstates custody: it lists an owner whose shares nobody can fetch.
#
# HOW THE FIX WORKS, and therefore what this drives.  cmd/qadenad/cmd/enclave_selfstart.go already
# read config.toml's p2p.external_address on every start -- it refuses to start without one -- but
# only handed it to the InitEnclave dispatch, whose gate shuts permanently once the JarRegulator row
# exists.  So an established node re-read the new address at every restart and discarded it.  It now
# rides on MsgUpdateHeight (every 11 blocks) to the enclave, which seals it and republishes the row.
# The operator's action is therefore the one they must take anyway: edit config.toml, restart.
#
# THIS TEST RESTARTS THE NODE.  It stops the chain, edits config.toml, starts it again, and restores
# the original address at the end -- including on failure, via a trap.  Do not run it against
# anything you are not willing to have bounced twice.
#
# WHAT IT DOES NOT COVER.  The cross-node rejection (node A publishing node B's row) is the security
# half of this change and CANNOT be driven from one node: forging it needs a second attested enclave
# willing to lie.  It is covered by TestPioneerRowCrossNodeUpdateIsRejected in
# x/qadena/keeper/msg_server_pioneer_update_interval_public_key_i_d_test.go, which builds a report
# that genuinely verifies and is still refused.  That is the case that must never regress.

SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

fail() { echo ""; echo "FAILED: $*"; exit 1 }
info() { echo "  $*" }

CONFIG="$QADENAHOME/config/config.toml"

# How long to wait for the row to move.  The address rides on UpdateHeight, which the keeper sends
# every 11 blocks, and the enclave republishes as soon as it sees a change -- so this is ~11 blocks
# plus one transaction, not a rotation interval.  Generous by a wide margin.
DEADLINE_SECONDS=180

# The address published for this pioneer, straight off the chain row.
row_address() {   # pioneerID
    qadenad_alias q qadena show-interval-public-key-id "$1" pioneer -o json 2>/dev/null \
        | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("IntervalPublicKeyID") or d.get("intervalPublicKeyID") or {}).get("externalIPAddress",""))' 2>/dev/null
}

config_address() { "$qadenascripts/get_external_address.sh" }

echo "========================="
echo "preflight"
echo "========================="

qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"

[[ -f "$CONFIG" ]] || fail "no config.toml at $CONFIG"

# The moniker names this node's pioneer, exactly as enclave_selfstart.go uses it to find the key.
MONIKER=$(grep -E '^moniker' "$CONFIG" | head -1 | sed -e 's/.*= *"//' -e 's/"$//')
[[ -n "$MONIKER" ]] || fail "could not read the moniker from $CONFIG"
info "pioneer (moniker): $MONIKER"

ORIG_CONFIG_ADDR=$(config_address) || fail "config.toml has no p2p.external_address"
info "config.toml address: $ORIG_CONFIG_ADDR"

ORIG_ROW_ADDR=$(row_address "$MONIKER")
[[ -n "$ORIG_ROW_ADDR" ]] || fail "this node has no pioneer interval-public-key row yet -- it has never proposed a block, so there is nothing to re-publish"
info "chain row address:   $ORIG_ROW_ADDR"

# WHERE TO MOVE THE NODE TO.
#
# PREFER A SECOND REAL ADDRESS ON THIS MACHINE, on the same /24 as the current one.  A Mac with both
# wifi and ethernet up typically has one (here: en15 192.168.86.92 and en0 192.168.86.128).  That
# makes this a REAL move rather than a simulated one: the node is genuinely reachable at the new
# address, so a peer -- and this node's own reachability probe -- can confirm the republished row
# actually works.  A dead address would leave that half untested, and "the row changed" is a weaker
# claim than "the row changed and the node is reachable there".
#
# FALLBACK: 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for documentation and guaranteed never
# to be a real host -- so if the restore below fails and this value is left behind, peers fail to
# dial a documented dead end rather than reaching a stranger.  It still proves the row moves; it
# just cannot prove reachability.
pick_second_local_address() {   # current-bare-ip
    local cur="$1" prefix
    prefix="${cur%.*}."
    # Bound to this machine, IPv4, not loopback, same /24, not the one in use.  Tunnels and VM
    # bridges (utun*, bridge*) are excluded: they are reachable only from a VPN or a guest VM, so
    # advertising one would be a worse address than the one we started with.
    ifconfig 2>/dev/null | awk -v pfx="$prefix" -v cur="$cur" '
        /^[a-z0-9]+:/ { ifc=$1 }
        /inet / {
            if (ifc ~ /^(utun|bridge|lo)/) next
            if ($2 == cur) next
            if (index($2, pfx) == 1) { print $2; exit }
        }'
}

NEW_ADDR=$(pick_second_local_address "$ORIG_CONFIG_ADDR")
if [[ -n "$NEW_ADDR" ]]; then
    REAL_MOVE=1
    info "moving to $NEW_ADDR -- a second address that is really bound to this machine"
else
    REAL_MOVE=0
    NEW_ADDR="192.0.2.77"
    info "no second local address found; using the documentation address $NEW_ADDR"
    info "  (the row is still checked; reachability at the new address is not)"
fi
[[ "$ORIG_CONFIG_ADDR" != "$NEW_ADDR" ]] || fail "config.toml is already set to the test address; refusing to run"

# RESTORE ON EVERY EXIT PATH.  Leaving a node advertising a documentation address is a broken node,
# so the restore must not depend on the test passing.
restore() {
    local rc=$?
    echo ""
    echo "restoring $CONFIG to $ORIG_CONFIG_ADDR"
    set_config_address "$ORIG_CONFIG_ADDR"
    "$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1 || true
    # Bring it back on the ORIGINAL address, so the machine ends how it was found.  Detached and
    # redirected, never piped: start_qadena.sh dies on a closing pipe and takes the chain with it.
    echo "  restarting on $ORIG_CONFIG_ADDR"
    "$qadenascripts/start_qadena.sh" > /dev/null 2>&1 &
    sleep 25
    if "$qadenabin/qadenad" --home "$QADENAHOME" status > /dev/null 2>&1; then
        echo "  node is back up."
    else
        echo "  WARNING: the node did not come back within 25s -- check it by hand."
    fi
    exit $rc
}

set_config_address() {   # bare-ip
    # Rewrite only the p2p external_address line, keeping whatever port was there.
    local port
    port=$(grep -E '^external_address' "$CONFIG" | head -1 | sed -e 's/.*= *"//' -e 's/"$//' | awk -F: '{print $2}')
    [[ -n "$port" ]] || port=26656
    python3 - "$CONFIG" "$1:$port" <<'PY'
import re, sys
path, value = sys.argv[1], sys.argv[2]
src = open(path).read()
# Anchored to the line, so the commented example above it is left alone.
out, n = re.subn(r'(?m)^external_address\s*=\s*".*"', 'external_address = "%s"' % value, src)
if n != 1:
    sys.exit("expected exactly one external_address line, found %d" % n)
open(path, "w").write(out)
PY
}

echo ""
echo "========================="
echo "1. move the node"
echo "========================="

trap restore EXIT INT TERM

info "stopping the node"
"$qadenascripts/stop_qadena.sh" --all > /dev/null 2>&1 || true

info "setting p2p.external_address to $NEW_ADDR"
set_config_address "$NEW_ADDR"
[[ "$(config_address)" == "$NEW_ADDR" ]] || fail "config.toml did not take the new address"

info "starting the node"
# Detached and NOT piped: start_qadena.sh is killed by a closing pipe, which takes the chain with it.
"$qadenascripts/start_qadena.sh" > /dev/null 2>&1 &
sleep 20

echo ""
echo "========================="
echo "2. wait for the row to follow"
echo "========================="
info "waiting up to ${DEADLINE_SECONDS}s for the chain row to become $NEW_ADDR"

moved=0
for i in $(seq 1 $((DEADLINE_SECONDS / 5))); do
    current=$(row_address "$MONIKER" 2>/dev/null || true)
    if [[ "$current" == "$NEW_ADDR" ]]; then
        moved=1
        info "row moved after ~$((i * 5))s"
        break
    fi
    sleep 5
done

[[ $moved -eq 1 ]] || fail "the chain row still says '$(row_address "$MONIKER")' after ${DEADLINE_SECONDS}s.
  On the CURRENT (unfixed) build this is the expected result and reproduces backlog item 109.
  On the fixed build, check the node log for lines tagged 'ext-addr:' -- an address that was seen
  but not published names its own reason there."

echo ""
echo "========================="
echo "3. the rest of the row survived"
echo "========================="

# An address-only update must not disturb anything else on the row.  ServiceProviderType and
# HomePioneerID are carried forward by the handler; PubKID is what every other enclave looks this
# node up by, so a change there would repoint key bindings rather than traffic.
after=$(qadenad_alias q qadena show-interval-public-key-id "$MONIKER" pioneer -o json)
echo "$after" | python3 -c '
import sys, json
d = json.load(sys.stdin)
row = d.get("IntervalPublicKeyID") or d.get("intervalPublicKeyID") or {}
print("  pubKID:              " + (row.get("pubKID") or "(none)"))
print("  externalIPAddress:   " + (row.get("externalIPAddress") or "(none)"))
print("  serviceProviderType: " + (row.get("serviceProviderType") or "(none)"))
print("  homePioneerID:       " + (row.get("homePioneerID") or "(none)"))
'

if [[ $REAL_MOVE -eq 1 ]]; then
    echo ""
    echo "========================="
    echo "4. the node answers at the new address"
    echo "========================="
    # The point of moving to a REAL second address: a row that changed but points somewhere
    # undialable would still pass step 2.  This is what makes the republished row worth having --
    # it is the same RPC port the enclave's own liveness probe dials (tcp://<ip>:26657).
    if "$qadenabin/qadenad" --home "$QADENAHOME" status --node "tcp://$NEW_ADDR:26657" > /dev/null 2>&1; then
        info "the node answers on tcp://$NEW_ADDR:26657 -- the published address is dialable"
    else
        fail "the row says $NEW_ADDR but nothing answers there.  A row that moved to an address
  nobody can reach is the failure this change exists to prevent, not a fix for it."
    fi
fi

echo ""
echo "========================="
echo "PASSED"
echo "========================="
echo "The node moved to $NEW_ADDR and the chain row followed without a second operator action."
echo "config.toml is restored to $ORIG_CONFIG_ADDR on the way out."
