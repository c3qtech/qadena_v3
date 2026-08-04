#!/bin/zsh
#
# Regression test for the enclave upgrade path.
#
# WHAT AN UPGRADE HAS TO PRESERVE.  The enclave holds the jar and regulator private keys in sealed
# state, in $QADENAHOME/enclave_config/enclave_params_<uniqueID>.json.  Those keys are the only way
# a suspicious transaction report can ever be read: they exist nowhere else, and no one -- including
# the regulator -- can recover them if a node throws them away.  So an enclave upgrade that starts
# with fresh keys does not merely lose state, it makes every report ever filed on that chain
# permanently undecryptable, silently, with the chain still producing blocks and looking healthy.
#
# THIS TEST EXISTS BECAUSE THAT SILENTLY HAPPENED.  check_upgrade_enclave.sh guarded itself with
#
#     [[ ! -f "$QADENAHOME/enclave_config/enclave_params_*.json" ]] && exit 0
#
# and zsh does not expand globs inside [[ ]], so -f tested a literal filename containing an asterisk
# and was always false.  The script exited 0 on every run, reported "no upgrade", and never compared
# a version.  run.sh saw the clean exit and started the new enclave with no migration at all.  Two
# further bugs sat behind that one, unreachable: a duplicated `fi` that made the script a parse
# error, and a relative ./upgrade_enclave.sh that could not resolve from run.sh's working directory.
# Nothing failed loudly at any point.
#
# WHAT IT DOES.  Registers the next enclave identity by governance, rebuilds the enclave under that
# identity, restarts, and then asserts the sealed keys came across and old reports still decrypt.
#
# WHY IT RESTARTS THE CHAIN.  There is no hot upgrade path and this test does not invent one.
# run.sh runs the upgrade check BEFORE launching anything, and upgrade_enclave.sh boots the OLD
# enclave in --upgrade-mode so the new one can dial it on 50051 and pull the keys across -- which it
# cannot do while the old enclave is running normally and already holds that port.
#
# NOT IDEMPOTENT against the same chain, which is why regression.sh runs it LAST and behind a flag:
# it registers a new identity on chain permanently and swaps the running enclave.  It does restore
# the repo's version files on exit, so a run leaves no diff behind; the installed binaries and the
# chain are left upgraded, and the next --from-genesis run rebuilds both from scratch.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

enclave_src="$qadenabuild/cmd/qadenad_enclave"
version_file="$enclave_src/version.txt"
unique_file="$enclave_src/test_unique_id.txt"
signer_file="$enclave_src/test_signer_id.txt"

fail() {
    echo "FAILED: $1"
    exit 1
}

# The version files are tracked in git.  Bumping them is how the build picks up a new identity, but
# leaving them bumped would turn every run of this suite into an uncommitted diff -- and a later
# --from-genesis run would then build genesis around an identity this test invented.  Restored on
# every exit path, including failure.
restore_version_files() {
    [ -n "$saved_version" ] && printf '%s' "$saved_version" > "$version_file"
    [ -n "$saved_unique" ]  && printf '%s' "$saved_unique"  > "$unique_file"
    [ -n "$saved_signer" ]  && printf '%s' "$saved_signer"  > "$signer_file"
}
saved_version=""; saved_unique=""; saved_signer=""
# ZERR as well as EXIT: a hard zsh error -- assigning to a read-only special like `status`, say --
# can tear the shell down without running the EXIT trap, which leaves the version files bumped and
# the next run confused about which enclave is actually installed.  The preflight below catches that
# state rather than building on it, but not leaving it behind is better.
trap restore_version_files EXIT INT TERM ZERR

regulator_privk_of() {
    sed 's/^[^{]*//' "$1" | jq -r '.SharedEnclaveParams.RegulatorPrivK'
}
jar_privk_of() {
    sed 's/^[^{]*//' "$1" | jq -r '.SharedEnclaveParams.JarPrivK'
}
suspicious_count() {
    qadenad_alias query qadena list-suspicious-transaction --output json 2>/dev/null \
        | jq -r '.SuspiciousTransaction | length' 2>/dev/null || echo ""
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"

saved_version=$(cat "$version_file")
saved_unique=$(cat "$unique_file")
saved_signer=$(cat "$signer_file")
echo "current enclave: $saved_version / $saved_unique / $saved_signer"

old_params="$QADENAHOME/enclave_config/enclave_params_$saved_unique.json"
[ -f "$old_params" ] \
    || fail "no sealed params at $old_params -- the running enclave does not match $unique_file, so there is nothing to upgrade FROM"

[ -x "$qadenabin/qadenad_enclave.$saved_unique" ] \
    || fail "no $qadenabin/qadenad_enclave.$saved_unique -- upgrade_enclave.sh needs the old binary to hand its keys over"

# Captured BEFORE anything is touched.  These three are the whole point of the test.
old_regulator=$(regulator_privk_of "$old_params")
old_jar=$(jar_privk_of "$old_params")
reports_before=$(suspicious_count)
[ -n "$old_regulator" ] && [ "$old_regulator" != "null" ] || fail "could not read RegulatorPrivK from $old_params"
[ -n "$reports_before" ] || fail "could not count suspicious transactions"
echo "sealed keys captured; $reports_before reports on record"

# A report to decrypt afterwards.  With none on record the decryption assertion below would pass
# vacuously -- and that assertion is the one that would actually catch lost keys.
[ "$reports_before" -gt 0 ] \
    || fail "no reports on record; run test_suspicious.sh first or this suite cannot prove the keys still work"

echo "========================="
echo "1. register the next enclave identity by governance"
echo "========================="
# Registration must come FIRST.  An enclave whose identity is unknown to the chain is refused, and
# run.sh has a dedicated exit code 5 for it: "the current enclave has not been registered with the
# chain.  Did you submit a proposal?"
# THE SIGNER ID MUST NOT CHANGE.  Only the measurement does.
#
# Sealing mirrors SGX: SealWithProductKey prefixes with signerID (MRSIGNER) and SealWithUniqueKey
# with uniqueID (MRENCLAVE), and Unseal accepts either prefix.  MustSeal -- which is what nearly
# everything uses -- seals with the PRODUCT key, precisely so a new enclave measurement built by the
# same signer can still read it.  That is the whole mechanism an upgrade relies on.
#
# Bump the signer too and neither prefix matches any more: the new enclave unseals nothing the old
# one wrote, every scan dies with "Couldn't unseal, unrecognized prefix" -> ErrGenericScan (1125),
# and the chain keeps producing blocks while every transfer and bank send fails.  Reports still
# decrypt, because those are encrypted to the regulator's PUBLIC key rather than sealed, so the
# damage does not show up where you would first look.
#
# Note that build.sh --update-test-unique-id bumps BOTH ids.  That is fine for a fresh chain and
# wrong for an upgrade; this suite deliberately does not use it.
next_unique=$(increment_id "$unique_file")
next_signer="$saved_signer"
next_version=$(increment_version "$version_file")
echo "next enclave: $next_version / $next_unique / $next_signer (signer deliberately unchanged)"

"$qadenatestscripts/test_update_enclave_identity.sh" "$next_unique" "$next_signer" unvalidated > /dev/null 2>&1 \
    || fail "could not submit the enclave identity proposal for $next_unique"

registered=false
for _ in {1..40}; do
    if qadenad_alias query qadena show-enclave-identity "$next_unique" > /dev/null 2>&1; then
        registered=true
        break
    fi
    sleep 3
done
[ "$registered" = "true" ] \
    || fail "$next_unique was never registered on chain; the proposal did not pass"
echo "$next_unique registered: $(qadenad_alias query qadena show-enclave-identity "$next_unique" --output json 2>/dev/null | jq -r '.enclaveIdentity.status')"

echo "========================="
echo "1b. wait for the new identity to go ACTIVE"
echo "========================="
# THE UPGRADE WILL NOT RUN UNTIL THIS HAPPENS.  A proposal registers an identity as `unvalidated`,
# and the OLD enclave refuses to hand its keys to an identity it cannot see as ACTIVE:
#
#     couldn't find an active enclave identity for uniqueID: <new>
#
# It is getEnclaveIdentity(uniqueID, signerID, false) -- the false means active-only.
#
# Promotion happens in validateEnclaveIdentities(), which has exactly one caller: a counter in
# UpdateHeight, and only on the proposer.  The counter starts at 1 when the enclave PROCESS starts,
# so the first UpdateHeight after a restart promotes -- and UpdateHeight only runs every 11 blocks.
# After that it resets to keyUpdateFrequency (555), i.e. ~6100 blocks before the next window, which
# is far longer than any test run.
#
# So the restart here is not a workaround, it is the only thing that makes promotion reachable in
# bounded time.  It is safe: the enclave binary is still the OLD one at this point, so
# check_upgrade_enclave.sh sees no version skew and does nothing.
"$qadenascripts/stop_qadena.sh" > /dev/null 2>&1 || true
sleep 3
"$qadenascripts/start_qadena.sh" > /dev/null 2>&1 \
    || fail "could not restart the chain to trigger identity validation"

active=false
for _ in {1..60}; do
    id_status=$(qadenad_alias query qadena show-enclave-identity "$next_unique" --output json 2>/dev/null \
        | jq -r '.enclaveIdentity.status' 2>/dev/null)
    [ "$id_status" = "active" ] && { active=true; break; }
    sleep 3
done
[ "$active" = "true" ] \
    || fail "$next_unique is still '$id_status' after 180s; the old enclave will refuse to hand over its keys to a non-active identity"
echo "$next_unique is active; the old enclave will now hand over its keys"

echo "========================="
echo "2. build the new enclave and restart"
echo "========================="
# Stopped before installing, not out of caution but because both halves need it: replacing the
# binary under the live process wedges the node, and upgrade_enclave.sh has to bind 50051 for the
# old enclave in --upgrade-mode.
"$qadenascripts/stop_qadena.sh" > /dev/null 2>&1 || true
sleep 3

"$qadenabuildscripts/build_enclave.sh" > /dev/null 2>&1 \
    || fail "could not build the enclave at $next_unique"

[ -x "$qadenabin/qadenad_enclave.$next_unique" ] \
    || fail "build succeeded but $qadenabin/qadenad_enclave.$next_unique was not installed"

main_version=$("$qadenabin/qadenad_enclave" -version 2>&1 | head -1)
old_version=$("$qadenabin/qadenad_enclave.$saved_unique" -version 2>&1 | head -1)
[ "$main_version" != "$old_version" ] \
    || fail "the main enclave still reports $main_version; check_upgrade_enclave.sh compares versions and would see no upgrade to do"
echo "main enclave $main_version, previous $old_version"

"$qadenascripts/start_qadena.sh" > /dev/null 2>&1 || fail "could not start the chain"

echo "========================="
echo "3. the upgrade ran"
echo "========================="
new_params="$QADENAHOME/enclave_config/enclave_params_$next_unique.json"
upgraded=false
for _ in {1..45}; do
    if [ -f "$new_params" ] && qadenad_alias status > /dev/null 2>&1; then
        upgraded=true
        break
    fi
    sleep 2
done
[ "$upgraded" = "true" ] \
    || fail "no sealed params at $new_params after restart -- the upgrade did not run (this is what the broken glob guard caused)"
echo "sealed params written for $next_unique"

echo "========================="
echo "4. the sealed keys came ACROSS, not fresh"
echo "========================="
# The heart of it.  A fresh enclave produces perfectly valid keys and a chain that looks healthy --
# the failure is invisible until someone tries to read a report, which may be months later.
new_regulator=$(regulator_privk_of "$new_params")
new_jar=$(jar_privk_of "$new_params")

[ "$new_regulator" = "$old_regulator" ] \
    || fail "the regulator key CHANGED across the upgrade; every report filed before it is now permanently undecryptable"
echo "regulator key preserved"

[ "$new_jar" = "$old_jar" ] \
    || fail "the jar key CHANGED across the upgrade"
echo "jar key preserved"

echo "========================="
echo "5. reports filed before the upgrade are still readable"
echo "========================="
# Comparing the key files proves the bytes match; this proves they still WORK, through the same
# path a regulator would use.
reports_after=$(suspicious_count)
[ "$reports_after" = "$reports_before" ] \
    || fail "report count changed across the upgrade ($reports_before -> $reports_after)"

decrypted=$(qadenad_alias query qadena list-suspicious-transaction "$new_regulator" 2>&1)
echo "$decrypted" | grep -q "Suspicious Transaction" \
    || { echo "$decrypted" | head -5; fail "the migrated regulator key could not decrypt any report"; }
echo "$decrypted" | grep -qiE "couldn't decrypt|invalid length|generic error" \
    && { echo "$decrypted" | head -5; fail "a report failed to decrypt with the migrated key"; }
echo "$reports_after reports still decrypt with the migrated key"

echo "========================="
echo "5b. the enclave can still UNSEAL what the old one wrote"
echo "========================="
# Decryptable reports are NOT enough on their own, and this is the trap the first run of this test
# fell into.  Reports are encrypted to the regulator's public key, so they survive even a completely
# fresh enclave -- while every wallet, credential and scan-window record, which are SEALED, do not.
# The chain then produces blocks normally and only fails when someone moves money.
#
# A transfer exercises the sealed store end to end, so it is the assertion that actually proves the
# upgrade preserved anything.
scan_probe=$(qadenad_alias tx bank send treasury "$(qadenad_alias keys show ann -a --keyring-backend test)" \
    1qdn --from treasury --yes --output json \
    --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment 2>/dev/null) \
    || fail "could not broadcast a probe send after the upgrade"
probe_hash=$(echo "$scan_probe" | jq -r '.txhash')
qadenad_alias query wait-tx "$probe_hash" --timeout 60s > /dev/null 2>&1 || true
probe_code=$(qadenad_alias query tx "$probe_hash" --output json 2>/dev/null | jq -r '.code // "UNKNOWN"')
[ "$probe_code" = "0" ] \
    || fail "a scanned send failed with code $probe_code after the upgrade; the enclave cannot unseal what the old one wrote (check the log for 'unrecognized prefix')"
echo "a scanned send still works, so the sealed store survived"

echo "========================="
echo "6. the upgraded enclave is live on chain"
echo "========================="
# Liveness AFTER the swap, not promotion -- 1b already made the identity active, which is what let
# the upgrade run at all.  What this adds is that the identity did not get demoted or dropped when
# the new enclave took over, and that the node is still building blocks with it.
id_status=$(qadenad_alias query qadena show-enclave-identity "$next_unique" --output json 2>/dev/null \
    | jq -r '.enclaveIdentity.status')
[ "$id_status" = "active" ] \
    || fail "$next_unique is '$id_status' after the upgrade; the chain no longer accepts the running enclave"
echo "$next_unique still active after the swap"

height=$(qadenad_alias status 2>/dev/null | jq -r '.sync_info.latest_block_height')
[ "${height:-0}" -gt 0 ] 2>/dev/null || fail "the chain is not producing blocks after the upgrade"
echo "chain producing blocks, height $height"

echo "========================="
echo "ENCLAVE UPGRADE TESTS PASSED"
echo "========================="
