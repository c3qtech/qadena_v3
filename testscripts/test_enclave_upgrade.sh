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
#
# ----------------------------------------------------------------------------------------------
# SGX MODE
#
# On real SGX the identity is not a number in a text file -- it is the MEASUREMENT OF THE BINARY, so
# almost every step above has to work differently and the difference is not cosmetic.
#
# 1. THE NEW IDENTITY CANNOT BE CHOSEN, ONLY DISCOVERED.  In debug mode the next uniqueID is whatever
#    we write into test_unique_id.txt, so it can be registered before the enclave that has it exists.
#    MRENCLAVE is a hash of the built binary, so on SGX it cannot be known until after the build.
#    The order therefore inverts: BUILD FIRST, then register what came out.
#
# 2. THE SOURCE CHANGE MUST BE COMMITTED.  build_enclave.sh --build-sgx runs `git checkout -f && git
#    clean -fd` before building, because a reproducible build is only meaningful against a known tree
#    state.  An uncommitted version.txt bump is therefore DISCARDED before the compiler sees it, and
#    the build reproduces the identical measurement -- leaving nothing to upgrade to, while looking
#    like it worked.  So this suite makes a temporary local commit and resets to the original HEAD on
#    exit.  The preflight refuses to start on a dirty tree, since `git clean -fd` would otherwise
#    destroy uncommitted work (including any untracked test scripts).
#
# 3. WHAT MAKES THE MEASUREMENT CHANGE.  cmd/qadenad_enclave/version.txt is //go:embed-ed into the
#    binary (enclave.go:195), so bumping it changes the bytes and therefore MRENCLAVE.  That is why
#    the same version bump that drives check_upgrade_enclave.sh's comparison also produces the new
#    identity -- one change, both effects.  The suite asserts the measurement actually moved rather
#    than assuming it.
#
# 4. THE BUILD INSTALLS, SO THE UPGRADE HAS TO BE HELD BACK.  build_enclave.sh installs its output as
#    the main enclave immediately, and check_upgrade_enclave.sh triggers on the MAIN binary's version
#    being higher.  Registration and promotion each need a restart, and a restart with the new binary
#    already in place would attempt the upgrade against an identity that is not yet active -- which
#    fails with "couldn't find an active enclave identity".  So after the build the previous binary
#    is put back as main, and the new one is only swapped in once its identity is active.
#
# 5. THE SIGNER IS FIXED BY THE KEY, NOT BY A FILE.  Both builds sign with the same public.pem, so
#    MRSIGNER is unchanged for free -- and since real sealing uses the SGX product key, the migration
#    this suite tests is enforced by hardware here rather than by the debug prefix convention.
#
# Everything from "register the next enclave identity" onwards is then common to both modes.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# COSMOVISOR: this script IS the unmanaged upgrade mechanism -- it swaps live binaries outside any
# governance plan, which is precisely what a managed fleet must never do (and its writes would go
# through the bin/ symlinks into the current generation directory).  On managed fleets every
# binary change is a plan: rolling_upgrade.sh --via-governance.
if [ -L "${QADENAHOME:-$HOME/qadena}/cosmovisor/current" ]; then
    echo "$(basename "$0"): refusing on a cosmovisor-managed node -- use rolling_upgrade.sh --via-governance" >&2
    exit 1
fi

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

# All git access goes through this, because on SGX this suite runs under sudo and plain git breaks
# there in two separate ways:
#
#   - the repo is owned by the invoking user, not root, so git refuses it with "detected dubious
#     ownership in repository" -- and `git status --porcelain` then prints NOTHING to stdout while
#     failing, which reads exactly like a clean tree.  The dirty-tree guard would wave it through and
#     --build-sgx would go on to `git clean -fd` the user's work.
#   - root has no user.name/user.email under sudo (HOME becomes /root), so the temporary commit
#     fails with "Please tell me who you are".
#
# Both are supplied per-invocation rather than written to any config, so running this suite leaves no
# git configuration behind on the machine.
git_repo() {
    git -c safe.directory="$qadenabuild" \
        -c user.name="qadena regression" \
        -c user.email="regression@localhost" \
        -C "$qadenabuild" "$@"
}

# The version files are tracked in git.  Bumping them is how the build picks up a new identity, but
# leaving them bumped would turn every run of this suite into an uncommitted diff -- and a later
# --from-genesis run would then build genesis around an identity this test invented.  Restored on
# every exit path, including failure.
restore_version_files() {
    # SGX mode makes a temporary commit so the reproducible build can see the version bump (see the
    # header).  Undoing that has to come FIRST: it restores the tracked files wholesale, and the
    # per-file writes below would otherwise be undone by it rather than the other way round.
    if [ -n "$orig_head" ]; then
        git_repo reset --hard "$orig_head" > /dev/null 2>&1 \
            && echo "restored the repo to $orig_head" \
            || echo "WARNING: could not reset the repo to $orig_head -- check 'git log' for a leftover temporary commit"
        return
    fi
    [ -n "$saved_version" ] && printf '%s' "$saved_version" > "$version_file"
    [ -n "$saved_unique" ]  && printf '%s' "$saved_unique"  > "$unique_file"
    [ -n "$saved_signer" ]  && printf '%s' "$saved_signer"  > "$signer_file"
}
saved_version=""; saved_unique=""; saved_signer=""; orig_head=""
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
    qadenad_alias query qadena list-suspicious-transaction --count-total --output json 2>/dev/null \
        | jq -r '.pagination.total' 2>/dev/null || echo ""
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"

# A LOG PATH THIS USER CAN ACTUALLY WRITE, proven before anything depends on it.
#
# This suite used to redirect the build into a fixed /tmp/enclave_upgrade_build.log, and a
# root-owned file of that name (from an earlier sudo run) made the redirect fail -- so the build
# NEVER RAN, zsh returned 1, and `tail` of that path printed an eleven-day-old successful build
# ending in "Install done."  Every artefact agreed with a story that was not happening, and the
# blame landed in turn on the build, docker's cache, version.txt and install.sh.
# See user_log_path in scripts/setup_env.sh.
build_log=$(user_log_path enclave_upgrade_build) \
    || fail "cannot create a writable build log (see above)"

# WHICH ENCLAVE IS ACTUALLY RUNNING decides where the current identity is read from, and the two
# sources disagree by design: on SGX the *.txt files are still embedded in the binary but they do not
# describe it -- the measurement does.  Reading the text files on an SGX box would name an identity
# no sealed-params file exists for, and the preflight below would blame the chain for it.
if use_real_enclave "$qadenabin/qadenad_enclave"; then
    sgx_mode=1
    echo "SGX mode: the running enclave is ego-signed, so identities come from measurements"
else
    sgx_mode=0
    echo "debug mode: identities come from cmd/qadenad_enclave/*.txt"
fi

saved_version=$(cat "$version_file")
if [ $sgx_mode -eq 1 ]; then
    # `ego uniqueid`/`ego signerid` accept a signed executable, so both come from the binary that is
    # actually installed rather than from anything that merely claims to describe it.
    saved_unique=$(ego uniqueid "$qadenabin/qadenad_enclave" 2>/dev/null) \
        || fail "could not measure $qadenabin/qadenad_enclave"
    saved_signer=$(ego signerid "$qadenabin/qadenad_enclave" 2>/dev/null) \
        || fail "could not read the signer id of $qadenabin/qadenad_enclave"
    [ -n "$saved_unique" ] || fail "ego reported an empty measurement for the installed enclave"
else
    saved_unique=$(cat "$unique_file")
    saved_signer=$(cat "$signer_file")
fi
echo "current enclave: $saved_version / $saved_unique / $saved_signer"

old_params="$QADENAHOME/enclave_config/enclave_params_$saved_unique.json"
[ -f "$old_params" ] \
    || fail "no sealed params at $old_params -- the running enclave does not match $unique_file, so there is nothing to upgrade FROM"

[ -x "$qadenabin/qadenad_enclave.$saved_unique" ] \
    || fail "no $qadenabin/qadenad_enclave.$saved_unique -- upgrade_enclave.sh needs the old binary to hand its keys over"

# Captured BEFORE anything is touched.
#
# READING THE SEALED KEYS IS A DEBUG-ONLY CAPABILITY, and that asymmetry is the security property
# rather than a limitation of the test.  The debug enclave "seals" by prefixing an id onto plaintext
# JSON, so the regulator and jar private keys sit in a file any process on the box can read.  A real
# SGX enclave seals with the hardware key, so the same file is ciphertext that NOBODY outside the
# enclave can read -- including root, and including this test.
#
# So on SGX the before/after key comparison is impossible, and the suite leans on the assertion that
# was always the stronger one anyway: a scanned send after the upgrade (5b).  Comparing the key files
# proves the bytes match; the send proves the new enclave can actually USE what the old one sealed,
# which is what an upgrade has to preserve.  Section 5b runs identically in both modes.
reports_before=$(suspicious_count)
[ -n "$reports_before" ] || fail "could not count suspicious transactions"

can_read_sealed_keys=0
old_regulator=""; old_jar=""
if [ $sgx_mode -eq 0 ]; then
    old_regulator=$(regulator_privk_of "$old_params")
    old_jar=$(jar_privk_of "$old_params")
    [ -n "$old_regulator" ] && [ "$old_regulator" != "null" ] \
        || fail "could not read RegulatorPrivK from $old_params"
    can_read_sealed_keys=1
    echo "sealed keys captured; $reports_before reports on record"

    # A report to decrypt afterwards.  With none on record the decryption assertion below would pass
    # vacuously -- and that assertion is the one that would actually catch lost keys.
    [ "$reports_before" -gt 0 ] \
        || fail "no reports on record; run test_suspicious.sh first or this suite cannot prove the keys still work"
else
    # Assert it really IS opaque rather than assuming so.  If a real enclave ever wrote its params in
    # the clear, every private key on the node would be readable and this is the one place positioned
    # to notice.
    if sed 's/^[^{]*//' "$old_params" 2>/dev/null | jq -e '.SharedEnclaveParams.RegulatorPrivK' > /dev/null 2>&1; then
        fail "$old_params is READABLE PLAINTEXT under a real SGX enclave; the regulator and jar private keys are exposed on disk"
    fi
    echo "REAL SGX SEALING: $old_params is ciphertext, so the keys cannot be compared across the upgrade."
    echo "NOT VERIFIED IN THIS RUN: byte-for-byte key preservation, and report decryption (both need the sealed keys)."
    echo "VERIFIED INSTEAD, and more strongly: that the new enclave can USE the old one's sealed state (5b)."
    echo "$reports_before reports on record"
fi

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
if [ $sgx_mode -eq 1 ]; then
    # SGX: BUILD FIRST.  The measurement is a hash of the binary, so there is nothing to register
    # until it exists.  See the header for why the bump must be committed and why the freshly built
    # binary is then put back in its box until its identity is active.
    # Checked for FAILURE as well as for output: a git that errors prints nothing to stdout, which
    # would otherwise be indistinguishable from a clean tree.
    tree_state=$(git_repo status --porcelain) \
        || fail "could not read git status for $qadenabuild; refusing to run --build-sgx blind, since it would 'git clean -fd' whatever is there"
    [ -z "$tree_state" ] \
        || fail "the working tree has uncommitted changes; --build-sgx runs 'git clean -fd' and would destroy them. Commit or stash first."
    orig_head=$(git_repo rev-parse HEAD) || fail "could not resolve HEAD for $qadenabuild"

    next_version=$(increment_version "$version_file")
    git_repo commit -q -am "temp: bump enclave version to $next_version for the upgrade test" \
        || fail "could not commit the version bump; --build-sgx would discard it and rebuild the same measurement"
    echo "temporary commit made on top of $orig_head (reset on exit)"

    # THE STATUS IS CAPTURED, not folded into a `||`.  The old form could not tell "the build
    # failed" from "the redirect failed and the build never ran", and reported the first for the
    # second -- see the build_log preflight above.  Naming the number costs one line and makes the
    # difference visible in the log.
    set +e
    "$qadenabuildscripts/build_enclave.sh" --build-sgx > "$build_log" 2>&1
    build_rc=$?
    set -e
    if [ $build_rc -ne 0 ]; then
        tail -20 "$build_log"
        fail "the --build-sgx enclave build exited $build_rc (log: $build_log)"
    fi

    next_unique=$(cat "$enclave_src/reproducible_build_unique_id.txt")
    next_signer=$(cat "$enclave_src/reproducible_build_signer_id.txt")
    [ -n "$next_unique" ] || fail "the build recorded no measurement"

    # If the bump did not move the measurement there is no upgrade to test, and every assertion below
    # would pass vacuously against a single unchanged enclave.  version.txt is //go:embed-ed, so this
    # failing means the embed was dropped -- exactly the kind of change that would silently turn this
    # suite into a no-op.
    [ "$next_unique" != "$saved_unique" ] \
        || fail "the version bump did not change the measurement ($next_unique); version.txt is meant to be //go:embed-ed into the enclave, so there is nothing to upgrade TO"
    [ "$next_signer" = "$saved_signer" ] \
        || fail "the signer id changed ($saved_signer -> $next_signer); the new enclave would be unable to unseal anything the old one wrote, since MustSeal uses the product (signer) key"

    # Put the OLD binary back as main.  The build installed the new one, and leaving it there would
    # make the next restart attempt the upgrade before the identity is active.  The new binary is
    # already preserved as qadenad_enclave.$next_unique, so nothing is lost by this.
    [ -x "$qadenabin/qadenad_enclave.$next_unique" ] \
        || fail "the build did not install $qadenabin/qadenad_enclave.$next_unique"
    cp "$qadenabin/qadenad_enclave.$saved_unique" "$qadenabin/qadenad_enclave" \
        || fail "could not restore the previous enclave as main"
    echo "new enclave built and held back; main is still $saved_unique"
else
    next_unique=$(increment_id "$unique_file")
    next_signer="$saved_signer"
    next_version=$(increment_version "$version_file")
fi
echo "next enclave: $next_version / $next_unique / $next_signer (signer deliberately unchanged)"

# Output kept, not discarded: when registration fails the interesting evidence is which of the
# three transactions (submit, deposit, vote) went wrong, and that only exists here.
"$qadenatestscripts/test_update_enclave_identity.sh" "$next_unique" "$next_signer" unvalidated \
    || fail "could not submit the enclave identity proposal for $next_unique"

# The wait budget must cover the REGULAR voting period, not the expedited one.  The proposal is
# submitted expedited (30s in the test config), but gov v1 CONVERTS an expedited proposal that
# misses its expedited tally into a regular proposal with the full voting period (300s here) --
# votes carry over, so it still passes, just later.  A single slow transaction inside the 30s
# window is enough to trigger the conversion, which made a 120s wait a coin-flip.
registered=false
for _ in {1..130}; do
    if qadenad_alias query qadena show-enclave-identity "$next_unique" > /dev/null 2>&1; then
        registered=true
        break
    fi
    sleep 3
done
[ "$registered" = "true" ] \
    || fail "$next_unique was never registered on chain; the proposal did not pass even a regular voting period"
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

if [ $sgx_mode -eq 1 ]; then
    # Already built above; this is the swap that was deliberately deferred until the identity went
    # active.  A copy rather than a move, so qadenad_enclave.$next_unique stays on disk -- the next
    # upgrade from this measurement would need it to hand its keys over, exactly as this one needed
    # qadenad_enclave.$saved_unique.
    cp "$qadenabin/qadenad_enclave.$next_unique" "$qadenabin/qadenad_enclave" \
        || fail "could not install $next_unique as the main enclave"
    echo "swapped $next_unique in as the main enclave"
else
    # KEEP THE BUILD OUTPUT.  This was `> /dev/null 2>&1`, so every way the build can fail arrived
    # as the same four words -- "could not build the enclave" -- with the reason discarded.  It cost
    # a diagnosis round trip for a build whose only complaint was `command not found: go`, printed
    # and thrown away: a suite launched over ssh or from nohup gets a non-login shell, and
    # /usr/local/go/bin is not on that PATH.
    build_log=$(user_log_path enclave_upgrade_build) || fail "no writable path for the build log"
    if ! "$qadenabuildscripts/build_enclave.sh" > "$build_log" 2>&1 ; then
        echo "--- last 15 lines of $build_log ---"
        tail -15 "$build_log" | sed 's/^/    /'
        fail "could not build the enclave at $next_unique (full output in $build_log)"
    fi
fi

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
new_regulator=""
if [ $can_read_sealed_keys -eq 1 ]; then
    new_regulator=$(regulator_privk_of "$new_params")
    new_jar=$(jar_privk_of "$new_params")

    [ "$new_regulator" = "$old_regulator" ] \
        || fail "the regulator key CHANGED across the upgrade; every report filed before it is now permanently undecryptable"
    echo "regulator key preserved"

    [ "$new_jar" = "$old_jar" ] \
        || fail "the jar key CHANGED across the upgrade"
    echo "jar key preserved"
else
    # Under hardware sealing the ciphertext cannot be compared either -- re-sealing the identical
    # plaintext yields different bytes, so a mismatch would prove nothing and a match is impossible.
    # What IS checkable from outside is that the new enclave sealed its params at all and did not
    # write them in the clear; whether the CONTENT carried across is settled by 5b.
    [ -s "$new_params" ] || fail "$new_params is empty; the new enclave sealed nothing"
    if sed 's/^[^{]*//' "$new_params" 2>/dev/null | jq -e '.SharedEnclaveParams.RegulatorPrivK' > /dev/null 2>&1; then
        fail "$new_params is READABLE PLAINTEXT under a real SGX enclave; the migrated keys are exposed on disk"
    fi
    echo "new params sealed and opaque; key identity is settled functionally by 5b, not by comparison"
fi

echo "========================="
echo "5. reports filed before the upgrade are still readable"
echo "========================="
# Comparing the key files proves the bytes match; this proves they still WORK, through the same
# path a regulator would use.
reports_after=$(suspicious_count)
[ "$reports_after" = "$reports_before" ] \
    || fail "report count changed across the upgrade ($reports_before -> $reports_after)"

if [ $can_read_sealed_keys -eq 1 ]; then
    # --limit "$reports_after" READS EVERY REPORT, and the count below states what was actually
    # examined rather than what is on record.  Unqualified, this took the DEFAULT PAGE -- the oldest
    # 100 -- and then printed "$reports_after reports still decrypt", claiming 2,300 verified on a
    # soak node when it had looked at 100.  The sample was not wrong (pre-upgrade reports are the
    # point) but the claim was, and a negative assertion is only as wide as the page it ran over.
    decrypted=$(qadenad_alias query qadena list-suspicious-transaction "$new_regulator" --limit "$reports_after" 2>&1)
    echo "$decrypted" | grep -q "Suspicious Transaction" \
        || { echo "$decrypted" | head -5; fail "the migrated regulator key could not decrypt any report"; }
    echo "$decrypted" | grep -qiE "couldn't decrypt|invalid length|generic error" \
        && { echo "$decrypted" | head -5; fail "a report failed to decrypt with the migrated key"; }
    decrypted_seen=$(echo "$decrypted" | grep -c "Suspicious Transaction")
    [ "$decrypted_seen" = "$reports_after" ] \
        || fail "only $decrypted_seen of $reports_after reports came back; the listing was truncated and the check below would be partial"
    echo "$decrypted_seen of $reports_after reports still decrypt with the migrated key"
else
    echo "$reports_after reports still on record (unchanged); decryption needs the sealed regulator key and cannot be checked here"
fi

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

probe_hash=$(echo "$scan_probe" | jq -r '.txhash' 2>/dev/null)
[ -n "$probe_hash" ] && [ "$probe_hash" != "null" ] \
    || fail "the probe send produced no txhash; the chain was not accepting transactions after the restart"

# READ THE IMMEDIATE RESPONSE FIRST.  A CheckTx rejection is reported right here, with a raw_log that
# names the cause -- and the transaction is then never included in a block, so it can never be found
# by the polling below.  Discarding this and polling anyway is how a run reported
#
#     the probe send <hash> never resolved, so whether the sealed store survived is UNKNOWN
#
# after five minutes, when the answer had been handed to it immediately.  A txhash is returned for a
# rejected transaction too, so its presence proves nothing about acceptance.
#
# Retried rather than failed outright: the node has just restarted, and a first attempt can lose to
# a stale sequence or an enclave still coming up.  What must not happen is treating the rejection as
# an absence of information.
probe_check=$(echo "$scan_probe" | jq -r '.code // empty' 2>/dev/null)
if [ -n "$probe_check" ] && [ "$probe_check" != "0" ]; then
    probe_log=$(echo "$scan_probe" | jq -r '.raw_log // empty' 2>/dev/null)
    echo "probe rejected at CheckTx (code $probe_check): $probe_log"
    echo "retrying -- the node has just restarted"
    for _ in {1..10}; do
        sleep 5
        scan_probe=$(qadenad_alias tx bank send treasury "$(qadenad_alias keys show ann -a --keyring-backend test)" \
            1qdn --from treasury --yes --output json \
            --gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment $gas_adjustment 2>/dev/null)
        probe_check=$(echo "$scan_probe" | jq -r '.code // empty' 2>/dev/null)
        [ "$probe_check" = "0" ] && break
    done
    [ "$probe_check" = "0" ] \
        || fail "the probe send is still refused at CheckTx (code $probe_check): $(echo "$scan_probe" | jq -r '.raw_log // empty' 2>/dev/null)"
    probe_hash=$(echo "$scan_probe" | jq -r '.txhash' 2>/dev/null)
    echo "probe accepted on retry"
fi

# POLLED, and "not resolvable yet" is kept DISTINCT from "the scan refused it".
#
# The node has just restarted, so the first query can easily land before the transaction is indexed
# and return nothing at all.  An earlier version compared that empty result straight against "0" and
# reported "a scanned send failed with code " -- blaming the enclave for losing its sealed keys when
# the upgrade had in fact worked perfectly and the transaction simply had not been indexed yet.  A
# test that accuses the wrong component is worse than one that just fails.
probe_code=""
for _ in {1..30}; do
    qadenad_alias query wait-tx "$probe_hash" --timeout 10s > /dev/null 2>&1 || true
    probe_code=$(qadenad_alias query tx "$probe_hash" --output json 2>/dev/null | jq -r '.code // empty' 2>/dev/null)
    [ -n "$probe_code" ] && break
    sleep 2
done

[ -n "$probe_code" ] \
    || fail "the probe send $probe_hash never resolved, so whether the sealed store survived is UNKNOWN -- this is not itself evidence of unsealing failure"
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
