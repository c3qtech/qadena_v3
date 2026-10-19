#!/bin/zsh
#
# test_cpu_move_recovery.sh -- prove a node survives its VM moving to another CPU, WITHOUT losing what
# was encrypted to its enclave key.
#
#   ./testscripts/test_cpu_move_recovery.sh --primary 10.211.55.5 --seed 10.211.55.6 \
#       --keyring-passfile ~/qadena-launch/fleet-launch/keyring-password
#
# --keyring-passfile is needed when the node keyring is `file` (the devnet config asks for it): it is
# copied to the primary at mode 600 for the run and removed on exit, as 1st_node_bringup.sh does.
#
# Run from the Mac against a devnet whose PRIMARY holds most of the stake (so taking it down halts the
# chain, as on c3q-mainnet 2026-10-14) and whose users are not yet provisioned.
#
# WHAT WOULD BE LOST WITHOUT THE ESCROW.  A user's key-recovery shares are encrypted, on chain, to
# their HOME pioneer's EnclavePubKType key, and `show-recover-key` has that pioneer's enclave decrypt
# them with EnclavePrivK (enclave.go, RecoverKey).  A pioneer re-keyed after a move holds a different
# EnclavePrivK and can never open them again.  So:
#
#   1. baseline   provision users; protect ann's and jill's seed phrases; open recovery; the USERS sign
#                 their shares (encrypted to pioneer1's enclave key).  ann's recovery is complete
#                 now -- record what show-recover-key returns.
#   2. move       stop the primary (chain halts); make its sealed state unreadable, as a new CPU
#                 would.  On a debug enclave "sealing" is a prefix, so corrupt the prefix.
#   3. control    with the escrow withheld, recovery must REFUSE and leave the sealed params as they
#                 were -- the refused-sync bug used to overwrite them with fresh, unregistered keys.
#   4. recover    recover_enclave_after_cpu_move.sh against the seed; restart; the chain resumes and
#                 both nodes agree on app hashes.
#   5. verify     the pioneer and service provider sign their shares NOW (a tx through the restored
#                 enclave), then show-recover-key for ann and jill must return exactly their
#                 seed phrases -- ann's built entirely from pre-move ciphertexts.
#
# Debug enclaves prove the LOGIC (escrow, refusal, restore, no tx, private-state fetch); they do not
# exercise CPU-bound sealing.  See enclave_escrow.go.

SCRIPT_DIR="${0:A:h}"
PRIMARY="" SEED="" REPO="qv3" FROM=1 PASSFILE="" HALT_SECONDS=900 EXPECT_OWNERS=2
ALSO_STOP=() PEERS=() CUSTODY_ONLY=""
while (( $# )); do
    case "$1" in
        --primary) PRIMARY="$2"; shift 2 ;;
        --seed)    SEED="$2"; shift 2 ;;
        --repo)    REPO="$2"; shift 2 ;;
        --from)    FROM="$2"; shift 2 ;;
        --keyring-passfile) PASSFILE="$2"; shift 2 ;;
        --halt-seconds) HALT_SECONDS="$2"; shift 2 ;;
        # Stopped together with the primary: makes a halt on a fleet where the primary alone is not
        # a third of the stake, and leaves the restore one owner short.  Repeatable.
        --also-stop) ALSO_STOP+=("$2"); shift 2 ;;
        # Other running nodes, compared for app hashes.  Repeatable.
        --peer) PEERS+=("$2"); shift 2 ;;
        # How many pioneers must own the escrow's SS key.  4+ gives threshold 2 -- a real combine.
        --expect-owners) EXPECT_OWNERS="$2"; shift 2 ;;
        # Only report a node's SS share custody and exit: owned / held / missing.
        --check-custody) CUSTODY_ONLY="$2"; shift 2 ;;
        *) echo "unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ -n "$CUSTODY_ONLY" ]] && { PRIMARY="${PRIMARY:-$CUSTODY_ONLY}"; SEED="${SEED:-$CUSTODY_ONLY}"; }
[[ -n "$PRIMARY" && -n "$SEED" ]] || { echo "usage: $0 --primary <host> --seed <host> [--from <phase>]" >&2; exit 2 }

source "$SCRIPT_DIR/setup_mnemonic.sh"

OUT="${TMPDIR:-/tmp}/test_cpu_move_recovery.$$"
mkdir -p "$OUT"
FAILS=0
pass() { print -r -- "  PASS  $*" }
fail() { print -r -- "  FAIL  $*"; (( FAILS++ )) }
die()  { print -r -- "  FATAL $*"; print -r -- "logs: $OUT"; exit 1 }
phase() { print -r -- ""; print -r -- "=== $*" }

# Run in the primary's checkout, with the node's environment.  bash -lc: go and friends are on PATH
# only under a bash login shell on these boxes.
REM_KP=""
if [[ -n "$PASSFILE" ]]; then
    [[ -f "$PASSFILE" ]] || { echo "--keyring-passfile $PASSFILE does not exist" >&2; exit 2 }
    scp -q "$PASSFILE" "alvillarica@$PRIMARY:.qadena-test-keyring-pass" || { echo "cannot copy the passphrase to $PRIMARY" >&2; exit 1 }
    ssh -o BatchMode=yes "alvillarica@$PRIMARY" 'chmod 600 .qadena-test-keyring-pass'
    # QADENA_KEYRING_PASS itself, not only the PASSFILE: the scripts read the variable, and only
    # qadena_keyring_unlock -- which none of them call -- turns the file into it.
    REM_KP='export QADENA_KEYRING_PASSFILE=$HOME/.qadena-test-keyring-pass QADENA_KEYRING_PASS="$(head -1 $HOME/.qadena-test-keyring-pass)"; '
    trap 'ssh -o BatchMode=yes "alvillarica@$PRIMARY" "rm -f .qadena-test-keyring-pass" 2>/dev/null' EXIT INT TERM
fi
on() { local h="$1"; shift; ssh -o BatchMode=yes "alvillarica@$h" "cd ~/$REPO && ${REM_KP}bash -lc $(printf '%q' "$*")" }
# Inline snippets source setup_env.sh, which is zsh.
onz() { local h="$1"; shift; on "$h" "zsh -c $(printf '%q' "source ./scripts/setup_env.sh >/dev/null 2>&1; $*")" }

status_of() { ssh -o BatchMode=yes "alvillarica@$1" 'curl -s --max-time 5 localhost:26657/status' }
height_of() { status_of "$1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["sync_info"]["latest_block_height"])' 2>/dev/null }
apphash_at() { ssh -o BatchMode=yes "alvillarica@$1" "curl -s --max-time 5 'localhost:26657/block?height=$2'" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["block"]["header"]["app_hash"])' 2>/dev/null }

# Wait (bounded) for a host's height to pass $2.
wait_height_past() {
    local h="$1" target="$2" i cur
    for i in {1..60}; do
        cur=$(height_of "$h"); [[ -n "$cur" ]] && (( cur > target )) && return 0
        sleep 5
    done
    return 1
}

# The seed phrase show-recover-key prints for a recover wallet, or nothing.
# The passphrase is piped HERE: qadenad_alias feeds it to keys/tx only, and show-recover-key is a
# query that still opens the recover wallet's key from the (file) keyring -- unfed, it reads EOF
# and fails with "Couldn't convert from bech32 format".
recovered_seed() { onz "$PRIMARY" "{ repeat 8 print -r -- \"\$QADENA_KEYRING_PASS\" } | qadenad_alias query qadena show-recover-key $1" 2>&1 | tee "$OUT/show-$1.$2.log" | sed -n 's/^seed phrase:\{0,1\} //p' | tail -1 }

check_seed() {   # wallet expected label
    local got; got=$(recovered_seed "$1" "$3")
    if [[ "$got" == "$2" ]]; then pass "$1 recovers the right seed phrase ($3)"
    else fail "$1 did not recover its seed phrase ($3): got '${got:-nothing}' -- see $OUT/show-$1.$3.log"; fi
}

H="/home/alvillarica/qadena"

# share_custody <host> -- "owned=N held=M missing=<ids>" for the SS keys whose owner list names that
# node's pioneer.  An owner listed on chain with no share is custody silently lost: the key survives
# one fewer departure, and peers asking that node for a share get nothing.  Values never leave the
# host; only counts and key IDs are printed.
share_custody() {
    # The node's INSTALLED scripts, not a checkout: joiners have none.
    ssh -o BatchMode=yes "alvillarica@$1" 'cd '"$H"' && p=$(jq -r .pioneer_id config/node_params.json)
zsh -c "source ./scripts/setup_env.sh >/dev/null 2>&1
qadenad_alias enclave export-private-state --section EnclaveSSOwnersMap 2>/dev/null > /tmp/cust_o.json
qadenad_alias enclave export-private-state --section EnclaveSSShareMap  2>/dev/null > /tmp/cust_s.json"
jq -r --arg p "$p" --slurpfile s /tmp/cust_s.json "
  (.EnclaveSSOwnersMap.Pioneers // {}) | to_entries
  | map(select(.value.PioneerIDs | index(\$p)))
  | map({k: .key, held: ((\$s[0].EnclaveSSShareMap[.key] // \"\") != \"\")})
  | \"owned=\" + (length|tostring) + \" held=\" + (map(select(.held))|length|tostring)
    + \" missing=\" + (map(select(.held|not)|.k)|join(\",\"))" /tmp/cust_o.json
rm -f /tmp/cust_o.json /tmp/cust_s.json'
}
custody_ok() { [[ "$1" == owned=* && "$1" == *" missing=" ]] }

# DOUBLE-SIGN PROTECTION.  signer_height: the last height the node's signer recorded signing.
signer_height() { ssh -o BatchMode=yes "alvillarica@$1" "jq -r '.height | tonumber' $H/enclave_data/signer_state.json 2>/dev/null" }
val_addr() { status_of "$1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["validator_info"]["address"])' 2>/dev/null }
# signed_at <addr> <height>: did that validator's signature make it into the commit for <height>?
signed_at() { ssh -o BatchMode=yes "alvillarica@$SEED" "curl -s --max-time 5 'localhost:26657/commit?height=$2'" \
    | python3 -c 'import sys,json;s=json.load(sys.stdin)["result"]["signed_header"]["commit"]["signatures"];print("yes" if any(x.get("validator_address")==sys.argv[1] for x in s) else "no")' "$1" 2>/dev/null }
# signs_again <host> <after-height>: the node's signature appears in a commit above <after-height>.
signs_again() {
    local addr; addr=$(val_addr "$1"); local i h
    for i in {1..30}; do
        h=$(( $(height_of "$SEED") - 1 ))
        (( h > $2 )) && [[ "$(signed_at "$addr" "$h")" == yes ]] && { print -r -- "$h"; return 0 }
        sleep 3
    done
    return 1
}

if [[ -n "$CUSTODY_ONLY" ]]; then
    c=$(share_custody "$CUSTODY_ONLY")
    print -r -- "$CUSTODY_ONLY: $c"
    custody_ok "$c" && exit 0 || exit 1
fi

if (( FROM <= 1 )); then
phase "0. an SS key the OTHER pioneers own, for the escrow"
# The chain's first interval key was minted while the primary was the only addressable pioneer, so
# only it owns that key -- and a restore cannot use the restoring node's own share.  The escrow
# writer refuses such a key; rotate once so there is one the seed also owns.  (debug-only command;
# on a real fleet the 555-block rotation does this.)
# A pioneer becomes an owner candidate only once it has PUBLISHED an address (first proposed block
# after bonding), so rotating before every joiner has would mint a key that leaves some out.
for i in {1..60}; do
    naddr=$(onz "$PRIMARY" "qadenad_alias query qadena list-interval-public-key-id --limit 5000 -o json" 2>/dev/null \
        | jq '[.intervalPublicKeyID[]? | select(.nodeType=="pioneer" and .externalIPAddress!="")] | length' 2>/dev/null)
    (( ${naddr:-0} >= EXPECT_OWNERS )) && break
    sleep 5
done
(( ${naddr:-0} >= EXPECT_OWNERS )) && pass "$naddr pioneers have published addresses" \
    || die "only ${naddr:-0} pioneers published addresses; $EXPECT_OWNERS needed"
onz "$PRIMARY" "qadenad_alias enclave update-ss-interval-key" > "$OUT/rotate.log" 2>&1 || die "could not force an SS key rotation ($OUT/rotate.log)"
esc_key="" nowners=0
for i in {1..24}; do
    sleep 5
    esc_key=$(ssh alvillarica@$PRIMARY "jq -r .SSPubKID $H/enclave_config/private_params_escrow.json 2>/dev/null")
    [[ -n "$esc_key" && "$esc_key" != null ]] || continue
    owners=$(onz "$PRIMARY" "qadenad_alias query qadena show-public-key $esc_key transaction -o json" 2>/dev/null | jq -r '[.publicKey.shares[]?.pioneerID] | join(",")')
    nowners=$(print -r -- "$owners" | tr ',' '\n' | grep -c .)
    (( nowners >= EXPECT_OWNERS )) && break
done
(( nowners >= EXPECT_OWNERS )) && pass "the escrow is on SS key $esc_key, owned by $owners ($nowners owners)" \
    || die "the escrow never moved to a key with $EXPECT_OWNERS+ owners (key ${esc_key:-none}, owners ${owners:-?})"
print -r -- "$nowners" > "$OUT/nowners"

phase "1. baseline: provision, protect, request recovery, users sign"
# A DEPLOYMENT PROFILE FIRST: setup_provider_base.sh refuses an empty app-server allow-list, and
# setup_prerequisites.sh does not load one itself.
onz "$PRIMARY" "source ./foundation_scripts/deployment_profile.sh >/dev/null 2>&1 && deployment_profile_load veritas && ./testscripts/setup_prerequisites.sh" > "$OUT/prereq.log" 2>&1 || die "setup_prerequisites.sh failed ($OUT/prereq.log)"
# ONE USER AT A TIME, and only the four this test needs.  setup.sh provisions every user in
# parallel, and in foundation-sponsored mode each one revokes and re-grants from the SAME sponsor
# account: the revokes collide on its sequence, fail silently, and every re-grant then dies with
# "fee allowance already exists".  victor first: he is a recovery partner of the others.
# VERITAS_FOUNDATION_APPSVR=testidentitysrvprv: create_user.sh names the identity provider's fee
# granter foundation-veritas-appsvr, a key a devnet keyring does not have ("decoding bech32
# failed"), and the treasury's grant to the provider does not cover MsgCreateCredential.  A granter
# equal to the payer makes the SDK charge the payer, and on a devnet the provider holds its own QDN.
for u in victor al ann jill; do
    onz "$PRIMARY" "source ./foundation_scripts/deployment_profile.sh >/dev/null 2>&1 && deployment_profile_load veritas && VERITAS_FOUNDATION_APPSVR=testidentitysrvprv ./testscripts/setup.sh --specific-user $u" > "$OUT/setup-$u.log" 2>&1 \
        || print -r -- "  note  setup.sh --specific-user $u did not finish ($OUT/setup-$u.log); continuing -- the seed-phrase checks below are the verdict"
done
# PROTECT-KEY DIRECTLY.  setup.sh does it only after every user step succeeds, and a late step this
# test does not need (a nameservice bind to <user>-eph2, outside that wallet's fee grant) stops it
# first.  Partners and threshold come from test_data/users.json, pioneer1 mapped as setup.sh does.
for u in ann jill; do
    onz "$PRIMARY" "source ./testscripts/setup_mnemonic.sh
        req=\$(jq -r --arg n $u '.[] | select(.name==\$n) | .recovery.required' test_data/users.json)
        partners=\$(jq -r --arg n $u '.[] | select(.name==\$n) | .recovery.partners | join(\" \")' test_data/users.json)
        ./testscripts/setup_user_recovery.sh $u \"\${${u}mnemonic}\" \"\$req\" \"\$partners\"" > "$OUT/protect-$u.log" 2>&1 \
        || print -r -- "  note  protect-key for $u returned non-zero ($OUT/protect-$u.log) -- it may already exist"
    sleep 3
done
# Re-runnable: on a second pass the recover-* wallets exist and this reports errors for them.
on "$PRIMARY" "./testscripts/request_key_recovery.sh" > "$OUT/request.log" 2>&1 || print -r -- "  note  request_key_recovery.sh returned non-zero ($OUT/request.log)"
# Only the USER signatures now; the pioneer and the service provider sign after the move, through
# the restored enclave.
onz "$PRIMARY" '
qadenad_alias tx qadena sign-recover-key ann-eph1 --from victor-eph1 --is-user --yes
sleep 3; qadenad_alias tx qadena sign-recover-key jill-eph1 --from victor-eph1 --is-user --yes; sleep 6' > "$OUT/sign-users.log" 2>&1 || print -r -- "  note  user signing returned non-zero ($OUT/sign-users.log)"
check_seed recover-ann "$annmnemonic" "before the move"
fi

if (( FROM <= 2 )); then
phase "2. move: stop the primary and make its sealed state unreadable"
pubk_before=$(ssh alvillarica@$PRIMARY "jq -r .EnclavePubK $H/enclave_config/private_params_escrow.json" 2>/dev/null)
[[ -n "$pubk_before" && "$pubk_before" != null ]] && pass "the primary has an escrow (enclave key ${pubk_before[1,16]}...)" || die "no escrow on the primary -- is it running this branch?"
print -r -- "$pubk_before" > "$OUT/pubk_before"
cust_before=$(share_custody "$PRIMARY")
custody_ok "$cust_before" && pass "share custody before the move: $cust_before" || fail "share custody already incomplete before the move: $cust_before"
h0=$(height_of "$SEED")
on "$PRIMARY" "$H/scripts/stop_qadena.sh" > "$OUT/stop.log" 2>&1
sh_before=$(signer_height "$PRIMARY")
[[ -n "$sh_before" && "$sh_before" != null ]] && pass "the primary's signer recorded signing up to height $sh_before" \
    || fail "the primary has no double-sign state (enclave_data/signer_state.json)"
print -r -- "$sh_before" > "$OUT/signer_before"
for x in "${ALSO_STOP[@]}"; do
    on "$x" "$H/scripts/stop_qadena.sh" > "$OUT/stop-$x.log" 2>&1
    pass "also stopped $x -- one fewer owner to rebuild the SS key from"
done
sleep 15
h1=$(height_of "$SEED")
(( h1 - h0 <= 2 )) && pass "the chain halted with the primary down (seed height $h0 -> $h1)" || print -r -- "  note  the seed kept producing blocks ($h0 -> $h1): the primary is not a majority here"
# A new CPU cannot open anything sealed on the old one.  Corrupt the debug seal prefix of every
# sealed file so the enclave and the signer fail exactly where SGX would.
ssh alvillarica@$PRIMARY "cd $H/enclave_config && for f in enclave_params_*.json priv_validator_key.json; do printf 'MOVED' | dd of=\$f bs=1 count=5 conv=notrunc 2>/dev/null; done; sha256sum enclave_params_*.json" > "$OUT/broken.sha" || die "could not break the sealed files"
pass "sealed files corrupted (as a new CPU would see them)"

# THE ESCROW MUST NOT DEPEND ON THE JAR KEY -- the regulator is to be given it.  It names the SS
# interval key it is wrapped to, and nothing else.
ssk=$(ssh alvillarica@$PRIMARY "jq -r '[.Version, .SSPubKID, (has(\"JarID\"))] | @tsv' $H/enclave_config/private_params_escrow.json")
[[ "$(print -r -- "$ssk" | cut -f1)" == 2 && -n "$(print -r -- "$ssk" | cut -f2)" && "$(print -r -- "$ssk" | cut -f3)" == false ]] \
    && pass "the escrow is wrapped to SS interval key $(print -r -- "$ssk" | cut -f2) and carries no jar reference" \
    || fail "the escrow is not an SS-keyed v2 escrow: $ssk"

# THE HALTED-CHAIN CASE, AS IT HAPPENED ON c3q-mainnet: hours down, not seconds.  The restore needs
# the OTHER owners' enclaves to serve SS shares while no block arrives; restarting the seed during the
# halt also covers an enclave that has never been told the chain's position.
on "$SEED" "$H/scripts/stop_qadena.sh" > "$OUT/seed-stop.log" 2>&1
ssh -o BatchMode=yes alvillarica@$SEED "$H/scripts/start_qadena.sh > /tmp/cpu_move_seed_start.log 2>&1 < /dev/null"
sleep 20
hs=$(height_of "$SEED")
[[ -n "$hs" ]] && pass "the seed restarted during the halt and answers at height $hs" || die "the seed did not come back after its restart"
print -r -- "  ....  holding the chain halted for ${HALT_SECONDS}s"
sleep "$HALT_SECONDS"
hs2=$(height_of "$SEED")
[[ "$hs2" == "$hs" ]] && pass "still halted after ${HALT_SECONDS}s (height $hs2)" || fail "the chain moved during the halt ($hs -> $hs2)"
fi

if (( FROM <= 3 )); then
phase "3. control: without the escrow, recovery refuses and writes nothing"
ssh alvillarica@$PRIMARY "mv $H/enclave_config/private_params_escrow.json $H/escrow.withheld"
on "$PRIMARY" "$H/scripts/recover_enclave_after_cpu_move.sh --seed tcp://$SEED:26657 --yes" > "$OUT/control.log" 2>&1
rc=$?
(( rc != 0 )) && pass "recovery refused without the escrow (exit $rc)" || fail "recovery claimed success with no escrow"
grep -q "no escrow" "$OUT/control.log" && pass "and said why" || fail "refusal did not name the missing escrow ($OUT/control.log)"
ssh alvillarica@$PRIMARY "cd $H/enclave_config && sha256sum enclave_params_*.json" > "$OUT/control.sha"
diff -q "$OUT/broken.sha" "$OUT/control.sha" > /dev/null && pass "sealed params untouched by the refusal" || fail "the refusal changed the sealed params"
ssh alvillarica@$PRIMARY "mv $H/escrow.withheld $H/enclave_config/private_params_escrow.json"
fi

if (( FROM <= 4 )); then
phase "4. recover from the escrow, restart, chain resumes"
on "$PRIMARY" "$H/scripts/recover_enclave_after_cpu_move.sh --seed tcp://$SEED:26657 --yes" > "$OUT/recover.log" 2>&1 \
    && pass "recover_enclave_after_cpu_move.sh succeeded" || die "recovery failed ($OUT/recover.log)"
sh_after=$(signer_height "$PRIMARY")
[[ -n "$sh_after" && "$sh_after" == "$(cat $OUT/signer_before 2>/dev/null)" ]] \
    && pass "the signer's double-sign state was carried across the restore (height $sh_after)" \
    || fail "double-sign state NOT carried across: before ${$(cat $OUT/signer_before 2>/dev/null):-?}, after ${sh_after:-missing}"
pubk_after=$(ssh alvillarica@$PRIMARY "jq -r .EnclavePubK $H/enclave_config/private_params_escrow.json")
[[ "$pubk_after" == "$(cat $OUT/pubk_before 2>/dev/null)" ]] && pass "enclave key unchanged across the move" || fail "enclave key changed: $pubk_after"
# Redirected to a file and never piped: start_qadena.sh leaks descriptors to the node.
ssh -o BatchMode=yes alvillarica@$PRIMARY "$H/scripts/start_qadena.sh > /tmp/cpu_move_start.log 2>&1 < /dev/null"
h_seed=$(height_of "$SEED")
wait_height_past "$SEED" $(( h_seed + 5 )) && pass "the chain resumed (seed past $(( h_seed + 5 )))" || die "the chain did not resume"
wait_height_past "$PRIMARY" $(( h_seed + 5 )) && pass "the primary is producing" || die "the primary is not advancing"
hc=$(( $(height_of "$SEED") - 1 ))
a1=$(apphash_at "$PRIMARY" $hc); a2=$(apphash_at "$SEED" $hc)
[[ -n "$a1" && "$a1" == "$a2" ]] && pass "app hashes agree at $hc ($a1)" || fail "app hash mismatch at $hc: $a1 vs $a2"
hsig=$(signs_again "$PRIMARY" "$(cat $OUT/signer_before 2>/dev/null || print 0)") \
    && pass "the restored primary's signature is in the commit for height $hsig" \
    || fail "the restored primary is not signing commits"
# The recovery log in full (it is small); only the tail of the node log.
ssh alvillarica@$PRIMARY "grep -h -E 'RESTORED from the escrow|restored pioneer|via=escrow-restore|escrow: gathering|ss-whohas|RECONSTRUCTED' $H/logs/recover_enclave.*.log 2>/dev/null; grep -h -E 'private state|private tables' $H/logs/qadena.log 2>/dev/null | tail -6" > "$OUT/restore-lines.log"
grep -q "RESTORED from the escrow" "$OUT/restore-lines.log" && pass "enclave log: restored from the escrow, no registration tx" || fail "no restore line in the enclave log ($OUT/restore-lines.log)"
# FROM SHARES, NOT FROM SOMEONE'S CACHE.  WHO-HAS (a peer holding the whole key cached) also opens
# the escrow, and an earlier run passed that way while asking zero owners -- proving nothing about
# the threshold path.  Require the gather to have reached at least one other owner and not to
# have needed the rescue.
if grep -q "escrow: gathering SS key .* from [1-9][0-9]* owner" "$OUT/restore-lines.log" \
   && grep -q "rebuilt via=escrow-restore" "$OUT/restore-lines.log" \
   && ! grep -q "RESCUED.*via=escrow-restore" "$OUT/restore-lines.log"; then
    pass "enclave log: the SS key was rebuilt from another owner's share during the halt"
else
    fail "the SS key was not rebuilt from owner shares ($OUT/restore-lines.log)"
fi
# SHARE CUSTODY CAME BACK.  The checks above all passed on a run that silently lost two shares (plan
# item 1a), because nothing looked.  Every key the node owned must have its share again.
cust_after=$(share_custody "$PRIMARY")
if custody_ok "$cust_after"; then
    pass "share custody after the restore: $cust_after"
else
    fail "share custody NOT restored: $cust_after (before the move: $cust_before)"
fi
# NO LAZY REBUILD OF THE ESCROW'S KEY.  The restore rebuilds that key; if the node then has to rebuild it
# again inside block execution (the LAZY path -- network I/O in consensus, a fork when peers do not
# answer), the restore's cached copy was lost.  It was: cached under the temporary sealed-table
# secret, unfindable once the escrowed one was installed.
esc_key_now=$(ssh alvillarica@$PRIMARY "jq -r .SSPubKID $H/enclave_config/private_params_escrow.json")
nlazy=$(ssh alvillarica@$PRIMARY "sed 's/\x1b\[[0-9;]*m//g' $H/logs/qadena.log | grep -c 'LAZY PATH pubKID=$esc_key_now'")
(( ${nlazy:-1} == 0 )) && pass "the restored node did not rebuild the escrow's SS key inside block execution" \
    || fail "the restored node rebuilt SS key $esc_key_now on the LAZY path $nlazy time(s) -- the restore's cached copy was lost"
# A REAL SHAMIR COMBINE when the key has 4+ owners: threshold 2, both shares from OTHER owners.
if (( $(cat "$OUT/nowners" 2>/dev/null || print 0) >= 4 )); then
    if grep -q "escrow: gathering SS key .* threshold 2" "$OUT/restore-lines.log" \
       && grep -q "RECONSTRUCTED .*via=escrow-restore shares=2/2" "$OUT/restore-lines.log"; then
        pass "the SS key was COMBINED from 2 other owners' shares (threshold 2)"
    else
        fail "no threshold-2 combine in the restore log ($OUT/restore-lines.log)"
    fi
fi
fi

if (( FROM <= 5 )); then
phase "5. verify: pre-move ciphertexts open, and the restored enclave serves new work"
onz "$PRIMARY" 'pioneer=${QADENA_PIONEER:-pioneer1}
qadenad_alias tx qadena sign-recover-key jill-eph1 --from "$pioneer" --yes &&
sleep 3 && qadenad_alias tx qadena sign-recover-key jill-eph1 --from testidentitysrvprv --is-service-provider --yes && sleep 6' > "$OUT/sign-after.log" 2>&1 \
    && pass "pioneer and service provider signed after the move" || fail "post-move signing failed ($OUT/sign-after.log)"
check_seed recover-ann  "$annmnemonic"  "after the move: every share pre-move"
check_seed recover-jill "$jillmnemonic" "after the move: pre-move user share + post-move shares"
hc=$(( $(height_of "$SEED") - 1 ))
a1=$(apphash_at "$PRIMARY" $hc); a2=$(apphash_at "$SEED" $hc)
[[ -n "$a1" && "$a1" == "$a2" ]] && pass "app hashes still agree at $hc after post-move txs" || fail "app hash mismatch at $hc: $a1 vs $a2"

for x in "${ALSO_STOP[@]}"; do
    ssh -o BatchMode=yes alvillarica@$x "$H/scripts/start_qadena.sh > /tmp/cpu_move_restart.log 2>&1 < /dev/null"
done
if (( ${#ALSO_STOP} )); then
    target=$(height_of "$SEED")
    for x in "${ALSO_STOP[@]}"; do
        wait_height_past "$x" "$target" && pass "$x came back and caught up past $target" || fail "$x did not catch up past $target"
    done
fi
# A LIVE RESTART must come back signing.  The identical-re-sign case (crash after signing, before
# the WAL) is the one the old, switched-off check would have stalled on.
if (( ${#PEERS} )); then
    rp="${PEERS[1]}"
    on "$rp" "$H/scripts/stop_qadena.sh" > "$OUT/restart-stop-$rp.log" 2>&1
    hr=$(height_of "$SEED")
    ssh -o BatchMode=yes alvillarica@$rp "$H/scripts/start_qadena.sh > /tmp/cpu_move_live_restart.log 2>&1 < /dev/null"
    hsig=$(signs_again "$rp" "$hr") && pass "$rp restarted on a live chain and is signing again (commit $hsig)" \
        || fail "$rp did not sign again after a live restart"
fi
# NO REFUSED SIGNATURES anywhere.  A refusal is the protection working, but in this run nothing
# should ever ask for one; seeing any means something tried to sign at or behind its last state.
for x in "$PRIMARY" "$SEED" "${PEERS[@]}" "${ALSO_STOP[@]}"; do
    nref=$(ssh -o BatchMode=yes "alvillarica@$x" "grep -h 'REFUSING to sign' $H/logs/qadena.log 2>/dev/null | wc -l | tr -d ' '")
    (( ${nref:-0} == 0 )) && pass "$x refused no signatures" || fail "$x refused $nref signature(s) -- see 'REFUSING to sign' in its log"
done
hc=$(( $(height_of "$SEED") - 2 ))
ref=$(apphash_at "$SEED" $hc)
for x in "$PRIMARY" "${PEERS[@]}" "${ALSO_STOP[@]}"; do
    a=$(apphash_at "$x" $hc)
    [[ -n "$a" && "$a" == "$ref" ]] && pass "$x agrees with the seed at $hc" || fail "$x disagrees at $hc: ${a:-none} vs $ref"
done
fi

print -r -- ""
print -r -- "logs: $OUT"
(( FAILS == 0 )) && { print -r -- "test_cpu_move_recovery: ALL PASSED"; exit 0 }
print -r -- "test_cpu_move_recovery: $FAILS FAILED"; exit 1
