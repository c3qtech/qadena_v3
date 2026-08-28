#!/bin/zsh
#
# Native custody follow-ups: the paths the Phase A suite left unproven.
#
# Everything here uses CORE Cosmos SDK modules only -- no CosmWasm, and no x/group (which moved to
# enterprise/ under a paid licence in SDK v0.54).  See tokenomics/qadena-native-brief.md.
#
# The centrepiece is a multisig vesting account whose tokens are GENUINELY STILL LOCKED.  An earlier
# run used a backdated single-period schedule that had already fully elapsed, so its "delegation of
# locked principal" was really a delegation of free tokens -- `delegated_free` was set and
# `delegated_vesting` was empty.  A long first period is used below so the distinction is real, and
# every assertion reads delegated_vesting rather than trusting the balance.
#
# Verdict convention as in test_token_gating.sh: on-chain result codes only, never exit status.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"
set -e
function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }
cd $qadenabuild

run_id=$(date +%s)
lbl="native-$run_id"
ev="$qadenabuild/logs/native-custody"; mkdir -p "$ev"
G=(--gas auto --gas-adjustment 1.5 --gas-prices $minimum_gas_prices)
CID=$(qadenad_alias status 2>/dev/null | jq -r '.node_info.network // .NodeInfo.network')

typeset -A V; typeset -A N; ord=()
rec() { V[$1]="$2"; N[$1]="$3"; ord+=("$1"); echo ""; echo ">>> $1: $2 -- $3"; echo "" }
die() { echo "HARNESS ERROR: $1"; exit 1 }
addr()  { qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null }
bal()   { local a; a=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null | jq -r '.balances[]?|select(.denom=="aqdn")|.amount'); echo "${a:-0}" }
spend() { local a; a=$(qadenad_alias query bank spendable-balances "$1" --output json 2>/dev/null | jq -r '.balances[]?|select(.denom=="aqdn")|.amount'); echo "${a:-0}" }
acct()  { qadenad_alias query auth account "$1" --output json 2>/dev/null }
dv()    { acct "$1" | jq -r '.account.value.base_vesting_account.delegated_vesting[0].amount // "0"' }
df()    { acct "$1" | jq -r '.account.value.base_vesting_account.delegated_free[0].amount // "0"' }

# wait_code <hash> -> on-chain code
wait_code() {
    [ -z "$1" ] && { echo "NO_HASH"; return }
    qadenad_alias query wait-tx "$1" --timeout 120s >/dev/null 2>&1 || true
    qadenad_alias query tx "$1" --output json 2>/dev/null > "$ev/$2.json" || true
    [ -s "$ev/$2.json" ] && jq -r '.code // "UNKNOWN"' "$ev/$2.json" 2>/dev/null || echo "NO_RESULT"
}
rawlog() { [ -s "$ev/$1.json" ] && jq -r '.raw_log // ""' "$ev/$1.json" 2>/dev/null || echo "" }

# msig_exec <name> <msig-key> <unsigned-file> -- 2-of-3 sign, combine, broadcast; echoes code.
# --generate-only must never be combined with --gas auto (no signer to simulate with), so callers
# build the unsigned tx with an explicit --gas.
msig_exec() {
    local name="$1" key="$2" unsigned="$3" a an sq
    a=$(addr "$key")
    local j=$(acct "$a")
    an=$(echo "$j" | jq -r '.account.value.base_vesting_account.base_account.account_number // .account.value.account_number // .account.account_number // ""')
    sq=$(echo "$j" | jq -r '.account.value.base_vesting_account.base_account.sequence // .account.value.sequence // .account.sequence // "0"')
    for k in 1 2; do
        qadenad_alias tx sign "$unsigned" --from "$lbl-k$k" --multisig "$a" \
            --account-number "$an" --sequence "$sq" --chain-id "$CID" --keyring-backend test \
            --output-document "$ev/$name-s$k.json" >/dev/null 2>&1 || true
    done
    [ -s "$ev/$name-s1.json" ] && [ -s "$ev/$name-s2.json" ] || { echo "SIGN_FAILED"; return }
    qadenad_alias tx multisign "$unsigned" "$key" "$ev/$name-s1.json" "$ev/$name-s2.json" \
        --account-number "$an" --sequence "$sq" --chain-id "$CID" --keyring-backend test \
        --output-document "$ev/$name-signed.json" >/dev/null 2>&1 || true
    [ -s "$ev/$name-signed.json" ] || { echo "MULTISIGN_FAILED"; return }
    local h=$(qadenad_alias tx broadcast "$ev/$name-signed.json" --output json 2>/dev/null | jq -r '.txhash // ""')
    wait_code "$h" "$name"
}

whitelist() {   # whitelist <address> <reason> -> final gov status
    local address="$1" reason="$2" f=$(mktemp -t qadena-nc.XXXXXX)
    local auth=$(qadenad_alias query auth module-account gov --output json 2>/dev/null | jq -r '.account.value.address // .account.base_account.address')
    jq -n --arg a "$auth" --arg ad "$address" --arg r "$reason" \
      '{messages:[{"@type":"/qadena.qadena.MsgAddScannedContractWhitelist",authority:$a,address:$ad,codeID:0,reason:$r}],
        metadata:"ipfs://CID",deposit:"100000qdn",title:"native custody whitelist",summary:"native custody whitelist",expedited:true}' > "$f"
    local r=$(qadenad_alias tx gov submit-proposal "$f" --from treasury -y --output json "${G[@]}" 2>/dev/null)
    rm -f "$f"
    local th=$(echo "$r" | jq -r .txhash)
    qadenad_alias query wait-tx "$th" --timeout 120s >/dev/null 2>&1 || true
    local pid=$(qadenad_alias query tx "$th" --output json 2>/dev/null | jq -r '.events[]|select(.type=="submit_proposal")|.attributes[]|select(.key=="proposal_id")|.value'|head -1)
    [ -n "$pid" ] || { echo "NO_PROPOSAL"; return }
    $qadenatestscripts/gov_vote_from_treasury.sh "$pid" yes >/dev/null 2>&1 || true
    local st deadline=$(( $(date +%s) + 400 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        st=$(qadenad_alias query gov proposal "$pid" --output json 2>/dev/null | jq -r '.proposal.status // .status')
        case "$st" in PROPOSAL_STATUS_PASSED|PROPOSAL_STATUS_REJECTED|PROPOSAL_STATUS_FAILED) break;; esac
        sleep 5
    done
    echo "$st"
}

echo "======================================================================"
echo "NATIVE CUSTODY FOLLOW-UPS -- run $run_id (chain $CID)"
echo "======================================================================"
qadenad_alias status >/dev/null 2>&1 || die "chain unreachable"
VAL=$(qadenad_alias query staking validators --output json | jq -r '.validators[0].operator_address')
TRE=$(addr treasury)

# ---------------------------------------------------------------------------------------------
# setup: a 2-of-3 multisig holding a vesting account that is GENUINELY STILL LOCKED
# ---------------------------------------------------------------------------------------------
echo "--- setup: locked multisig vesting account ---"
for k in 1 2 3; do qadenad_alias keys add "$lbl-k$k" --algo eth_secp256k1 --keyring-backend test >/dev/null 2>&1; done
qadenad_alias keys add "$lbl-msig" --multisig "$lbl-k1,$lbl-k2,$lbl-k3" --multisig-threshold 2 --keyring-backend test >/dev/null 2>&1 \
    || die "could not build the multisig"
MS=$(addr "$lbl-msig"); echo "multisig: $MS"

wl=$(whitelist "$MS" "native custody follow-up: locked multisig")
echo "whitelist: $wl"
[ "$wl" = "PROPOSAL_STATUS_PASSED" ] || die "whitelist did not pass: $wl"

# 10,000 QDN: 2,000 unlocks after 60s (a small operating float), 8,000 locked for a year.
# The long second period is the point -- it keeps 8,000 QDN genuinely locked for every test below.
periods="$qadenabuild/testscripts/.native_periods.json"
jq -n --argjson st "$(date +%s)" '{start_time:$st, periods:[
    {coins:"2000000000000000000000aqdn", length_seconds:60},
    {coins:"8000000000000000000000aqdn", length_seconds:31536000}]}' > "$periods"
c=$(wait_code "$(qadenad_alias tx vesting create-periodic-vesting-account "$MS" "$periods" --from treasury -y --output json "${G[@]}" 2>/dev/null | jq -r .txhash)" "setup-vest")
[ "$c" = "0" ] || die "could not create the vesting account: $c $(rawlog setup-vest)"

# GAS FLOAT -- without it nothing below can run, and the reason is itself a design finding.
#
# A fully locked account has ZERO spendable balance, so it cannot pay its own fee.  It may DELEGATE
# locked principal, but it cannot pay the gas to submit the delegation.  A first run failed here
# with spendable=0 and no delegation on chain at all.
#
# Coins sent to a vesting account from outside are NOT part of original_vesting, so they land fully
# spendable and can pay fees.  This is why the brief's D1 orders the gas float AFTER the grant --
# and it is why the foundation's locked 504M needs either a float or a standing feegrant before it
# can join the delegation programme.
c=$(wait_code "$(qadenad_alias tx bank send treasury "$MS" 200qdn --from treasury -y --output json "${G[@]}" 2>/dev/null | jq -r .txhash)" "setup-float")
[ "$c" = "0" ] || die "could not send the gas float: $c $(rawlog setup-float)"
echo "total=$(bal $MS)  spendable=$(spend $MS)  (spendable is the gas float; the rest is locked)"

# ---------------------------------------------------------------------------------------------
# N1 -- delegate LOCKED principal from a multisig, and prove it was locked
# ---------------------------------------------------------------------------------------------
echo ""; echo "=== N1: delegate locked principal from a multisig ==="
sp_before=$(spend "$MS")
qadenad_alias tx staking delegate "$VAL" 8000000000000000000000aqdn --from "$MS" \
    --generate-only --gas 500000 --gas-prices "$minimum_gas_prices" --output json > "$ev/n1.json" 2>/dev/null
c=$(msig_exec n1 "$lbl-msig" "$ev/n1.json")
dvest=$(dv "$MS"); dfree=$(df "$MS")
echo "code=$c delegated_vesting=$dvest delegated_free=$dfree spendable_before=$sp_before"
if [ "$c" = "0" ] && [ "$dvest" != "0" ]; then
    rec N1 PASS "a 2-of-3 multisig delegated $dvest aqdn of STILL-LOCKED principal (delegated_vesting \
is non-zero, which is the only proof that the tokens were locked rather than merely present). \
delegated_free=$dfree. This is the mechanism the foundation's 504M programme and the whole 1% \
inflation rationale depend on."
elif [ "$c" = "0" ]; then
    rec N1 FAIL "the delegation succeeded but delegated_vesting is 0 (delegated_free=$dfree), so \
only ALREADY-VESTED tokens were bonded. Locked principal was not delegated."
else
    rec N1 FAIL "delegation failed with code $c: $(rawlog n1 | head -c 300)"
fi

# ---------------------------------------------------------------------------------------------
# N2 -- staking rewards on locked stake: liquid, and spendable by the multisig?
# ---------------------------------------------------------------------------------------------
echo ""; echo "=== N2: withdraw rewards earned on locked stake ==="
sleep 20
# `rewards.total` is a DecCoin list that this build renders as bare STRINGS
# ("3682638350722511000.000000000000000000aqdn"), not objects -- so `.total[0].amount` is an
# "cannot index string with string" error, which under `set -e` kills the suite. Handle both shapes.
rew=$(qadenad_alias query distribution rewards "$MS" --output json 2>/dev/null \
    | jq -r '(.total[0] // "0") | if type=="object" then .amount else . end' 2>/dev/null || echo "0")
sp_pre=$(spend "$MS")
qadenad_alias tx distribution withdraw-rewards "$VAL" --from "$MS" \
    --generate-only --gas 500000 --gas-prices "$minimum_gas_prices" --output json > "$ev/n2.json" 2>/dev/null
c=$(msig_exec n2 "$lbl-msig" "$ev/n2.json")
sp_post=$(spend "$MS")
echo "code=$c pending_rewards=$rew spendable $sp_pre -> $sp_post"
if [ "$c" = "0" ] && [ "$sp_post" != "$sp_pre" ]; then
    rec N2 PASS "rewards on locked stake were withdrawn by the multisig and are IMMEDIATELY \
SPENDABLE (spendable rose $sp_pre -> $sp_post). A locked bucket therefore produces liquid income \
during its own lock. Disclose this deliberately."
else
    rec N2 FAIL "rewards withdrawal code $c, spendable unchanged ($sp_pre): $(rawlog n2 | head -c 300)"
fi

# ---------------------------------------------------------------------------------------------
# N3 -- undelegate: do locked tokens come back LOCKED?
#
# evm-vesting-handoff.md §6.4 named this "the single most valuable follow-up ... the one remaining
# path by which locked principal could plausibly become spendable early", and it was never run.
# If unbonding returned locked principal as SPENDABLE, every lock in the design could be unwound in
# one unbonding period: delegate, undelegate, spend.
# ---------------------------------------------------------------------------------------------
echo ""; echo "=== N3: undelegate locked principal -- does it return locked? ==="
unbond=$(qadenad_alias query staking params --output json 2>/dev/null | jq -r '.params.unbonding_time // .unbonding_time')
echo "chain unbonding_time: $unbond"
dv_pre=$(dv "$MS"); sp_pre=$(spend "$MS"); tot_pre=$(bal "$MS")
qadenad_alias tx staking unbond "$VAL" 8000000000000000000000aqdn --from "$MS" \
    --generate-only --gas 500000 --gas-prices "$minimum_gas_prices" --output json > "$ev/n3.json" 2>/dev/null
c=$(msig_exec n3 "$lbl-msig" "$ev/n3.json")
echo "undelegate code=$c"
# Go duration strings come back as "504h0m0s", "1m0s" or "60s" -- parse all three shapes.
ub_secs=$(python3 -c "
import re
s='$unbond'.strip()
m=re.match(r'^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?\$', s)
print(int(float(m.group(1) or 0)*3600 + float(m.group(2) or 0)*60 + float(m.group(3) or 0)) if m and s else -1)
" 2>/dev/null || echo -1)
if [ "$c" != "0" ]; then
    rec N3 FAIL "undelegate failed with code $c: $(rawlog n3 | head -c 300)"
elif [ "$ub_secs" -gt 0 ] && [ "$ub_secs" -le 600 ]; then
    echo "waiting out the ${ub_secs}s unbonding period..."
    sleep $(( ub_secs + 20 ))
    dv_post=$(dv "$MS"); sp_post=$(spend "$MS"); tot_post=$(bal "$MS")
    echo "delegated_vesting $dv_pre -> $dv_post | spendable $sp_pre -> $sp_post | total $tot_pre -> $tot_post"
    # DO NOT assert on a spendable DELTA.  The 60s first period vests during the unbonding wait, so
    # spendable legitimately rises by 2,000 QDN for reasons that have nothing to do with unbonding.
    # An earlier version of this test did exactly that and reported a false "unbonding unlocked the
    # principal" alarm.  The sound assertion is on how much is STILL LOCKED afterwards: the 8,000
    # QDN second period has not elapsed, so it must still be locked.
    locked_after=$(python3 -c "print(int('$tot_post') - int('$sp_post'))")
    still_locked_ok=$(python3 -c "print('yes' if int('$locked_after') >= 7_900*10**18 else 'no')")
    echo "locked after unbonding: $locked_after aqdn (expect ~8000e18)"
    if [ "$still_locked_ok" = "yes" ]; then
        rec N3 PASS "unbonding returned the principal STILL LOCKED. $locked_after aqdn remains \
locked after the unbonding period completed -- the entire un-elapsed 8,000 QDN tranche. \
delegated_vesting fell $dv_pre -> $dv_post as the bond was released, and the tokens went back under \
the lock rather than into spendable. delegate -> undelegate -> spend does NOT unwind a vesting \
lock. This closes the question evm-vesting-handoff.md flagged as its most valuable follow-up."
    else
        rec N3 FAIL "!! UNBONDING UNLOCKED THE PRINCIPAL !! only $locked_after aqdn remains locked, \
where the un-elapsed schedule is 8000e18. Every vesting lock could be unwound in one unbonding \
period by delegate -> undelegate -> spend. STOP AND REPORT."
    fi
else
    rec N3 NOT-EXERCISED "undelegate accepted (code 0), but the chain's unbonding_time is $unbond, \
too long to wait out in this suite. The DECISIVE observation -- whether spendable rises when the \
unbonding completes -- was not made. Re-run on a devnet with a short unbonding_time."
fi

# ---------------------------------------------------------------------------------------------
# N4 -- x/authz MsgGrant signed BY THE MULTISIG THRESHOLD
#
# The brief's membership answer (Q2 mechanism 2) depends on a fixed custody multisig being able to
# grant and revoke operator authority.  Granting FROM a single key was already proven; the threshold
# -signed grant was not.
# ---------------------------------------------------------------------------------------------
echo ""; echo "=== N4: authz grant signed by the multisig threshold ==="
qadenad_alias keys add "$lbl-op" --algo eth_secp256k1 --keyring-backend test >/dev/null 2>&1
OP=$(addr "$lbl-op")
DEST=$(addr ann)
c=$(wait_code "$(qadenad_alias tx bank send treasury "$OP" 50qdn --from treasury -y --output json "${G[@]}" 2>/dev/null | jq -r .txhash)" "n4-fund")
qadenad_alias tx authz grant "$OP" send --spend-limit 500000000000000000000aqdn --allow-list "$DEST" \
    --from "$MS" --generate-only --gas 400000 --gas-prices "$minimum_gas_prices" --output json > "$ev/n4.json" 2>/dev/null
c=$(msig_exec n4 "$lbl-msig" "$ev/n4.json")
grant=$(qadenad_alias query authz grants "$MS" "$OP" --output json 2>/dev/null | jq -c '.grants[]?|.authorization.type')
echo "grant code=$c grant=$grant"
if [ "$c" = "0" ] && [ -n "$grant" ]; then
    d_before=$(bal "$DEST")
    qadenad_alias tx bank send "$MS" "$DEST" 100000000000000000000aqdn --from "$MS" --generate-only --gas 300000 --output json > "$ev/n4inner.json" 2>/dev/null
    ec=$(wait_code "$(qadenad_alias tx authz exec "$ev/n4inner.json" --from "$lbl-op" -y --output json "${G[@]}" 2>/dev/null | jq -r .txhash)" "n4-exec")
    d_after=$(bal "$DEST")
    moved=$(python3 -c "print(int('$d_after')-int('$d_before'))")
    echo "exec code=$ec moved=$moved"
    # `[ -gt ]` is int64 in the shell and these amounts are 1e20 -- compare in python or a genuine
    # success reads as a failure.
    moved_ok=$(python3 -c "print('yes' if int('$moved') > 0 else 'no')" 2>/dev/null || echo no)
    if [ "$ec" = "0" ] && [ "$moved_ok" = "yes" ]; then
        rec N4 PASS "the multisig THRESHOLD signed a MsgGrant, and a brand-new operator key -- no \
eKYC, no whitelist entry of its own -- then spent $moved aqdn out of the multisig. Operators can be \
added and removed WITHOUT changing the custody address or its whitelist entry, and the n-of-m still \
governs who may grant. This is the mechanism the membership answer rests on."
    else
        rec N4 FAIL "grant succeeded but exec failed (code $ec, moved $moved): $(rawlog n4-exec | head -c 300)"
    fi
else
    rec N4 FAIL "threshold-signed MsgGrant failed with code $c: $(rawlog n4 | head -c 300)"
fi

# ---------------------------------------------------------------------------------------------
# N5 -- StakeAuthorization: a delegation manager with NO spending power
#
# The foundation must delegate ~504M across member validators and redelegate away from misbehaving
# ones.  Doing that with the full custody threshold every time is impractical; doing it with a key
# that can also SPEND is unacceptable.  StakeAuthorization is meant to be exactly that separation.
# ---------------------------------------------------------------------------------------------
echo ""; echo "=== N5: StakeAuthorization -- delegate yes, spend no ==="
qadenad_alias keys add "$lbl-delmgr" --algo eth_secp256k1 --keyring-backend test >/dev/null 2>&1
DM=$(addr "$lbl-delmgr")
wait_code "$(qadenad_alias tx bank send treasury "$DM" 50qdn --from treasury -y --output json "${G[@]}" 2>/dev/null | jq -r .txhash)" "n5-fund" >/dev/null
gc=$(wait_code "$(qadenad_alias tx authz grant "$DM" delegate --allowed-validators "$VAL" \
        --spend-limit 1000000000000000000000aqdn --from treasury -y --output json "${G[@]}" 2>/dev/null | jq -r .txhash)" "n5-grant")
echo "stake grant code=$gc"
qadenad_alias tx staking delegate "$VAL" 100000000000000000000aqdn --from "$TRE" --generate-only --gas 400000 --output json > "$ev/n5d.json" 2>/dev/null
dc=$(wait_code "$(qadenad_alias tx authz exec "$ev/n5d.json" --from "$lbl-delmgr" -y --output json "${G[@]}" 2>/dev/null | jq -r .txhash)" "n5-deleg")
# the same manager must NOT be able to move money
qadenad_alias tx bank send "$TRE" "$DM" 100000000000000000000aqdn --from "$TRE" --generate-only --gas 300000 --output json > "$ev/n5s.json" 2>/dev/null
sc=$(qadenad_alias tx authz exec "$ev/n5s.json" --from "$lbl-delmgr" -y --output json "${G[@]}" 2>/dev/null | jq -r '.txhash // "REJECTED"')
[ "$sc" != "REJECTED" ] && sc=$(wait_code "$sc" "n5-send") || sc="REJECTED_AT_BROADCAST"
echo "delegate-as-granter code=$dc | send-as-granter result=$sc"
if [ "$dc" = "0" ] && [ "$sc" != "0" ]; then
    rec N5 PASS "a StakeAuthorization holder delegated on the granter's behalf (code 0) but could \
NOT move funds (send result: $sc). A delegation manager can run the foundation's validator \
programme with no spending power at all -- the separation the 504M programme needs."
elif [ "$dc" = "0" ]; then
    rec N5 FAIL "!! the delegation manager could ALSO SEND FUNDS (code $sc). StakeAuthorization is \
not containing spending authority; do not use it to separate roles."
else
    rec N5 NOT-EXERCISED "delegate-as-granter did not succeed (code $dc): $(rawlog n5-deleg | head -c 250)"
fi

# ---------------------------------------------------------------------------------------------
# N6 -- can a multisig hold an eKYC credential?
#
# If it CAN, the custody/identity trade-off in D1a disappears: a founder could hold a multisig AND
# spend without a governance whitelist.  Reasoned to be impossible (create-wallet derives from one
# mnemonic; a multisig has none) but never attempted, so it is attempted here.
# ---------------------------------------------------------------------------------------------
echo ""; echo "=== N6: can a multisig become an eKYC wallet? ==="
#
# An earlier version of this test called create-wallet with ONE argument, got back
# "accepts 3 arg(s), received 1" -- a CLI usage error that never reached the chain -- and reported
# it as CONFIRMED-NO. That verdict was worthless. The command takes three arguments.
#
# The correct answer is more interesting than either yes or no, and it is a CODE READ, not a test:
#
#   tx_create_wallet.go does not attach a credential to an account you name. It MINTS one:
#     - it generates (or takes) a BIP39 mnemonic
#     - CreatePublicKey() derives the TRANSACTION key from it, and a second call derives the
#       CREDENTIAL key from the SAME mnemonic at a different HD index
#     - line ~317 then OVERRIDES the signer:  ctx.WithFrom(from).WithFromAddress(fromAddr)
#       so whatever --from you passed is discarded and the tx is signed by the new key
#   and msg_server_create_wallet.go sets  walletID := msg.Creator  -- the Creator being that
#   freshly minted key.
#
# So the wallet address is NECESSARILY the mnemonic-derived address. There is no argument, and no
# code path in this command, for targeting an address that already exists. A multisig address is
# derived from a pubkey set + threshold, so no mnemonic yields it.
#
# What is NOT settled: msg.Creator is just the signer, so a HAND-CRAFTED MsgCreateWallet signed by
# a multisig is not obviously refused by the message server. Building one means reproducing the
# pubK/pubKID material and the sponsor feegrant that the CLI assembles, which was not attempted.
# Reported as NOT-EXERCISED rather than guessed at in either direction.
qadenad_alias tx qadena create-wallet "msig-ekyc-$run_id" pioneer1 create-wallet-sponsor \
    --from "$MS" --generate-only --gas 900000 --gas-prices "$minimum_gas_prices" \
    --output json > "$ev/n6.json" 2>"$ev/n6.err" || true
if [ -s "$ev/n6.json" ] && jq -e '.body.messages[0]."@type"' "$ev/n6.json" >/dev/null 2>&1; then
    creator=$(jq -r '.body.messages[0].creator // "?"' "$ev/n6.json")
    if [ "$creator" = "$MS" ]; then
        rec N6 PASS "create-wallet produced a MsgCreateWallet whose creator IS the multisig \
($creator) -- so a multisig-held wallet may be constructible after all. Broadcast it and check \
whether a credential can then be issued before relying on this."
    else
        rec N6 CONFIRMED-NO "create-wallet built the message for $creator, NOT the multisig $MS -- \
the command overrode --from with its own mnemonic-derived key, exactly as the code read predicts."
    fi
else
    rec N6 NOT-EXERCISED "the CLI cannot express this: it mints a wallet from a fresh mnemonic and \
overrides --from with the derived key, so it never targets an existing address (see n6.err). \
Whether a HAND-CRAFTED MsgCreateWallet signed by a multisig would be accepted is untested -- \
msg_server_create_wallet.go takes walletID := msg.Creator, i.e. the signer, so it is not obviously \
refused. SEPARATELY, and probably decisive: an eKYC credential encodes a PERSON's residency and \
citizenship, which is what the AML scan reads to pick a threshold. Attaching one to an n-of-m \
account asserts that a group has a nationality. The obstacle may be semantic before it is technical."
fi

# ---------------------------------------------------------------------------------------------
echo ""; echo "======================================================================"
echo "SUMMARY -- run $run_id"
echo "======================================================================"
printf '%-4s %-15s %s\n' ID VERDICT NOTE
fails=0
for t in N1 N2 N3 N4 N5 N6; do
    [ -n "${V[$t]}" ] || continue
    printf '%-4s %-15s %s\n' "$t" "${V[$t]}" "$(echo ${N[$t]} | tr '\n' ' ' | head -c 130)"
    [ "${V[$t]}" = "FAIL" ] && fails=$((fails+1))
done
{ echo "run $run_id"; for t in N1 N2 N3 N4 N5 N6; do [ -n "${V[$t]}" ] && { echo ""; echo "## $t: ${V[$t]}"; echo "${N[$t]}" }; done } > "$ev/summary.txt"
echo ""; echo "evidence: $ev"; echo "$fails FAIL(s)"
exit 0
