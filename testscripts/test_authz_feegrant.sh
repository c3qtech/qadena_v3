#!/bin/zsh
#
# Proves the "Option A" toll-free VERITAS architecture end to end: the Qadena foundation pays for
# everything, and SEC holds NO BALANCE AT ALL -- not for users' transactions, and not even for its
# own administrative ones.
#
# This is testscripts/test_token_gating.sh case A6 plus one more layer.  A6 already proves that a
# zero-balance account can transact because a sponsor pays.  What it does not prove, and what the
# whole VERITAS design rests on, is the step above that:
#
#     SEC issues a fee allowance AS THE FOUNDATION (via authz MsgExec),
#     while the foundation ALSO pays for that very MsgExec.
#
# Why this needs proving.  Fee grants DO NOT NEST -- cosmos-sdk x/auth/ante/fee.go sets
# deductFeesFrom to the granter's own account, so the granter must hold the balance itself and
# cannot in turn be covered by someone else.  That rules out the obvious design (foundation funds a
# SEC sponsor, SEC grants to users): the SEC sponsor would need a real balance, which is the
# treasury we are trying to eliminate.  The foundation must therefore be the DIRECT granter on
# every fee-paying transaction.
#
# But MsgGrantAllowance is signed by the GRANTER, so somebody has to sign as the foundation every
# time a new user wallet appears.  Handing SEC a foundation key just relocates the treasury.  authz
# is the way out: the foundation authorises SEC to send MsgGrantAllowance on its behalf, SEC wraps
# each grant in MsgExec, and SEC ends up holding a revocable permission instead of money.
#
# Each half of that is ordinary Cosmos.  The COMBINATION has never been run on this chain, and
# everything else in the design depends on it -- so it is proved here, with the CLI, before any
# app-server code is written.  A failure here is just as useful as a pass: it would mean the
# ante-handler fee exemption is the only route.
#
# THE ASSERTION IS BALANCES, NOT EXIT CODES.  See the gas price note at step 4.
#
# Idempotent: throwaway keys and documents are per-run, and the grants are revoked at the end.
#
# Run AFTER testscripts/setup.sh (needs treasury, testdsvssrvprv and the users.json identities).

# NOTE: setup_env.sh sets SCRIPT_DIR itself (to scripts/), clobbering anything of that name in the
# sourcing shell.  Use $qadenatestscripts below, as the other suites do.
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

cd $qadenabuild

run_id=$(date +%s)
label="authzfg-$run_id"
evidence="$qadenabuild/logs/authz-feegrant"
mkdir -p "$evidence"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# FORCE A REAL GAS PRICE -- do not use $minimum_gas_prices here.
#
# set_min_gas_price() derives that from the LIVE feemarket, and on an idle devnet the EIP-1559 base
# fee decays toward zero: this run saw it at 1.000000000000000007 aqdn.  At that price the fee for a
# whole transaction rounds to a rounding error, and a completely broken feegrant is indistinguishable
# from a working one -- the exact failure test_token_gating.sh A6 documents.
#
# 500000000aqdn is the node's OWN configured minimum-gas-prices (config/app.toml), so it is a price
# this chain is actually built to charge rather than an arbitrary large number.
chain_min_gas_price=$(sed -n 's/^minimum-gas-prices *= *"\(.*\)"/\1/p' "$QADENAHOME/config/app.toml" 2>/dev/null | head -1)
[ -n "$chain_min_gas_price" ] || chain_min_gas_price="500000000aqdn"
gas_flags=(--gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $chain_min_gas_price)

# ---------------------------------------------------------------------------------------------
# helpers -- same shapes as test_token_gating.sh, so behaviour matches the rest of the suite
# ---------------------------------------------------------------------------------------------

typeset -A verdict_of
typeset -A note_of
order=()

record() {   # record <id> <verdict> <note>
    verdict_of[$1]="$2"
    note_of[$1]="$3"
    order+=("$1")
    echo ""
    echo ">>> $1: $2 -- $3"
    echo ""
}

fail() { echo "HARNESS ERROR: $1"; exit 1; }

addr_of() { qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null; }

bank_aqdn() {
    local a
    a=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[] | select(.denom=="aqdn") | .amount' 2>/dev/null | head -1)
    echo "${a:-0}"
}

# tx_result <evidence-name> <args...> -- broadcasts, waits, echoes the ON-CHAIN result code.
#
# STDERR IS REDIRECTED TO A FILE, NEVER FOLDED INTO STDOUT.  `--gas auto` writes "gas estimate: N"
# to stderr; capturing 2>&1 puts that line inside the JSON, jq then fails, and under `set -e` the
# script dies mid-run with no verdicts.  This trap is documented in test_bank_restriction.sh and
# has already bitten test_token_gating.sh once.
tx_result() {
    local name="$1"; shift
    local out hash
    local err="$evidence/$name.stderr.txt"
    out=$(qadenad_alias "$@" --yes --output json "${gas_flags[@]}" 2>"$err") || {
        echo "BROADCAST_REJECTED"; return; }
    # THE JSON IS NOT THE WHOLE OF STDOUT.  The dsvs commands print diagnostics -- "File hash:",
    # srcWalletID, srcPubKey, the encryptedDocument byte array -- to STDOUT, ahead of the result:
    #
    #     File hash: 1e3d0cfb...
    #     srcWalletID qadena1dnayz...
    #     {"height":"0","txhash":"DB7EC5...",...}
    #
    # Feeding all of that to jq yields no txhash, and the tx is misreported as NO_TXHASH even though
    # it broadcast fine.  Take the last line that starts with '{' instead.  (This is the stdout twin
    # of the documented "gas estimate:" stderr trap handled above.)
    #
    # printf, NOT echo.  zsh's builtin echo INTERPRETS BACKSLASH ESCAPES, and sign-document's
    # srcWallet dump is thick with them (\003, \026, \n inside the protobuf text).  `echo "$out"`
    # rewrites that payload before grep ever sees it -- the JSON line stops starting with '{', the
    # txhash comes back empty, and a transaction that broadcast perfectly well is reported as
    # NO_TXHASH.  test_token_gating.sh uses echo here and gets away with it only because wasm
    # output contains no backslashes.
    local json
    json=$(printf '%s\n' "$out" | grep '^{' | tail -1)
    hash=$(printf '%s\n' "$json" | jq -r '.txhash' 2>/dev/null)
    if [ -z "$hash" ] || [ "$hash" = "null" ]; then echo "NO_TXHASH"; return; fi
    qadenad_alias query wait-tx "$hash" --timeout 90s > /dev/null 2>&1 || true
    qadenad_alias query tx "$hash" --output json 2>/dev/null > "$evidence/$name.tx.json" || true
    if [ -s "$evidence/$name.tx.json" ]; then
        jq -r '.code // "UNKNOWN"' "$evidence/$name.tx.json" 2>/dev/null || echo "UNPARSEABLE"
    else
        echo "NO_RESULT"
    fi
}

tx_rawlog() { [ -s "$evidence/$1.tx.json" ] && jq -r '.raw_log // ""' "$evidence/$1.tx.json" 2>/dev/null || echo ""; }

# a brand-new eth_secp256k1 key, never funded
fresh_key() {
    qadenad_alias keys add "$1" --algo eth_secp256k1 --keyring-backend test --output json >/dev/null 2>&1
    addr_of "$1"
}

echo "======================================================================"
echo "AUTHZ + FEEGRANT -- toll-free VERITAS, run $run_id"
echo "======================================================================"
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable"
for w in treasury testdsvssrvprv victor-eph1; do
    addr_of "$w" > /dev/null 2>&1 || fail "$w not in the keyring -- run testscripts/setup.sh first"
done
echo "gas price forced to: $chain_min_gas_price (live feemarket reads $minimum_gas_prices)"

# ---------------------------------------------------------------------------------------------
# roles
#
# A DEDICATED foundation key, funded from treasury, rather than treasury itself.  treasury signs
# half the suite, so asserting "its balance fell" would prove nothing about who paid for OUR
# transactions.  A key that only this test spends from makes the balance delta unambiguous.
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 1. roles ==="
foundation_key="$label-foundation"
secadmin_key="$label-secadmin"

foundation_addr=$(fresh_key "$foundation_key")
secadmin_addr=$(fresh_key "$secadmin_key")
user_addr=$(addr_of victor-eph1)

[ -n "$foundation_addr" ] || fail "could not create foundation key"
[ -n "$secadmin_addr" ]   || fail "could not create secadmin key"
[ -n "$user_addr" ]       || fail "could not resolve victor-eph1"
# authz refuses a self-grant (ErrGranteeIsGranter); these must be distinct.
[ "$foundation_addr" != "$secadmin_addr" ] || fail "foundation and secadmin must differ"

echo "foundation : $foundation_addr"
echo "secadmin   : $secadmin_addr   (must end at ZERO)"
echo "user       : $user_addr   (victor-eph1, must end at ZERO)"

# Fund ONLY the foundation.  1e24 aqdn is ample for a handful of txs at 5e8 aqdn/gas.
fund_code=$(tx_result "01-fund" tx bank send treasury "$foundation_addr" 1000000000000000000000000aqdn --from treasury)
[ "$fund_code" = "0" ] || fail "could not fund foundation (code $fund_code): $(tx_rawlog 01-fund)"

foundation_before=$(bank_aqdn "$foundation_addr")
secadmin_before=$(bank_aqdn "$secadmin_addr")
user_before=$(bank_aqdn "$user_addr")
echo "balances before -- foundation=$foundation_before secadmin=$secadmin_before user=$user_before"

# ---------------------------------------------------------------------------------------------
# 2. foundation authorises SEC to issue fee allowances on its behalf
#
# GenericAuthorization accepts unconditionally (x/authz/generic_authorization.go: Accept returns
# {Accept: true} without inspecting the message).  It cannot cap the amount or restrict who the
# allowance goes to -- the only bounds available are the ones SEC puts on the grants it issues, at
# step 4.  That asymmetry is a real property of this design, not an oversight here.
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 2. foundation -> secadmin: authz to send MsgGrantAllowance ==="
authz_expiry=$(( $(date +%s) + 3600 ))
authz_code=$(tx_result "02-authz-grant" tx authz grant "$secadmin_addr" generic \
    --msg-type /cosmos.feegrant.v1beta1.MsgGrantAllowance \
    --expiration "$authz_expiry" --from "$foundation_key")
if [ "$authz_code" = "0" ]; then
    record "AUTHZ-GRANT" "PASS" "foundation authorised secadmin for MsgGrantAllowance"
else
    record "AUTHZ-GRANT" "FAIL" "code $authz_code: $(tx_rawlog 02-authz-grant)"
    fail "cannot continue without the authorization"
fi

granted=$(qadenad_alias query authz grants "$foundation_addr" "$secadmin_addr" --output json 2>/dev/null \
    | jq -r '.grants[0].authorization.msg // .grants[0].authorization.value.msg // "none"' 2>/dev/null)
echo "authorization on chain: $granted"

# ---------------------------------------------------------------------------------------------
# 3. foundation pays for SEC's OWN transactions
#
# MsgExec is signed by the grantee, so the MsgExec at step 4 is charged to secadmin.  Without this
# grant secadmin needs a balance -- which is precisely the SEC treasury this design exists to
# remove -- and step 4 fails with insufficient funds, an error that reads like an authz problem and
# is not.  This one static grant is what keeps secadmin at exactly zero.
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 3. foundation -> secadmin: feegrant for MsgExec ==="
rfc3339_expiry=$(date -u -v+1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
exec_fg_code=$(tx_result "03-feegrant-secadmin" tx feegrant grant "$foundation_addr" "$secadmin_addr" \
    --allowed-messages /cosmos.authz.v1beta1.MsgExec \
    --spend-limit 100000000000000000000000aqdn \
    --expiration "$rfc3339_expiry" \
    --from "$foundation_key")
if [ "$exec_fg_code" = "0" ]; then
    record "FEEGRANT-SECADMIN" "PASS" "foundation will pay secadmin's MsgExec fees"
else
    record "FEEGRANT-SECADMIN" "FAIL" "code $exec_fg_code: $(tx_rawlog 03-feegrant-secadmin)"
    fail "cannot continue without the MsgExec allowance"
fi

# ---------------------------------------------------------------------------------------------
# 4. THE STEP THIS SCRIPT EXISTS FOR
#
# SEC issues the user's allowance while ACTING AS the foundation, and the foundation pays for that
# action too.  Two commands:
#
#   a) build MsgGrantAllowance with --generate-only so its granter field is the FOUNDATION.
#      This is not a stylistic choice.  authz resolves the grant on the INNER message's signer
#      (x/authz/keeper/keeper.go DispatchActions: granter = signers[0]), so a message built
#      --from secadmin names secadmin as granter, matches no authorization, and is rejected with
#      ErrNoAuthorizationFound.
#
#   b) exec it as secadmin, with --fee-granter pointing back at the foundation.
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 4. secadmin issues the user's allowance AS the foundation ==="
inner="$workdir/inner_grant.json"
qadenad_alias tx feegrant grant "$foundation_addr" "$user_addr" \
    --allowed-messages /qadena.dsvs.MsgSignDocument \
    --spend-limit 10000000000000000000000aqdn \
    --expiration "$rfc3339_expiry" \
    --from "$foundation_addr" --generate-only > "$inner" 2>"$evidence/04-generate.stderr.txt" \
    || fail "could not generate the inner MsgGrantAllowance"

inner_granter=$(jq -r '.body.messages[0].granter // "?"' "$inner" 2>/dev/null)
echo "inner msg granter: $inner_granter"
[ "$inner_granter" = "$foundation_addr" ] || fail "inner granter is $inner_granter, expected the foundation"
cp "$inner" "$evidence/04-inner_grant.json"

exec_code=$(tx_result "04-authz-exec" tx authz exec "$inner" \
    --from "$secadmin_key" --fee-granter "$foundation_addr")

if [ "$exec_code" = "0" ]; then
    record "AUTHZ-EXEC" "PASS" "secadmin issued a foundation-granted allowance, foundation paid for it"
else
    record "AUTHZ-EXEC" "FAIL" "code $exec_code: $(tx_rawlog 04-authz-exec)"
fi

user_allowance=$(qadenad_alias query feegrant grant "$foundation_addr" "$user_addr" --output json 2>/dev/null \
    | jq -r '.allowance.granter // "none"' 2>/dev/null)
echo "user allowance granter on chain: $user_allowance"
if [ "$user_allowance" = "$foundation_addr" ]; then
    record "ALLOWANCE-OWNER" "PASS" "allowance for the user is owned by the foundation, not SEC"
else
    record "ALLOWANCE-OWNER" "FAIL" "expected granter $foundation_addr, got $user_allowance"
fi

# ---------------------------------------------------------------------------------------------
# 5. the real VERITAS transaction: a user signs a document, paying nothing
#
# Document ids and CONTENT are per-run.  A document is keyed by its content hash, so re-creating
# one from the same bytes fails with "Hash already exists" even under a fresh id -- embedding
# run_id in the content is what makes this re-runnable (same reasoning as test_dsvs.sh).
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 5. victor signs a document, foundation pays ==="
docid="authzfg-doc-$run_id"
doctype="ByLaws"
company="C3Q Technologies, Inc."
doc1="$workdir/doc_v1.txt"
doc2="$workdir/doc_v2.txt"
printf 'authz feegrant regression %s -- version 1\n' "$run_id" > "$doc1"
printf 'authz feegrant regression %s -- version 2 (signed)\n' "$run_id" > "$doc2"

sig_email=$(jq -r '.[] | select(.name=="victor") | .email' "$qadenatestdata/users.json")
sig_phone=$(jq -r '.[] | select(.name=="victor") | .phone' "$qadenatestdata/users.json")
[ -n "$sig_email" ] || fail "could not read victor's email from users.json"
echo "signatory: $sig_email / $sig_phone"

# Signing requires the signer's eph wallet to be a REGISTERED authorized signatory (setup.sh does
# this via provider_scripts/create_user.sh).  Checked explicitly because the failure otherwise
# surfaces from sign-document as a generic rejection, several steps after the missing setup.
sig_count=$(qadenad_alias query dsvs list-authorized-signatory 2>/dev/null | sed -n 's/^Count: *\([0-9]*\)/\1/p' | head -1)
[ "${sig_count:-0}" -gt 0 ] || fail "no authorized signatories registered -- run testscripts/setup.sh first"
echo "authorized signatories on chain: $sig_count"

create_code=$(tx_result "05-create-doc" tx dsvs create-document "$docid" "$doctype" "$company" "$doc1" \
    "$sig_email" "$sig_phone" --from testdsvssrvprv)
[ "$create_code" = "0" ] || fail "create-document failed (code $create_code): $(tx_rawlog 05-create-doc)"
echo "document $docid created"

sign_code=$(tx_result "06-sign-doc" tx dsvs sign-document "$doc1" "$doc2" "$sig_email" "$sig_phone" \
    --from victor-eph1 --fee-granter "$foundation_addr")
if [ "$sign_code" = "0" ]; then
    record "SIGN-DOCUMENT" "PASS" "zero-balance user signed a real document"
else
    record "SIGN-DOCUMENT" "FAIL" "code $sign_code: $(tx_rawlog 06-sign-doc)"
fi

# ---------------------------------------------------------------------------------------------
# 6. balances -- the actual claim
#
# Exit codes are not the assertion.  The feemarket base fee decays toward zero on an idle devnet
# (EIP-1559 with under-full blocks); test_token_gating.sh records it reading 0.000000000000000007
# aqdn on a quiet chain, at which "a broken feegrant is indistinguishable from a working one,
# because the fee rounds to nothing".  Every tx above therefore forces --gas-prices, and the proof
# is that the FOUNDATION'S BALANCE FELL while the other two did not move.
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 6. balances ==="
foundation_after=$(bank_aqdn "$foundation_addr")
secadmin_after=$(bank_aqdn "$secadmin_addr")
user_after=$(bank_aqdn "$user_addr")

spent=$(python3 -c "print(int('${foundation_before:-0}') - int('${foundation_after:-0}'))" 2>/dev/null || echo 0)

printf '%-12s before %-30s after %-30s\n' "foundation" "$foundation_before" "$foundation_after"
printf '%-12s before %-30s after %-30s\n' "secadmin"   "$secadmin_before"   "$secadmin_after"
printf '%-12s before %-30s after %-30s\n' "user"       "$user_before"       "$user_after"
echo "foundation spent: $spent aqdn"

if [ "$spent" -gt 0 ] 2>/dev/null; then
    record "FOUNDATION-PAID" "PASS" "foundation balance fell by $spent aqdn"
else
    record "FOUNDATION-PAID" "FAIL" "foundation balance did not fall -- nobody paid a real fee"
fi

if [ "$secadmin_after" = "0" ]; then
    record "SEC-ZERO-BALANCE" "PASS" "secadmin never held or spent a token"
else
    record "SEC-ZERO-BALANCE" "FAIL" "secadmin holds $secadmin_after aqdn -- this is a SEC treasury"
fi

if [ "$user_after" = "$user_before" ]; then
    record "USER-PAID-NOTHING" "PASS" "user balance unchanged at $user_after"
else
    record "USER-PAID-NOTHING" "FAIL" "user balance moved: $user_before -> $user_after"
fi

# ---------------------------------------------------------------------------------------------
# 7. the foundation can withdraw the authority
#
# The point of authz over handing SEC a key: it is revocable.  After the revoke, the SAME exec must
# fail -- otherwise "revocable" is a claim, not a property.
# ---------------------------------------------------------------------------------------------
echo ""
echo "=== 7. revoke, and prove the authority is gone ==="
revoke_code=$(tx_result "07-authz-revoke" tx authz revoke "$secadmin_addr" \
    /cosmos.feegrant.v1beta1.MsgGrantAllowance --from "$foundation_key")
echo "revoke code: $revoke_code"

# A DIFFERENT grantee, so this cannot fail merely because the previous allowance already exists.
probe_addr=$(fresh_key "$label-probe")
qadenad_alias tx feegrant grant "$foundation_addr" "$probe_addr" \
    --allowed-messages /qadena.dsvs.MsgSignDocument \
    --spend-limit 10000000000000000000000aqdn \
    --expiration "$rfc3339_expiry" \
    --from "$foundation_addr" --generate-only > "$workdir/probe_grant.json" 2>/dev/null || true

after_revoke_code=$(tx_result "08-exec-after-revoke" tx authz exec "$workdir/probe_grant.json" \
    --from "$secadmin_key" --fee-granter "$foundation_addr")
echo "exec-after-revoke code: $after_revoke_code"
if [ "$after_revoke_code" = "0" ]; then
    record "REVOKE-EFFECTIVE" "FAIL" "secadmin could still act as the foundation after revoke"
else
    record "REVOKE-EFFECTIVE" "PASS" "authority withdrawn -- exec rejected ($after_revoke_code)"
fi

# tidy up the remaining fee allowances so re-runs start clean
qadenad_alias tx feegrant revoke "$foundation_addr" "$secadmin_addr" --from "$foundation_key" \
    --yes --output json "${gas_flags[@]}" >/dev/null 2>&1 || true
qadenad_alias tx feegrant revoke "$foundation_addr" "$user_addr" --from "$foundation_key" \
    --yes --output json "${gas_flags[@]}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "SUMMARY -- run $run_id"
echo "======================================================================"
failures=0
for id in "${order[@]}"; do
    printf '%-20s %-6s %s\n' "$id" "${verdict_of[$id]}" "${note_of[$id]}"
    [ "${verdict_of[$id]}" = "FAIL" ] && failures=$((failures+1))
done
echo ""
echo "evidence: $evidence"
if [ "$failures" -eq 0 ]; then
    echo "RESULT: PASS -- Option A works. The foundation paid for everything; SEC held nothing."
    exit 0
else
    echo "RESULT: FAIL ($failures) -- see above."
    echo "If AUTHZ-EXEC failed, Option A does not work as designed and the ante-handler"
    echo "fee exemption (Option B) is the remaining route."
    exit 1
fi
