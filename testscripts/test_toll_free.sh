#!/bin/zsh
#
# Toll-free VERITAS with TWO foundation accounts, and no SEC treasury of any kind.
#
# This supersedes test_authz_feegrant.sh, which proved the mechanism but asserted the wrong thing.
# Three findings since then changed what has to be tested:
#
#   1. THE CHAIN ENDOWS EVERY WALLET.  `query qadena incentives` pays 500 QDN to a real wallet and
#      50 QDN to an ephemeral one, at creation.  So "the transaction succeeded" proves NOTHING about
#      who paid -- a wallet can fund itself for a good while out of that endowment.  The only honest
#      assertion is that the endowment is STILL EXACTLY INTACT afterwards.  That is what this script
#      asserts, to the aqdn, and it is why it can tell a working grant from a decorative one.
#
#   2. THE ALLOWLIST NEEDS TEN MESSAGE TYPES, not the six the app-server grants today.  Missing:
#      ClaimCredential, ProtectPrivateKey, SignDocument, RegisterAuthorizedSignatory.  A grant short
#      of one of these fails closed at exactly the step that needs it, so walking the whole lifecycle
#      is self-diagnosing.
#
#   3. THE TWO POPULATIONS HAVE DIFFERENT SHAPES, so they get different accounts and different
#      mechanisms:
#
#        foundation-appsvr  ->  SEC's 124 operational wallets.  A FIXED set, known at deployment.
#                               Granted DIRECTLY, one time, offline.  No authz, no delegation, no
#                               hot key, nothing running.
#
#        foundation-users   ->  user wallets.  These appear continuously (every onboarding, QR scan
#                               and key rotation mints one), so nobody can sign each grant by hand.
#                               This is the ONLY part that needs authz: foundation-users authorises
#                               secadmin to issue grants on its behalf.
#
#      The split is not bookkeeping.  It confines the unbounded GenericAuthorization -- whoever holds
#      secadmin can drain its granter -- to the user float alone.  foundation-appsvr has no
#      delegation against it at all.  Watching two balances also separates citizen activity from
#      SEC's own processing, and a divergence between them is a real anomaly signal.
#
# Run AFTER testscripts/setup.sh.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Env-defaulted: the devnet's validator is pioneer1, a launch chain names its own.
pioneer="${QADENA_PIONEER:-pioneer1}"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

cd $qadenabuild

run_id=$(date +%s)
label="tollfree-$run_id"
evidence="$qadenabuild/logs/toll-free"
mkdir -p "$evidence"
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# FORCE A REAL GAS PRICE.  $minimum_gas_prices comes from the LIVE feemarket, and on an idle devnet
# the EIP-1559 base fee decays toward zero -- observed at 1.000000000000000007 aqdn.  At that price
# every fee rounds to a rounding error and a broken feegrant is indistinguishable from a working one.
# The node's own configured floor is a price this chain is actually built to charge.
chain_min_gas_price=$(sed -n 's/^minimum-gas-prices *= *"\(.*\)"/\1/p' "$QADENAHOME/config/app.toml" 2>/dev/null | head -1)
[ -n "$chain_min_gas_price" ] || chain_min_gas_price="500000000aqdn"
gas_flags=(--gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $chain_min_gas_price)

# The ten message types a user wallet must be able to send across its whole life.  Six of these are
# what the app-server grants today; the last four are the gap.
USER_MSGS="/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet,/qadena.qadena.MsgUpdateCredential,/qadena.qadena.MsgClaimUpdatedCredential,/qadena.nameservice.MsgBindCredential,/qadena.nameservice.MsgUnbindCredential,/qadena.qadena.MsgClaimCredential,/qadena.qadena.MsgProtectPrivateKey,/qadena.dsvs.MsgSignDocument,/qadena.dsvs.MsgRegisterAuthorizedSignatory"

# What SEC's own wallets send, from the trace of every GenerateOrBroadcastTxCLISync call site.
APPSVR_MSGS="/qadena.dsvs.MsgCreateDocument,/qadena.dsvs.MsgRemoveDocument,/qadena.dsvs.MsgSignDocument,/qadena.qadena.MsgCreateCredential,/qadena.qadena.MsgRemoveCredential,/qadena.qadena.MsgSignRecoverPrivateKey"

EPH_INCENTIVE=50000000000000000000     # query qadena incentives -> createEphemeralWalletTransparentIncentive

typeset -A verdict_of; typeset -A note_of; order=()
record() { verdict_of[$1]="$2"; note_of[$1]="$3"; order+=("$1"); echo ""; echo ">>> $1: $2 -- $3"; echo ""; }
fail() { echo "HARNESS ERROR: $1"; exit 1; }
addr_of() { qadenad_alias keys show "$1" -a --keyring-backend test 2>/dev/null; }
bal() { local a; a=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[]|select(.denom=="aqdn")|.amount' 2>/dev/null | head -1); echo "${a:-0}"; }
delta() { python3 -c "print(int('${1:-0}')-int('${2:-0}'))"; }

# tx_result <name> <args...> -- broadcasts, waits, echoes the ON-CHAIN code.
#
# Two output traps, both of which have already cost a debugging cycle:
#   * stderr goes to a FILE.  `--gas auto` writes "gas estimate: N" there; folding it into stdout
#     breaks jq and, under `set -e`, kills the run mid-flight.
#   * printf, NOT echo.  zsh's echo INTERPRETS BACKSLASH ESCAPES and sign-document dumps a protobuf
#     blob full of them, which rewrites the payload before grep sees it and makes a perfectly good
#     tx report as NO_TXHASH.  The dsvs commands also print diagnostics to STDOUT ahead of the JSON,
#     hence the last '{'-line rather than the whole stream.
tx_result() {
    local name="$1"; shift
    local out hash json err="$evidence/$name.stderr.txt"
    out=$(qadenad_alias "$@" --yes --output json "${gas_flags[@]}" 2>"$err") || { echo "BROADCAST_REJECTED"; return 0; }
    json=$(printf '%s\n' "$out" | grep '^{' | tail -1)
    hash=$(printf '%s\n' "$json" | jq -r '.txhash' 2>/dev/null)
    [ -n "$hash" ] && [ "$hash" != "null" ] || { echo "NO_TXHASH"; return 0; }
    qadenad_alias query wait-tx "$hash" --timeout 90s > /dev/null 2>&1 || true
    qadenad_alias query tx "$hash" --output json 2>/dev/null > "$evidence/$name.tx.json" || true
    [ -s "$evidence/$name.tx.json" ] && jq -r '.code // "UNKNOWN"' "$evidence/$name.tx.json" 2>/dev/null || echo "NO_RESULT"
}
tx_rawlog() { [ -s "$evidence/$1.tx.json" ] && jq -r '.raw_log // ""' "$evidence/$1.tx.json" 2>/dev/null | head -c 200 || echo ""; }
fresh_key() { qadenad_alias keys add "$1" --algo eth_secp256k1 --keyring-backend test --output json >/dev/null 2>&1; addr_of "$1"; }

echo "======================================================================"
echo "TOLL-FREE VERITAS -- two foundation accounts -- run $run_id"
echo "======================================================================"
qadenad_alias status >/dev/null 2>&1 || fail "chain is not reachable"
for w in treasury testdsvssrvprv testidentitysrvprv victor victor-eph1; do
    addr_of "$w" >/dev/null 2>&1 || fail "$w not in the keyring -- run testscripts/setup.sh first"
done
echo "gas price forced to: $chain_min_gas_price   (live feemarket: $minimum_gas_prices)"

# =============================================================================================
# roles
# =============================================================================================
echo ""
echo "=== 0. roles ==="
fa_key="$label-foundation-appsvr"; fu_key="$label-foundation-users"; sa_key="$label-secadmin"
FA=$(fresh_key "$fa_key"); FU=$(fresh_key "$fu_key"); SA=$(fresh_key "$sa_key")
SP=$(addr_of testdsvssrvprv); IDP=$(addr_of testidentitysrvprv)
[ "$FA" != "$FU" ] && [ "$FU" != "$SA" ] || fail "foundation/secadmin keys must be distinct"
echo "foundation-appsvr : $FA"
echo "foundation-users  : $FU"
echo "secadmin          : $SA   (must end at ZERO)"

for k in "$fa_key" "$fu_key"; do
    a=$(addr_of "$k")
    c=$(tx_result "00-fund-$k" tx bank send treasury "$a" 1000000000000000000000000aqdn --from treasury)
    [ "$c" = "0" ] || fail "could not fund $k (code $c): $(tx_rawlog 00-fund-$k)"
done
fa_before=$(bal $FA); fu_before=$(bal $FU); sa_before=$(bal $SA)
sp_before=$(bal $SP); idp_before=$(bal $IDP)
echo "funded: appsvr=$fa_before users=$fu_before"

# =============================================================================================
# PHASE A -- SEC's own operations, paid by foundation-appsvr, NO authz anywhere
#
# SEC's operational wallets are a fixed set known at deployment, so the foundation can grant to each
# of them directly and be done.  Nothing needs to run afterwards, and no key of SEC's can spend the
# foundation's money -- only present these grants.
# =============================================================================================
echo ""
echo "=== PHASE A: SEC operations paid by foundation-appsvr ==="
expiry=$(date -u -v+1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
for pair in "sp:$SP" "idp:$IDP"; do
    nm=${pair%%:*}; ad=${pair#*:}
    c=$(tx_result "A-grant-$nm" tx feegrant grant "$FA" "$ad" \
        --allowed-messages "$APPSVR_MSGS" --spend-limit 100000000000000000000000aqdn \
        --expiration "$expiry" --from "$fa_key")
    [ "$c" = "0" ] || fail "grant to $nm failed (code $c): $(tx_rawlog A-grant-$nm)"
done
echo "granted $SP and $IDP against foundation-appsvr"

docid="tollfree-A-$run_id"
printf 'phase A %s\n' "$run_id" > "$workdir/a1.txt"
sig_email=$(jq -r '.[]|select(.name=="victor")|.email' "$qadenatestdata/users.json")
sig_phone=$(jq -r '.[]|select(.name=="victor")|.phone' "$qadenatestdata/users.json")
a_doc=$(tx_result "A-create-doc" tx dsvs create-document "$docid" ByLaws "C3Q Technologies, Inc." \
    "$workdir/a1.txt" "$sig_email" "$sig_phone" --from testdsvssrvprv --fee-granter "$FA")
[ "$a_doc" = "0" ] && record "A-CREATE-DOCUMENT" "PASS" "service provider wrote a document" \
                   || record "A-CREATE-DOCUMENT" "FAIL" "code $a_doc: $(tx_rawlog A-create-doc)"

A=$(( run_id % 100000 )); BF=$(( run_id % 99991 ))
a_cred=$(tx_result "A-create-cred" tx qadena create-credential "$A" "$BF" email-contact-info \
    "tollfree-$run_id@c3qtech.com" --from testidentitysrvprv --fee-granter "$FA")
[ "$a_cred" = "0" ] && record "A-CREATE-CREDENTIAL" "PASS" "identity provider issued a credential" \
                    || record "A-CREATE-CREDENTIAL" "FAIL" "code $a_cred: $(tx_rawlog A-create-cred)"

# A3 -- SEC signs a document itself, from the secdsvs-eph* pool (DocumentSigningQueue).
# Distinct from a citizen signing: this is SEC as a signatory, and it is the third SEC key set.
SECD=$(addr_of secdsvs-eph1)
secd_before=$(bal "$SECD")
c=$(tx_result "A-grant-secdsvs" tx feegrant grant "$FA" "$SECD" \
    --allowed-messages "$APPSVR_MSGS" --spend-limit 100000000000000000000000aqdn \
    --expiration "$expiry" --from "$fa_key")
[ "$c" = "0" ] || fail "grant to secdsvs-eph1 failed: $(tx_rawlog A-grant-secdsvs)"
sd_email=$(jq -r '.[]|select(.name=="secdsvs")|.email' "$qadenatestdata/users.json")
sd_phone=$(jq -r '.[]|select(.name=="secdsvs")|.phone' "$qadenatestdata/users.json")
printf 'phase A sec-sign %s v1\n' "$run_id" > "$workdir/as1.txt"
printf 'phase A sec-sign %s v2\n' "$run_id" > "$workdir/as2.txt"
c=$(tx_result "A-secdoc" tx dsvs create-document "tollfree-Asec-$run_id" ByLaws "C3Q Technologies, Inc." \
    "$workdir/as1.txt" "$sd_email" "$sd_phone" --from testdsvssrvprv --fee-granter "$FA")
[ "$c" = "0" ] || fail "sec-signable document failed: $(tx_rawlog A-secdoc)"
c=$(tx_result "A-secsign" tx dsvs sign-document "$workdir/as1.txt" "$workdir/as2.txt" \
    "$sd_email" "$sd_phone" --from secdsvs-eph1 --fee-granter "$FA")
secd_after=$(bal "$SECD")
if [ "$c" = "0" ] && [ "$(delta $secd_before $secd_after)" = "0" ]; then
    record "A-SEC-SIGN-DOCUMENT" "PASS" "secdsvs-eph1 signed, its own balance unmoved"
else
    record "A-SEC-SIGN-DOCUMENT" "FAIL" "code $c, secdsvs-eph1 spent $(delta $secd_before $secd_after): $(tx_rawlog A-secsign)"
fi

# A4 -- remove a document.  Only an UNSIGNED document can be removed (a fully signed one is
# permanent by design, proved in test_dsvs.sh), so this removes the one A-CREATE-DOCUMENT made and
# nobody signed -- which also tidies up after the run.
c=$(tx_result "A-remove-doc" tx dsvs remove-document "$docid" --from testdsvssrvprv --fee-granter "$FA")
[ "$c" = "0" ] && record "A-REMOVE-DOCUMENT" "PASS" "unsigned document removed, paid by foundation-appsvr" \
               || record "A-REMOVE-DOCUMENT" "FAIL" "code $c: $(tx_rawlog A-remove-doc)"

sleep 4
sp_after=$(bal $SP); idp_after=$(bal $IDP); fa_mid=$(bal $FA)
sp_d=$(delta $sp_before $sp_after); idp_d=$(delta $idp_before $idp_after); fa_d=$(delta $fa_before $fa_mid)
echo "service provider spent: $sp_d | identity provider spent: $idp_d | foundation-appsvr spent: $fa_d"
[ "$sp_d" = "0" ] && [ "$idp_d" = "0" ] \
    && record "A-SEC-WALLETS-UNTOUCHED" "PASS" "neither SEC wallet spent a token" \
    || record "A-SEC-WALLETS-UNTOUCHED" "FAIL" "sp spent $sp_d, idp spent $idp_d"
[ "$fa_d" -gt 0 ] 2>/dev/null \
    && record "A-APPSVR-FOUNDATION-PAID" "PASS" "foundation-appsvr paid $fa_d aqdn" \
    || record "A-APPSVR-FOUNDATION-PAID" "FAIL" "foundation-appsvr balance did not fall"

# =============================================================================================
# PHASE B -- a user's whole life, paid by foundation-users via authz
#
# User wallets appear continuously, so nobody can sign each grant by hand.  foundation-users
# authorises secadmin once; secadmin then issues grants AS foundation-users, and foundation-users
# pays for those MsgExec transactions too -- which is what keeps secadmin at exactly zero.
#
# THE WALLET IS CREATED DURING THIS RUN ON PURPOSE.  The chain endows a new ephemeral wallet with
# EXACTLY 50 QDN, so "still exactly 50 QDN" is positive proof a fee was paid by someone else.  A
# pre-existing wallet has already spent an unknown amount and gives nothing to compare against --
# and because the endowment would quietly cover the fee, a grant that never applied would still let
# every transaction succeed.  That is the illusion this phase is built to defeat.
#
# alexis rather than victor/kelvin: test_dsvs.sh signs as those two, and Phase C rotates whoever we
# use here, which would change their authorized signatory for every later run.
# =============================================================================================
echo ""
echo "=== PHASE B: a user's lifecycle paid by foundation-users ==="
USER=alexis
mnemonic=$(jq -r --arg n "$USER" '.[]|select(.name==$n)|.mnemonic' "$qadenatestdata/users.json")
[ -n "$mnemonic" ] && [ "$mnemonic" != "null" ] || fail "no mnemonic for $USER in users.json"
u_email=$(jq -r --arg n "$USER" '.[]|select(.name==$n)|.email' "$qadenatestdata/users.json")
u_phone=$(jq -r --arg n "$USER" '.[]|select(.name==$n)|.phone' "$qadenatestdata/users.json")

# next free ephemeral index for this user
last=$(qadenad_alias keys list --keyring-backend test --output json 2>/dev/null \
    | jq -r --arg u "$USER" '.[].name|select(startswith($u+"-eph"))' | sed "s/^$USER-eph//" | sort -n | tail -1)
NEW_IDX=$(( ${last:-1} + 1 ))
NEW_EPH="$USER-eph$NEW_IDX"
echo "creating a brand-new ephemeral wallet: $NEW_EPH (index $NEW_IDX)"

# 1. foundation-users authorises secadmin to issue allowances on its behalf
authz_exp=$(( $(date +%s) + 3600 ))
c=$(tx_result "B-authz" tx authz grant "$SA" generic \
    --msg-type /cosmos.feegrant.v1beta1.MsgGrantAllowance --expiration "$authz_exp" --from "$fu_key")
[ "$c" = "0" ] && record "B-AUTHZ-GRANT" "PASS" "foundation-users authorised secadmin" \
               || { record "B-AUTHZ-GRANT" "FAIL" "code $c: $(tx_rawlog B-authz)"; fail "cannot continue"; }

# 2. foundation-users covers secadmin's MsgExec fees -- without this secadmin needs a balance,
#    which is the SEC treasury we are removing.
c=$(tx_result "B-fg-secadmin" tx feegrant grant "$FU" "$SA" \
    --allowed-messages /cosmos.authz.v1beta1.MsgExec --spend-limit 100000000000000000000000aqdn \
    --expiration "$expiry" --from "$fu_key")
[ "$c" = "0" ] || fail "MsgExec allowance failed (code $c): $(tx_rawlog B-fg-secadmin)"

# 3. create the wallet.  Creation itself is paid by the existing create-wallet-sponsor: the address
#    is derived from mnemonic+index by the CLI, so it cannot be granted to before it exists.  From
#    here on, everything is on foundation-users.
c=$(tx_result "B-create-wallet" tx qadena create-wallet "$NEW_EPH" "$pioneer" create-wallet-sponsor \
    --link-to-real-wallet "$USER" --account-mnemonic="$mnemonic" --eph-account-index "$NEW_IDX")
[ "$c" = "0" ] || fail "create-wallet failed (code $c): $(tx_rawlog B-create-wallet)"
sleep 4
NEW_ADDR=$(addr_of "$NEW_EPH")
[ -n "$NEW_ADDR" ] || fail "could not resolve $NEW_EPH after creation"
endow=$(bal "$NEW_ADDR")
echo "$NEW_EPH = $NEW_ADDR   endowment=$endow"
[ "$endow" = "$EPH_INCENTIVE" ] \
    && record "B-ENDOWMENT-EXACT" "PASS" "new wallet holds exactly the $EPH_INCENTIVE aqdn incentive" \
    || record "B-ENDOWMENT-EXACT" "FAIL" "expected $EPH_INCENTIVE, got $endow -- later assertions lose their reference point"

# 4. secadmin issues the TEN-message grant AS foundation-users.
#    --generate-only so the inner msg's granter is the FOUNDATION: authz resolves the grant on the
#    inner message's signer, so building it --from secadmin matches no authorization.
qadenad_alias tx feegrant grant "$FU" "$NEW_ADDR" \
    --allowed-messages "$USER_MSGS" --spend-limit 10000000000000000000000aqdn \
    --expiration "$expiry" --from "$FU" --generate-only > "$workdir/inner.json" 2>/dev/null \
    || fail "could not generate the inner MsgGrantAllowance"
[ "$(jq -r '.body.messages[0].granter' "$workdir/inner.json")" = "$FU" ] \
    || fail "inner granter is not foundation-users"
cp "$workdir/inner.json" "$evidence/B-inner_grant.json"
c=$(tx_result "B-exec" tx authz exec "$workdir/inner.json" --from "$sa_key" --fee-granter "$FU")
[ "$c" = "0" ] && record "B-AUTHZ-EXEC" "PASS" "secadmin issued a 10-message grant as foundation-users" \
               || record "B-AUTHZ-EXEC" "FAIL" "code $c: $(tx_rawlog B-exec)"

# 4b. THE REAL WALLET NEEDS ITS OWN GRANT, and this is not a detail of the test.
#
# RegisterAuthorizedSignatory is broadcast from the REAL wallet, not the ephemeral one -- the SDK
# sends it from realWalletTransactionAccount (qadena_hd_wallet.dart), and the first run of this
# script proved it on chain: granting only the ephemeral wallet produced "does not allow to pay fees
# for ...: fee-grant not found".  A fee grant names ONE address, so rotation is funded on the main
# wallet or not at all.  Any real deployment has to grant both.
REAL_ADDR=$(addr_of "$USER")
real_before=$(bal "$REAL_ADDR")
qadenad_alias tx feegrant grant "$FU" "$REAL_ADDR" \
    --allowed-messages "$USER_MSGS" --spend-limit 10000000000000000000000aqdn \
    --expiration "$expiry" --from "$FU" --generate-only > "$workdir/inner_real.json" 2>/dev/null \
    || fail "could not generate the real-wallet grant"
c=$(tx_result "B-exec-real" tx authz exec "$workdir/inner_real.json" --from "$sa_key" --fee-granter "$FU")
[ "$c" = "0" ] && record "B-GRANT-REAL-WALLET" "PASS" "real wallet granted too (rotation is signed by it)" \
               || record "B-GRANT-REAL-WALLET" "FAIL" "code $c: $(tx_rawlog B-exec-real)"

# 5. register the new ephemeral wallet as the authorized signatory -- the key-rotation operation.
#    This is the message that locks out a stolen key, so it must not depend on a balance.
c=$(tx_result "B-register" tx dsvs register-authorized-signatory "$NEW_EPH" \
    --from "$USER" --fee-granter "$FU")
[ "$c" = "0" ] && record "B-REGISTER-SIGNATORY" "PASS" "rotation succeeded, paid by foundation-users" \
               || record "B-REGISTER-SIGNATORY" "FAIL" "code $c: $(tx_rawlog B-register)"

# 6. sign a real document from the brand-new wallet
docid_b="tollfree-B-$run_id"
printf 'phase B %s v1\n' "$run_id" > "$workdir/b1.txt"; printf 'phase B %s v2\n' "$run_id" > "$workdir/b2.txt"
c=$(tx_result "B-create-doc" tx dsvs create-document "$docid_b" ByLaws "C3Q Technologies, Inc." \
    "$workdir/b1.txt" "$u_email" "$u_phone" --from testdsvssrvprv --fee-granter "$FA")
[ "$c" = "0" ] || fail "phase B create-document failed (code $c): $(tx_rawlog B-create-doc)"
c=$(tx_result "B-sign" tx dsvs sign-document "$workdir/b1.txt" "$workdir/b2.txt" "$u_email" "$u_phone" \
    --from "$NEW_EPH" --fee-granter "$FU")
[ "$c" = "0" ] && record "B-SIGN-DOCUMENT" "PASS" "new wallet signed, paid by foundation-users" \
               || record "B-SIGN-DOCUMENT" "FAIL" "code $c: $(tx_rawlog B-sign)"

# 7. THE ASSERTION: the endowment must be untouched to the aqdn.
sleep 4
endow_after=$(bal "$NEW_ADDR")
spent_own=$(delta "$endow" "$endow_after")
echo "$NEW_EPH endowment: before=$endow after=$endow_after (spent $spent_own)"
# NOT A VACUOUS PASS.  An untouched endowment only means anything if the wallet actually did
# something: if register and sign never ran, nothing was spent and this would "pass" while proving
# the opposite.  The first run of this script did exactly that, so the operations are checked first.
real_after=$(bal "$REAL_ADDR")
real_spent=$(delta "$real_before" "$real_after")
echo "$USER (real wallet): before=$real_before after=$real_after (spent $real_spent)"
if [ "${verdict_of[B-REGISTER-SIGNATORY]}" != "PASS" ] || [ "${verdict_of[B-SIGN-DOCUMENT]}" != "PASS" ]; then
    record "B-ENDOWMENT-UNTOUCHED" "FAIL" "inconclusive: the wallet did not complete register+sign, so spending nothing proves nothing"
elif [ "$endow_after" = "$EPH_INCENTIVE" ] && [ "$real_spent" = "0" ]; then
    record "B-ENDOWMENT-UNTOUCHED" "PASS" "eph still exactly $EPH_INCENTIVE and real wallet unmoved -- every fee came from the grant"
else
    record "B-ENDOWMENT-UNTOUCHED" "FAIL" "eph spent $spent_own, real wallet spent $real_spent -- a grant did not apply"
fi

# =============================================================================================
# PHASE C -- rotation actually locks out the old key
#
# Authorization is decided by the HEAD of the list, not membership: RegisterAuthorizedSignatory
# PREPENDS (x/dsvs/keeper/msg_server_register_authorized_signatory.go) and the enclave reads only
# Signatory[0] ("convert the top-most one", cmd/qadenad_enclave/enclave.go GetAuthorizedSignatory).
# Old registrations stay on chain as history and are never consulted.
#
# That is the whole security value of "I may have lost my device", so it gets a regression test:
# after Phase B rotated to the new wallet, the PREVIOUS ephemeral wallet must be refused.  If a
# future change ever appends instead of prepends, this is what catches it.
# =============================================================================================
echo ""
echo "=== PHASE C: the rotated-out wallet can no longer sign ==="
OLD_EPH="$USER-eph$(( NEW_IDX - 1 ))"
if [ "${verdict_of[B-REGISTER-SIGNATORY]}" != "PASS" ]; then
    record "C-OLD-KEY-REFUSED" "SKIP" "no rotation happened in phase B, so there is nothing to lock out"
elif ! addr_of "$OLD_EPH" >/dev/null 2>&1; then
    record "C-OLD-KEY-REFUSED" "SKIP" "no previous ephemeral wallet ($OLD_EPH) to test against"
else
    OLD_ADDR=$(addr_of "$OLD_EPH")
    # its own grant, so a refusal cannot be blamed on having no way to pay
    qadenad_alias tx feegrant grant "$FU" "$OLD_ADDR" \
        --allowed-messages "$USER_MSGS" --spend-limit 10000000000000000000000aqdn \
        --expiration "$expiry" --from "$FU" --generate-only > "$workdir/inner_old.json" 2>/dev/null || true
    tx_result "C-grant-old" tx authz exec "$workdir/inner_old.json" --from "$sa_key" --fee-granter "$FU" >/dev/null

    docid_c="tollfree-C-$run_id"
    printf 'phase C %s v1\n' "$run_id" > "$workdir/c1.txt"; printf 'phase C %s v2\n' "$run_id" > "$workdir/c2.txt"
    c=$(tx_result "C-create-doc" tx dsvs create-document "$docid_c" ByLaws "C3Q Technologies, Inc." \
        "$workdir/c1.txt" "$u_email" "$u_phone" --from testdsvssrvprv --fee-granter "$FA")
    [ "$c" = "0" ] || fail "phase C create-document failed (code $c): $(tx_rawlog C-create-doc)"

    c=$(tx_result "C-old-sign" tx dsvs sign-document "$workdir/c1.txt" "$workdir/c2.txt" \
        "$u_email" "$u_phone" --from "$OLD_EPH" --fee-granter "$FU")
    echo "$OLD_EPH sign result: $c"
    if [ "$c" = "0" ]; then
        record "C-OLD-KEY-REFUSED" "FAIL" "$OLD_EPH could STILL sign after rotation -- an attacker keeps access"
    else
        record "C-OLD-KEY-REFUSED" "PASS" "$OLD_EPH refused after rotation ($c)"
    fi
fi

# =============================================================================================
# balances -- the two streams, separately
# =============================================================================================
echo ""
echo "=== balances ==="
sleep 4
fa_after=$(bal $FA); fu_after=$(bal $FU); sa_after=$(bal $SA)
fa_spent=$(delta $fa_before $fa_after); fu_spent=$(delta $fu_before $fu_after)
printf '%-20s %-28s %-28s %s\n' "ACCOUNT" "BEFORE" "AFTER" "SPENT"
printf '%-20s %-28s %-28s %s\n' "foundation-appsvr" "$fa_before" "$fa_after" "$fa_spent"
printf '%-20s %-28s %-28s %s\n' "foundation-users"  "$fu_before" "$fu_after" "$fu_spent"
printf '%-20s %-28s %-28s %s\n' "secadmin"          "$sa_before" "$sa_after" "$(delta $sa_before $sa_after)"
printf '%-20s %-28s %-28s %s\n' "$NEW_EPH" "$endow" "$endow_after" "$(delta $endow $endow_after)"

[ "$fa_spent" -gt 0 ] 2>/dev/null && [ "$fu_spent" -gt 0 ] 2>/dev/null \
    && record "TWO-STREAMS-SEPARATE" "PASS" "appsvr spent $fa_spent, users spent $fu_spent -- independently observable" \
    || record "TWO-STREAMS-SEPARATE" "FAIL" "appsvr=$fa_spent users=$fu_spent (both must be > 0)"
[ "$sa_after" = "0" ] \
    && record "SEC-ZERO-BALANCE" "PASS" "secadmin never held or spent a token" \
    || record "SEC-ZERO-BALANCE" "FAIL" "secadmin holds $sa_after aqdn -- that is a SEC treasury"

# tidy up so re-runs start clean
for g in "$SP" "$IDP"; do
    qadenad_alias tx feegrant revoke "$FA" "$g" --from "$fa_key" --yes --output json "${gas_flags[@]}" >/dev/null 2>&1 || true
done
qadenad_alias tx authz revoke "$SA" /cosmos.feegrant.v1beta1.MsgGrantAllowance --from "$fu_key" \
    --yes --output json "${gas_flags[@]}" >/dev/null 2>&1 || true

echo ""
echo "======================================================================"
echo "SUMMARY -- run $run_id"
echo "======================================================================"
failures=0
for id in "${order[@]}"; do
    printf '%-26s %-6s %s\n' "$id" "${verdict_of[$id]}" "${note_of[$id]}"
    [ "${verdict_of[$id]}" = "FAIL" ] && failures=$((failures+1))
done
echo ""
echo "evidence: $evidence"
if [ "$failures" -eq 0 ]; then
    echo "RESULT: PASS -- two foundation accounts cover SEC and users; no SEC treasury; endowments untouched."
    exit 0
else
    echo "RESULT: FAIL ($failures)"
    echo "B-ENDOWMENT-UNTOUCHED failing means a message type is missing from the grant: the wallet"
    echo "silently paid from its own 50 QDN and every transaction still 'succeeded'."
    exit 1
fi
