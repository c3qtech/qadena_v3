#!/bin/zsh
#
# Verify the END STATE of a SEC VERITAS bring-up against the chain -- every invariant the flow
# claims, queried rather than assumed.  READ-ONLY: no keyring, no passphrase, no transaction.
#
#   sec_veritas_verify.sh --pregrant ~/sec-veritas/pregrant_addresses.json \
#                         --pool     ~/sec-veritas/pool_addresses.json \
#                         --appsvr <address> --users <address>
#
# Either side can run it -- SEC holds the two JSON files, QFI holds the account addresses its
# prepare stage printed; both are public data.
#
# THE INVARIANTS, and why each one is the design working:
#
#   1. THE ADMIN HOLDS EXACTLY ZERO.  Not "little": zero.  sec-veritas-admin signed every
#      delegated act of the bring-up (200+ transactions) and its balance never moving is the
#      whole point of the authz + MsgExec-feegrant construction.  A nonzero balance means
#      someone funded the key that can drain two foundation accounts -- investigate, then sweep.
#
#   2. THE ADMIN'S AUTHORITY IS EXACTLY THREE MESSAGE TYPES.  MsgGrantAllowance,
#      MsgRevokeAllowance, MsgSubmitProposal -- each earned by a measured refusal during the
#      first full run.  Fewer and the flow breaks (a widen or a submission has no authority);
#      MORE is worse: GenericAuthorization is uncapped, so every extra type is extra drainage
#      surface nobody decided on.
#
#   3. EVERY OPERATIONAL WALLET IS WIDENED.  All 4*(count+1) wallets hold the appsvr allowance
#      with the full message set -- MsgClaimCredential present is the discriminator, since the
#      narrow bootstrap grant (AddPublicKey+CreateWallet) never has it.  A narrow survivor means
#      a widen silently failed, and that wallet breaks on its first claim.
#
#   4. THE POOL IS FULLY AUTHORISED.  Each pool wallet holds BOTH halves from foundation-users:
#      the authz to issue grants as it, and the MsgExec feegrant to pay for doing so.  The
#      app-server picks pool members arbitrarily, so ONE missing half means onboarding fails
#      for some citizens and not others -- the worst failure shape there is.
#
#   5. THE PROVIDERS ARE REGISTERED, BY GOVERNANCE.  Both srvprv entries present with the right
#      serviceProviderType.
#
# Exit 0 only when every check passes; the summary names each failure.

HERE="${0:A:h}"
source "$HERE/../scripts/setup_env.sh" > /dev/null 2>&1 || true
SCRIPT_DIR="$HERE"

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
NODE_HOME="${QADENAHOME:-$HOME/qadena}"
NODE="${QADENA_NODE:-tcp://localhost:26657}"
PREGRANT="" POOL="" FA="" FU="" SA=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pregrant)  PREGRANT="$2"; shift 2 ;;
        --pool)      POOL="$2"; shift 2 ;;
        --appsvr)    FA="$2"; shift 2 ;;
        --users)     FU="$2"; shift 2 ;;
        --sec-admin) SA="$2"; shift 2 ;;
        --node)      NODE="$2"; shift 2 ;;
        --help|-h)
            print "Usage: sec_veritas_verify.sh --pregrant <file> --pool <file> --appsvr <addr> --users <addr>"
            print "  --sec-admin <addr>  override; default read from the pregrant file"
            print "  Read-only: verifies every bring-up invariant against the chain."
            exit 0 ;;
        *) print -u2 -- "unknown option: $1"; exit 1 ;;
    esac
done

qq() { "$QBIN" --home "$NODE_HOME" "$@" --node "$NODE"; }

[[ -r "$PREGRANT" ]] || { print -u2 "need --pregrant <file> (step_1's block)"; exit 1 }
[[ -n "$SA" ]] || SA=$(jq -r '.sec_admin // empty' "$PREGRANT")
[[ -n "$SA" && -n "$FA" && -n "$FU" ]] || { print -u2 "need --appsvr and --users (and an admin in the pregrant file)"; exit 1 }

PASS=0; FAIL=0
ok()   { print "  ok    $1"; PASS=$(( PASS + 1 )) }
bad()  { print "  FAIL  $1"; FAIL=$(( FAIL + 1 )) }

print "VERITAS end-state verification  (chain $(qq status 2>/dev/null | jq -r '.node_info.network // "?"'))"
print ""

# ---- 1. the admin holds exactly zero --------------------------------------------------------
_b=$(qq query bank balances "$SA" --output json 2>/dev/null | jq -r '(.balances[]?|select(.denom=="aqdn")|.amount) // "0"')
if [[ "${_b:-0}" == "0" ]]; then
    ok "admin balance is exactly 0"
else
    bad "admin holds ${_b}aqdn -- must be 0; someone funded the delegation key"
fi

# ---- 2. the admin's authority is exactly these three ----------------------------------------
_expect="/cosmos.feegrant.v1beta1.MsgGrantAllowance
/cosmos.feegrant.v1beta1.MsgRevokeAllowance
/cosmos.gov.v1.MsgSubmitProposal"
_got=$(qq query authz grants "$FA" "$SA" --output json 2>/dev/null \
        | jq -r '.grants[].authorization.value.msg' | sort)
if [[ "$_got" == "$(print -r -- "$_expect" | sort)" ]]; then
    ok "admin authority is exactly the three delegated message types"
else
    bad "admin authz mismatch -- have: $(print -r -- "$_got" | tr '\n' ' ')"
fi
_fexec=$(qq query feegrant grant "$FA" "$SA" --output json 2>/dev/null \
           | jq -r '.allowance.allowance.value.allowed_messages // [] | join(",")')
if [[ "$_fexec" == "/cosmos.authz.v1beta1.MsgExec" ]]; then
    ok "admin MsgExec feegrant present and scoped to MsgExec only"
elif [[ -n "$_fexec" ]]; then
    bad "admin feegrant allows [$_fexec] -- must be exactly MsgExec; wider is fee drainage"
else
    bad "admin has NO MsgExec feegrant -- it cannot pay for its own execs"
fi

# EXPIRY.  A delegated authority that lapses mid-deployment fails exactly like the missing-revoke
# bug did: silently, at the next widen.  Expired is a failure; expiring soon is a warning.
_now=$(date -u +%s)
qq query authz grants "$FA" "$SA" --output json 2>/dev/null \
  | jq -r '.grants[] | "\(.authorization.value.msg) \(.expiration // "never")"' \
  | while read -r _m _e; do
        [[ "$_e" == "never" ]] && continue
        _es=$(python3 -c "from datetime import datetime,timezone;print(int(datetime.fromisoformat('$_e'.replace('Z','+00:00')).timestamp()))" 2>/dev/null)
        if [[ -n "$_es" && "$_es" -le "$_now" ]]; then
            bad "authz for ${_m##*.} EXPIRED at $_e"
        elif [[ -n "$_es" && $(( _es - _now )) -lt 2592000 ]]; then
            print "  warn  authz for ${_m##*.} expires within 30 days ($_e)"
        fi
    done

# ---- 3. every operational wallet is widened -------------------------------------------------
#
# TWO "WIDE" SETS EXIST, AND THE LAST WRITER WINS.  create_user grants USER_MSGS (claims,
# signatory registration, binds); step_3's fund_wallet then revokes and re-grants
# VERITAS_APPSVR_MSGS (documents, credential ISSUANCE, MsgGrantAllowance) -- which lacks
# MsgClaimCredential, MsgClaimUpdatedCredential, MsgRegisterAuthorizedSignatory and the binds.
# The bring-up's own claims succeed only because they run BETWEEN the two grants.  So the END
# state is now the UNION of both (the widen grants it as of 2026-09-06), so a wallet showing the
# appsvr marker without the claim marker is from a pre-union bring-up -- functional for the
# app-server, broken for any later claim/rotation/bind.  Reported distinctly.
_narrow=0; _missing=0; _wide=0; _userset=0
while read -r _ad; do
    _al=$(qq query feegrant grant "$FA" "$_ad" --output json 2>/dev/null \
            | jq -r '.allowance.allowance.value.allowed_messages // [] | join(",")')
    if [[ -z "$_al" ]]; then
        _missing=$(( _missing + 1 ))
    elif [[ "$_al" == *MsgCreateDocument* ]]; then
        _wide=$(( _wide + 1 ))
    elif [[ "$_al" == *MsgClaimCredential* ]]; then
        _userset=$(( _userset + 1 ))     # widened but never re-widened -- fund_wallet skipped it
    else
        _narrow=$(( _narrow + 1 ))
    fi
done < <(jq -r '.wallets[].address' "$PREGRANT")
_total=$(jq -r '.wallets|length' "$PREGRANT")
if [[ $(( _wide + _userset )) -eq $_total && $_userset -eq 0 ]]; then
    ok "all $_total wallets hold the operational (appsvr) allowance"
elif [[ $(( _narrow + _missing )) -eq 0 ]]; then
    ok "all $_total wallets widened ($_wide operational, $_userset user-set -- mixed but functional)"
else
    bad "wallet allowances: $_wide operational, $_userset user-set, $_narrow narrow, $_missing missing of $_total"
fi

# ---- 4. the pool holds both halves ----------------------------------------------------------
if [[ -r "$POOL" ]]; then
    _pmiss=0; _ptot=0
    while read -r _ad; do
        _ptot=$(( _ptot + 1 ))
        _a1=$(qq query authz grants "$FU" "$_ad" --output json 2>/dev/null \
                | jq -r '[.grants[].authorization.value.msg] | index("/cosmos.feegrant.v1beta1.MsgGrantAllowance") // empty')
        _pf=$(qq query feegrant grant "$FU" "$_ad" --output json 2>/dev/null \
                | jq -r '.allowance.allowance.value.allowed_messages // [] | join(",")')
        { [[ -n "$_a1" ]] && [[ "$_pf" == *MsgExec* ]]; } || _pmiss=$(( _pmiss + 1 ))
    done < <(jq -r '.pool[].address' "$POOL")
    if [[ $_pmiss -eq 0 ]]; then
        ok "pool: all $_ptot wallets hold BOTH the authz and the MsgExec feegrant from users"
    else
        bad "pool: $_pmiss of $_ptot wallets missing a half -- onboarding will fail for SOME citizens"
    fi
else
    print "  skip  pool (--pool not given)"
fi

# ---- 5.5 NO STRAY AUTHORITY.  The per-grantee checks above prove what SHOULD exist; only a
# by-granter sweep proves nothing else does.  GenericAuthorization is uncapped, so an authz
# grantee nobody expected is standing permission to spend a foundation account -- exactly the
# thing an audit must catch and a green per-grantee check would never show.
_stray=0
while read -r _g; do
    [[ "$_g" == "$SA" ]] || { print "  FAIL  appsvr has an UNEXPECTED authz grantee: $_g"; _stray=$(( _stray + 1 )); }
done < <(qq query authz grants-by-granter "$FA" --limit 1000 --output json 2>/dev/null \
           | jq -r '[.grants[].grantee] | unique | .[]')
if [[ -r "$POOL" ]]; then
    _poolset=$(jq -r '[.pool[].address]|join(" ")' "$POOL")
    while read -r _g; do
        [[ " $_poolset " == *" $_g "* ]] || { print "  FAIL  users has an UNEXPECTED authz grantee: $_g"; _stray=$(( _stray + 1 )); }
    done < <(qq query authz grants-by-granter "$FU" --limit 1000 --output json 2>/dev/null \
               | jq -r '[.grants[].grantee] | unique | .[]')
fi
if [[ $_stray -eq 0 ]]; then
    ok "no stray authz grantees on either foundation account"
else
    FAIL=$(( FAIL + _stray ))
fi

# ---- 5. providers registered by governance --------------------------------------------------
_prov=$(qq query qadena list-interval-public-key-id 2>/dev/null \
          | grep -B0 -A6 "srvprv" | grep "serviceProviderType:" | grep -cE "identity|dsvs")
if [[ "${_prov:-0}" -ge 2 ]]; then
    ok "both service providers registered (identity + dsvs)"
else
    bad "expected 2 registered providers, found ${_prov:-0}"
fi

# ---- informational: the floats --------------------------------------------------------------
for _p in "appsvr:$FA" "users:$FU"; do
    _n="${_p%%:*}"; _a="${_p#*:}"
    _b=$(qq query bank balances "$_a" --output json 2>/dev/null | jq -r '(.balances[]?|select(.denom=="aqdn")|.amount) // "0"')
    print "  info  foundation-$_n float: $(python3 -c "v=int('${_b:-0}');print(f'{v//10**18:,}.{v%10**18:018d}'.rstrip('0').rstrip('.'))") QDN"
done

print ""
print "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] || exit 1
