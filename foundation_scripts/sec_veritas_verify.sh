#!/bin/zsh
#
# Verify the END STATE of a SEC VERITAS bring-up against the chain -- every invariant the flow
# claims, queried rather than assumed.  READ-ONLY: no keyring, no passphrase, no transaction.
#
#   sec_veritas_verify.sh --coord-home ~/launch/coord          # the foundation: types nothing
#   sec_veritas_verify.sh --pregrant <file> --pool <file> \
#                         --appsvr <address> --users <address>  # SEC: also checks the EXPECTED set
#
# Either side can run it, and neither needs the other's files.  The foundation's prepare stage
# records the sponsor addresses beside its keyring; everything else -- the wallet set, the pool,
# SEC's admin -- is enumerable on chain with grants-by-granter.  SEC additionally holds the two
# paste blocks, which turn "what exists" into "what exists vs what was supposed to".
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
# The name to PRINT in usage.  A per-deployment wrapper execs this file, so a hard-coded
# "sec_veritas_*.sh" told an ekycph operator to run a script whose --help they were not
# reading.  The wrapper exports QADENA_PROG; direct callers get the real name.
PROG="${QADENA_PROG:-sec_veritas_verify.sh}"
source "$HERE/../scripts/setup_env.sh" > /dev/null 2>&1 || true
SCRIPT_DIR="$HERE"

QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
NODE_HOME="${QADENAHOME:-$HOME/qadena}"
NODE="${QADENA_NODE:-tcp://localhost:26657}"
# Pre-scanned before the parse loop -- see sec_veritas_before_step_1.sh for why.
DEPLOYMENT="${DEPLOYMENT:-veritas}"
_dep_i=1
while (( _dep_i <= $# )); do
    [[ "${@[$_dep_i]}" == "--deployment" ]] && DEPLOYMENT="${@[$((_dep_i+1))]:?--deployment needs a name}"
    _dep_i=$(( _dep_i + 1 ))
done
source "$SCRIPT_DIR/deployment_profile.sh"
deployment_profile_load "$DEPLOYMENT" || exit 1

PREGRANT="" POOL="" FA="" FU="" SA=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pregrant)  PREGRANT="$2"; shift 2 ;;
        --deployment) shift 2 ;;   # pre-scanned above; consumed so it is not "unknown"
        --pool)      POOL="$2"; shift 2 ;;
        --appsvr)    FA="$2"; shift 2 ;;
        --users)     FU="$2"; shift 2 ;;
        --sec-admin) SA="$2"; shift 2 ;;
        --coord-home) COORD_HOME="$2"; shift 2 ;;
        --node)      NODE="$2"; shift 2 ;;
        --help|-h)
            print "Usage: $PROG [--coord-home <dir> | --appsvr <addr> --users <addr>] [options]"
            print ""
            print "Verifies a VERITAS bring-up against the chain.  READ-ONLY: no keyring, no"
            print "passphrase, no transactions.  Exit 0 only if every check passes."
            print ""
            print "The sponsor addresses -- one of:"
            print "  --coord-home <dir>    read them from <dir>/$DEPLOY_STATE_FILE, written by"
            print "                        sec_veritas_before_step_1.sh --stage prepare.  The"
            print "                        foundation needs nothing else."
            print "  --deployment <name>   which programme: $(deployment_profile_list).  Default"
            print "                        $DEPLOY_NAME.  Selects which sponsors/pregrant/pool files"
            print "                        --coord-home reads."
            print "  --appsvr <addr>       the $DEPLOY_APPSVR account"
            print "  --users <addr>        the $DEPLOY_USERS account"
            print ""
            print "Optional -- the EXPECTED sets, as SEC's paste blocks:"
            print "  --pregrant <file>     step_1's block (admin + every wallet address)"
            print "  --pool <file>         step_3's block (the sponsor pool)"
            print "  Without these the wallet and pool sets are read from the chain, which verifies"
            print "  what EXISTS but cannot detect a wallet that was never granted at all."
            print ""
            print "Other:"
            print "  --sec-admin <addr>    override; else taken from --pregrant, else identified on"
            print "                        chain as the grantee scoped to MsgExec alone"
            print "  --node <rpc>          default \$QADENA_NODE or tcp://localhost:26657"
            print ""
            print "  # foundation, nothing typed:"
            print "  $PROG --coord-home ~/launch/coord"
            print ""
            print "  # SEC, with the expected sets:"
            print "  $PROG --pregrant ~/sec-veritas/pregrant_addresses.json \\"
            print "      --pool ~/sec-veritas/pool_addresses.json \\"
            print "      --appsvr \$(jq -r .appsvraddr ~/sec-veritas/variables.json) \\"
            print "      --users  \$(jq -r .usersaddr  ~/sec-veritas/variables.json)"
            exit 0 ;;
        *) print -u2 -- "unknown option: $1"; exit 1 ;;
    esac
done

qq() { "$QBIN" --home "$NODE_HOME" "$@" --node "$NODE"; }

# THE FILES ARE OPTIONAL.  The foundation has no access to SEC's directory, and on a real
# deployment neither side holds the other's files -- so the chain is the primary source: every
# grant this flow issues is enumerable with grants-by-granter.  Pass --pregrant/--pool when you
# have them (QFI's own saved copies of SEC's paste blocks count) and the run additionally checks
# the on-chain set against the EXPECTED one; without them it checks what exists, which cannot
# detect a wallet that was never granted at all.  That difference is reported, not glossed.
# THE FOUNDATION TYPES NOTHING.  before_step_1 records the two sponsor addresses beside the
# coordinator keyring; read them from there so the addresses in play are the ones that RUN
# actually used, not a pair remembered from an earlier deployment's scrollback.
if [[ -z "$FA" || -z "$FU" ]]; then
    _st="${COORD_HOME:-$HOME/launch/coord}/$DEPLOY_STATE_FILE"
    if [[ -r "$_st" ]]; then
        [[ -n "$FA" ]] || FA=$(jq -r '.appsvr // empty' "$_st")
        [[ -n "$FU" ]] || FU=$(jq -r '.users  // empty' "$_st")
        # The endpoint too, unless the caller named one.  NODE still holds its default here, so
        # compare against that rather than testing for emptiness.
        if [[ "$NODE" == "${QADENA_NODE:-tcp://localhost:26657}" ]]; then
            _n=$(jq -r '.node // empty' "$_st")
            [[ -n "$_n" ]] && NODE="$_n"
        fi
        print "sponsors read from $_st"
    fi
fi
[[ -n "$FA" && -n "$FU" ]] || {
    print -u2 "need the two sponsor addresses.  Either:"
    print -u2 "    --coord-home <dir>   read them from <dir>/$DEPLOY_STATE_FILE (written by"
    print -u2 "                         sec_veritas_before_step_1.sh --stage prepare), or"
    print -u2 "    --appsvr <addr> --users <addr>"
    print -u2 "  --pregrant/--pool are optional; with them the expected wallet set is checked too."
    exit 1
}
# The expected sets, if the foundation retained them (after_step_1/after_step_3 copy the blocks
# they signed into the coordinator home).  Explicit flags win.
if [[ -n "${COORD_HOME:-}" ]]; then
    [[ -n "$PREGRANT" ]] || { [[ -r "$COORD_HOME/$DEPLOY_PREGRANT_FILE" ]] && PREGRANT="$COORD_HOME/$DEPLOY_PREGRANT_FILE" }
    [[ -n "$POOL"     ]] || { [[ -r "$COORD_HOME/$DEPLOY_POOL_FILE"     ]] && POOL="$COORD_HOME/$DEPLOY_POOL_FILE" }
fi
if [[ -r "$PREGRANT" ]]; then
    [[ -n "$SA" ]] || SA=$(jq -r '.sec_admin // empty' "$PREGRANT")
fi
# Without a file, the admin is the one grantee holding the MsgExec-scoped allowance -- the
# delegation key is defined by exactly that, so it identifies itself.
if [[ -z "$SA" ]]; then
    SA=$(qq query feegrant grants-by-granter "$FA" --output json 2>/dev/null \
          | jq -r '[(.allowances // [])[]
                    | select((.allowance.value.allowed_messages // [])
                             == ["/cosmos.authz.v1beta1.MsgExec"])
                    | .grantee] | first // empty')
fi
[[ -n "$SA" ]] || { print -u2 "cannot identify SEC's admin: pass --sec-admin <addr> or --pregrant <file>"; exit 1 }

PASS=0; FAIL=0
ok()   { print "  ok    $1"; PASS=$(( PASS + 1 )) }
bad()  { print "  FAIL  $1"; FAIL=$(( FAIL + 1 )) }

# REACHABILITY FIRST.  Every check below reads the chain, so against a dead endpoint they all
# "fail" -- and a run that prints five FAILs reads as a broken deployment when the truth is that
# nothing was asked.  Measured 2026-09-06: a --coord-home run with no node defaulted to localhost
# and reported 5 failed, 2 passed on a deployment that was in fact fine.
_CHAIN=$(qq status 2>/dev/null | jq -r '.node_info.network // empty' 2>/dev/null)
if [[ -z "$_CHAIN" ]]; then
    print -u2 "cannot reach a chain at $NODE -- nothing was verified."
    print -u2 ""
    print -u2 "  This is NOT a statement about the deployment: no query succeeded."
    print -u2 "  Point at the right node:"
    print -u2 "      --node tcp://<host>:26657"
    print -u2 "  (a --coord-home run uses the node recorded by sec_veritas_before_step_1.sh;"
    print -u2 "   a record written before 2026-09-06 has no node field and defaults to localhost.)"
    exit 1
fi
print "VERITAS end-state verification  (chain $_CHAIN via $NODE)"
if [[ ! -r "$PREGRANT" ]]; then
    print "reading the wallet set FROM THE CHAIN (no --pregrant): this verifies what exists,"
    print "but cannot detect a wallet that was never granted at all."
fi
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

# ---- 3. every operational wallet holds the EXACT expected allowance -----------------------
#
# THE SET, NOT JUST ITS EXISTENCE.  A narrowed allowance and a correct one are indistinguishable
# to any check that only asks "is there a grant" -- and narrowing is precisely how this broke
# before: two wide sets overwrote each other and the survivor silently lacked every claim,
# rotation and bind message.  Nothing about the final on-chain state showed it.  So compare the
# full sorted set, and report what is MISSING and what is EXTRA rather than a verdict.
#
# The expected set is READ FROM step_3.sh, not restated here.  A second copy is a second thing to
# forget: the last time this list changed it had to change in two places, and a verifier holding
# a stale third copy would fail every wallet while the deployment was correct.
_expect_msgs=$(grep -h '^VERITAS_APPSVR_MSGS=' "$SCRIPT_DIR/../veritas_scripts/step_3.sh" 2>/dev/null \
                 | sed 's/^VERITAS_APPSVR_MSGS="//; s/"$//' | tr ',' '\n' | sort -u)
if [[ -z "$_expect_msgs" ]]; then
    bad "cannot read VERITAS_APPSVR_MSGS from veritas_scripts/step_3.sh -- wallet check skipped"
else
if [[ -r "$PREGRANT" ]]; then
    _wallets=$(jq -r '.wallets[].address' "$PREGRANT")
else
    _wallets=$(qq query feegrant grants-by-granter "$FA" --output json 2>/dev/null \
                | jq -r --arg sa "$SA" '(.allowances // [])[] | select(.grantee != $sa) | .grantee')
fi
_exact=0 _narrow=0 _missing=0 _first_bad=""
while read -r _ad; do
    [[ -n "$_ad" ]] || continue
    _got=$(qq query feegrant grant "$FA" "$_ad" --output json 2>/dev/null \
            | jq -r '(.allowance.allowance.value.allowed_messages // [])[]' | sort -u)
    if [[ -z "$_got" ]]; then
        _missing=$(( _missing + 1 ))
        [[ -n "$_first_bad" ]] || _first_bad="$_ad (no allowance at all)"
    elif [[ "$_got" == "$_expect_msgs" ]]; then
        _exact=$(( _exact + 1 ))
    else
        _narrow=$(( _narrow + 1 ))
        if [[ -z "$_first_bad" ]]; then
            _miss=$(comm -23 <(print -r -- "$_expect_msgs") <(print -r -- "$_got") | sed 's|.*Msg|Msg|' | tr '\n' ' ')
            _extra=$(comm -13 <(print -r -- "$_expect_msgs") <(print -r -- "$_got") | sed 's|.*Msg|Msg|' | tr '\n' ' ')
            _first_bad="$_ad${_miss:+ -- MISSING: $_miss}${_extra:+ -- EXTRA: $_extra}"
        fi
    fi
done < <(print -r -- "$_wallets")
_total=$(print -r -- "$_wallets" | grep -c . || true)
if [[ $_exact -eq $_total && $_total -gt 0 ]]; then
    ok "all $_total wallets hold the exact operational allowance ($(print -r -- "$_expect_msgs" | grep -c .) messages)"
elif [[ $_total -eq 0 ]]; then
    bad "no wallets found to check"
else
    bad "wallet allowances: $_exact exact, $_narrow wrong, $_missing absent of $_total"
    print "        first: $_first_bad"
fi
fi

# ---- 3b. THE FLOOR: an independently-sourced minimum ---------------------------------------
#
# CHECK 3 IS A DRIFT CHECK, NOT A CORRECTNESS CHECK.  It reads the expected set out of step_3.sh,
# so it proves the chain matches the SCRIPT.  If that list is itself short a type something needs,
# every wallet passes while under-granted and the check says "exact" with total confidence -- the
# same shape as the bug it was written to catch, one level up.
#
# This is the other half: a minimum derived from a DIFFERENT source -- the app-server's own
# message constructors, swept from api/ independently 2026-09-06 for BOTH construction forms --
# `types.NewMsgX(...)` AND `types.MsgX{...}` struct literals.  Grepping only the first form is how
# the first version of this list came back short: MsgRemoveDocument is a struct literal, and a
# check that misses it reports "covers everything" with full confidence.  It cannot drift with
# step_3.sh because it does not come from there.
#
# THREE MESSAGE POPULATIONS ARE DELIBERATELY EXCLUDED, each signed by a wallet family this
# bring-up does not create:  MsgExec (pool wallets, covered by check 4 under a DIFFERENT granter),
# MsgExecuteContract (DBM/notarial wallets), MsgCreateBulkCredentials (eKYC partner wallets).
# If any of those families is ever deployed here, it needs its own grant and its own check.  A superset is
# expected and fine: the bring-up's wallets also claim, bind and rotate, which the server never
# does.  What must never happen is a wallet that cannot pay for something the server will ask of
# it.  MsgExec is deliberately NOT here -- only pool wallets sign that, and check 4 covers it.
_floor=(
    /qadena.qadena.MsgAddPublicKey
    /qadena.qadena.MsgCreateWallet
    /qadena.qadena.MsgClaimCredential
    /qadena.qadena.MsgCreateCredential
    /qadena.qadena.MsgRemoveCredential
    /qadena.qadena.MsgSignRecoverPrivateKey
    /qadena.dsvs.MsgCreateDocument
    /qadena.dsvs.MsgRemoveDocument
    /qadena.dsvs.MsgSignDocument
    /qadena.dsvs.MsgRegisterAuthorizedSignatory
    /cosmos.feegrant.v1beta1.MsgGrantAllowance
    /cosmos.feegrant.v1beta1.MsgRevokeAllowance
)
_short=""
for _m in "${_floor[@]}"; do
    print -r -- "$_expect_msgs" | grep -qx -- "$_m" || _short="$_short ${_m##*.}"
done
if [[ -z "$_short" ]]; then
    ok "the granted set covers all ${#_floor[@]} messages the app-server builds (independent source)"
else
    bad "the granted set is SHORT of what the app-server builds:$_short"
    print "        this is not drift -- step_3.sh's list itself cannot serve the server."
fi

# ---- 4. the pool holds both halves ----------------------------------------------------------
if [[ -r "$POOL" ]]; then
    _pool_list=$(jq -r '.pool[].address' "$POOL")
else
    # Chain-derived: the pool is exactly who foundation-users has granted.
    _pool_list=$(qq query feegrant grants-by-granter "$FU" --output json 2>/dev/null \
                  | jq -r '(.allowances // [])[].grantee')
fi
if [[ -n "$_pool_list" ]]; then
    _pmiss=0; _ptot=0
    while read -r _ad; do
        [[ -n "$_ad" ]] || continue
        _ptot=$(( _ptot + 1 ))
        # `.grants` is NULL, not [], when a grantee has none -- iterating it makes jq spew
        # "Cannot iterate over null" onto the operator's screen mid-report.  `// []` first.
        _a1=$(qq query authz grants "$FU" "$_ad" --output json 2>/dev/null \
                | jq -r '[(.grants // [])[].authorization.value.msg] | index("/cosmos.feegrant.v1beta1.MsgGrantAllowance") // empty')
        _pf=$(qq query feegrant grant "$FU" "$_ad" --output json 2>/dev/null \
                | jq -r '.allowance.allowance.value.allowed_messages // [] | join(",")')
        { [[ -n "$_a1" ]] && [[ "$_pf" == *MsgExec* ]]; } || _pmiss=$(( _pmiss + 1 ))
    done < <(print -r -- "$_pool_list")
    if [[ $_pmiss -eq 0 ]]; then
        ok "pool: all $_ptot wallets hold BOTH the authz and the MsgExec feegrant from users"
    elif [[ $_pmiss -eq $_ptot ]]; then
        # ALL missing is a different situation from SOME missing: it means the step simply has not
        # run yet.  Reported as an unfinished deployment, not as damage.
        bad "pool: none of the $_ptot wallets are authorised -- has sec_veritas_after_step_3.sh been run?"
    else
        bad "pool: $_pmiss of $_ptot wallets missing a half -- onboarding will fail for SOME citizens"
    fi
else
    bad "pool: none of the wallets are authorised -- has sec_veritas_after_step_3.sh been run?"
fi

# ---- 5.5 NO STRAY AUTHORITY.  The per-grantee checks above prove what SHOULD exist; only a
# by-granter sweep proves nothing else does.  GenericAuthorization is uncapped, so an authz
# grantee nobody expected is standing permission to spend a foundation account -- exactly the
# thing an audit must catch and a green per-grantee check would never show.
_stray=0
while read -r _g; do
    [[ "$_g" == "$SA" ]] || { print "  FAIL  appsvr has an UNEXPECTED authz grantee: $_g"; _stray=$(( _stray + 1 )); }
done < <(qq query authz grants-by-granter "$FA" --limit 1000 --output json 2>/dev/null \
           | jq -r '[(.grants // [])[].grantee] | unique | .[]')
if [[ -n "$_pool_list" ]]; then
    _poolset=$(print -r -- "$_pool_list" | tr '\n' ' ')
    while read -r _g; do
        [[ " $_poolset " == *" $_g "* ]] || { print "  FAIL  users has an UNEXPECTED authz grantee: $_g"; _stray=$(( _stray + 1 )); }
    done < <(qq query authz grants-by-granter "$FU" --limit 1000 --output json 2>/dev/null \
               | jq -r '[(.grants // [])[].grantee] | unique | .[]')
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

# ---- 6. CAN THE PAYERS ACTUALLY PAY, AND DO THE NON-PAYERS HOLD NOTHING ---------------------
#
# Every check above asks whether the PERMISSIONS are right.  This one asks whether the money is,
# which is a separate way for the same deployment to stop working: a fee grant is an authorisation
# to spend someone else's balance, and it authorises nothing once that balance is gone.  A drained
# sponsor fails exactly like a missing grant -- "spendable balance 0aqdn" -- so the two are worth
# distinguishing before someone re-issues grants that were never the problem.
#
# The mirror check matters as much.  Pool and operational wallets are supposed to hold NOTHING:
# that is the whole toll-free claim, and it is what makes a stolen wallet key worthless.  A
# balance on one of them means somebody funded it -- usually to "fix" a failure whose real cause
# was a missing grant -- and the deployment has quietly acquired a second funding source that
# masks the first.  That is the endowment trap the zeroed incentives exist to prevent.
for _p in "appsvr:$FA" "users:$FU"; do
    _n="${_p%%:*}"; _a="${_p#*:}"
    _b=$(qq query bank balances "$_a" --output json 2>/dev/null | jq -r '(.balances[]?|select(.denom=="aqdn")|.amount) // "0"')
    if [[ "${_b:-0}" == "0" ]]; then
        bad "foundation-$_n holds NOTHING -- every grant it issued is now unfundable"
    else
        ok "foundation-$_n can still pay ($(python3 -c "v=int('${_b:-0}');print(f'{v//10**18:,}')") QDN)"
    fi
done
# The chain's own wallet incentives are not a second funding source.  x/qadena pays
# create_wallet_transparent_incentive on every wallet and the ephemeral equivalent on every
# ephemeral.  Both are zero on a launch chain, so the check is unchanged there; on a devnet they
# are 500 and 50 QDN.  The threshold is the entitlement, not zero -- a wallet holding more than
# the chain would have paid it still trips the check.
_inc=$(qq query qadena params --output json 2>/dev/null | sed -n '/^{/,$p' \
       | jq -r '.params.create_wallet_transparent_incentive.amount // "0"' 2>/dev/null)
_inc_eph=$(qq query qadena params --output json 2>/dev/null | sed -n '/^{/,$p' \
       | jq -r '.params.create_ephemeral_wallet_transparent_incentive.amount // "0"' 2>/dev/null)
_inc="${_inc:-0}"; _inc_eph="${_inc_eph:-0}"
# Deliberately the LARGER of the two, not per-wallet-type: the expected set does not record which
# addresses are ephemeral, and erring by one incentive tier is the right way to err -- a wallet
# funded from somewhere else holds far more than one tier's difference.
_allow_aqdn=$(python3 -c "print(max(int('$_inc'), int('$_inc_eph')) * 10**18)")
if [[ "$_inc" != "0" || "$_inc_eph" != "0" ]]; then
    print "  note  chain pays wallet incentives ($_inc / $_inc_eph QDN) -- allowed below"
fi

_funded=0 _first_funded=""
while read -r _ad; do
    [[ -n "$_ad" ]] || continue
    _b=$(qq query bank balances "$_ad" --output json 2>/dev/null | jq -r '(.balances[]?|select(.denom=="aqdn")|.amount) // "0"')
    if [[ "${_b:-0}" != "0" ]] \
       && python3 -c "import sys; sys.exit(0 if int('${_b:-0}') > int('$_allow_aqdn') else 1)"; then
        _funded=$(( _funded + 1 ))
        [[ -n "$_first_funded" ]] || _first_funded="$_ad ($(python3 -c "v=int('${_b:-0}');print(f'{v/10**18:,.6f}')") QDN)"
    fi
done < <(print -r -- "$_wallets")
if [[ $_funded -eq 0 ]]; then
    if [[ "$_inc" != "0" || "$_inc_eph" != "0" ]]; then
        ok "no operational wallet holds more than its wallet incentive -- fee grants fund the rest"
    else
        ok "no operational wallet holds tokens -- fee grants are the only funding source"
    fi
else
    bad "$_funded operational wallet(s) hold MORE THAN their wallet incentive -- a second funding source masks missing grants"
    print "        first: $_first_funded"
fi

# ---- 7. THE THING BEING GRANTED TO ACTUALLY EXISTS -----------------------------------------
#
# EVERY CHECK ABOVE PROVES THE GRANTS, NOT THE WALLETS.  A fee grant is issued to an ADDRESS and
# the chain does not require anything to exist there -- so "16 wallets hold the exact operational
# allowance" stays true while `list-wallet` returns ZERO and nothing can transact.  Measured
# 2026-09-07 on this fleet: 10/10 green, 33 keys in the keyring, no wallets on chain at all, and
# the app-server's onboarding failing at a query before it ever reached a fee.
#
# The provider public keys are the same class.  A passed MsgAddServiceProvider registers the
# IntervalPublicKeyID; the transaction and credential pubkeys come from create-wallet.  A provider
# with an interval id and no keys looks registered to `list-interval-public-key-id` and is unusable
# to anything that resolves a key through it, which is every wallet operation.
# EVERY EXPECTED WALLET, NOT A COUNT.  The first version asserted only that list-wallet was
# non-empty, and 13 of an expected 16 passed it -- the three missing were an entire family's
# ephemerals, and the run that produced them reported success.  A count cannot notice a gap; the
# expected set can, and we have it in the pregrant file.
#
# Asked one address at a time on purpose: list-wallet paginates, so scanning it would start
# reporting existing wallets as absent once a deployment outgrows a page.
if [[ -r "$PREGRANT" ]]; then
    _wmiss=0 _wseen=0 _wfirst=""
    while read -r _wa; do
        [[ -n "$_wa" ]] || continue
        _wseen=$(( _wseen + 1 ))
        _wr=$(qq query qadena show-wallet "$_wa" --output json 2>&1 || true)
        case "$_wr" in
            *"no route to host"*|*"connection refused"*|*"post failed"*)
                bad "cannot reach the chain to check wallets"; break ;;
        esac
        if [[ -z "$(print -r -- "$_wr" | sed -n '/^{/,$p' | jq -r '.walletID // empty' 2>/dev/null)" ]]; then
            _wmiss=$(( _wmiss + 1 ))
            [[ -n "$_wfirst" ]] || _wfirst="$_wa"
        fi
    done < <(jq -r '.wallets[].address' "$PREGRANT")
    if [[ $_wmiss -eq 0 && $_wseen -gt 0 ]]; then
        ok "all $_wseen expected wallets exist on chain"
    else
        bad "$_wmiss of $_wseen expected wallets DO NOT exist on chain"
        print "        first missing: $_wfirst"
        print "        their grants are issued to addresses with nothing behind them."
    fi
else
    # Without the expected set this degrades to the old, weak assertion -- said plainly.
    _wcount=$(qq query qadena list-wallet --output json 2>/dev/null | jq -r '(.wallet // [])|length' 2>/dev/null)
    : ${_wcount:=0}
    if [[ "$_wcount" -gt 0 ]]; then
        ok "$_wcount wallet(s) exist on chain (no --pregrant: cannot tell if any are MISSING)"
    else
        bad "ZERO wallets on chain -- every grant is issued to an address that does not exist"
    fi
fi

# ---- CREDENTIALS ACTUALLY CLAIMED ----------------------------------------------------------
#
# A user with wallets and no credentials looks finished and cannot do anything: claiming is what
# binds a credential to the wallet, and register-authorized-signatory REFUSES without one
# (qadena 1118).  On 2026-09-07 secdsvs had 4 wallets, 0 credentials, and every check then in this
# file passed.  The claim is keyed by the CREDENTIAL WALLET address -- account 1 of the same
# mnemonic -- which is why the pregrant file's `-credential` entries are the right thing to ask
# about.
# BY OWNER, NOT BY CREDENTIAL ID.  show-credential is keyed on the CREDENTIAL WALLET address --
# account 1 of the user's mnemonic -- and this script deliberately holds no mnemonics: it is
# foundation-side and read-only.  list-credential carries the owning walletID, so ask that way and
# match on the MAIN wallet address, which the pregrant file does have.
#
# This scans the credential list, which paginates; on a chain with many citizens it would need a
# by-owner query that does not exist today.  Said here rather than discovered later.
_credmiss=""
_credlist=$(qq query qadena list-credential --output json 2>/dev/null | sed -n '/^{/,$p' || true)
for _un in "$DEPLOY_SPONSOR_BASE" "$DEPLOY_DSVS"; do
    _uw=$(jq -r --arg n "$_un" '(.wallets // [])[] | select(.name==$n) | .address' "$PREGRANT" 2>/dev/null | head -1)
    [[ -n "$_uw" ]] || continue
    _n=$(print -r -- "$_credlist" | jq -r --arg w "$_uw" '[(.credential // [])[] | select(.walletID==$w)] | length' 2>/dev/null)
    [[ "${_n:-0}" -gt 0 ]] || _credmiss="$_credmiss $_un"
done
if [[ -z "$_credmiss" ]]; then
    ok "both user wallets own claimed credentials"
else
    bad "NO claimed credentials for:$_credmiss"
    print "        the wallets exist but nothing is bound to them -- SEC cannot register a"
    print "        signatory (qadena 1118) and the app cannot present a credential."
fi


_nokeys=""
_provseen=0
for _prov in $(qq query qadena list-interval-public-key-id --output json 2>/dev/null \
                 | jq -r '(.intervalPublicKeyID // [])[] | select(.nodeType=="srv-prv") | .nodeID' 2>/dev/null); do
    _pid=$(qq query qadena list-interval-public-key-id --output json 2>/dev/null \
             | jq -r --arg n "$_prov" '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID')
    _k=$(qq query qadena list-public-key --output json 2>/dev/null \
           | jq -r --arg i "$_pid" '[(.publicKey // [])[] | select(.pubKID==$i and .pubKType=="transaction")] | length')
    _provseen=$(( _provseen + 1 ))
    [[ "${_k:-0}" -gt 0 ]] || _nokeys="$_nokeys $_prov"
done
# A LOOP THAT FOUND NOTHING MUST NOT REPORT SUCCESS.  The first version of this filtered on
# nodeType "identity"/"dsvs" -- the serviceProviderType, not the node type -- matched zero rows,
# and printed "ok" on a chain where BOTH providers were keyless.  The node type is "srv-prv";
# the identity/dsvs distinction lives in the proposal, not here.
if [[ "$_provseen" -eq 0 ]]; then
    bad "no service providers found to check (expected 2) -- has governance run?"
elif [[ -z "$_nokeys" ]]; then
    ok "all $_provseen registered service provider(s) have a transaction public key"
else
    bad "service provider(s) registered with NO public key:$_nokeys"
    print "        governance recorded the interval id; create-wallet never registered the keys."
    print "        Anything resolving a key through these providers fails with NotFound."
fi

# ---- 8. SEC CAN ACTUALLY COUNTER-SIGN --------------------------------------------------------
#
# THIRD INSTANCE OF THE SAME BLIND SPOT.  Checks 1-7 prove grants, allowances and registrations --
# every one a POINTER to a capability.  A document flow needs the capability itself: SEC's
# counter-signature is signed by a secdsvs ephemeral, and the chain rejects it with "Unauthorized
# signer" (qadena 1137) unless that wallet is a registered authorized signatory.
#
# On this fleet the whole bring-up passed 13/13 with ZERO signatory records for secdsvs, because
# the registration is the last thing create_user.sh does and a resume that skipped to the end
# never reached it.  Nothing else asserted here would have noticed.
_sig_addr=""
if [[ -r "$PREGRANT" ]]; then
    _sig_addr=$(jq -r --arg n "$DEPLOY_DSVS" '(.wallets // [])[] | select(.name==$n) | .address' "$PREGRANT" 2>/dev/null | head -1)
fi
if [[ -z "$_sig_addr" ]]; then
    print "  skip  signatory (no $DEPLOY_DSVS address in the pregrant file)"
elif qq query dsvs show-authorized-signatory "$_sig_addr" > /dev/null 2>&1; then
    ok "$DEPLOY_DSVS has an authorized signatory registered (it can counter-sign)"
else
    bad "NO authorized signatory registered for $DEPLOY_DSVS -- it cannot counter-sign any document"
    print "        the wallets and credentials exist; the registration does not.  Re-run the"
    print "        register-authorized-signatory step, or step_3 for that user."
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
