#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

username=$1
usermnemonic=$2
pioneer=$3
serviceprovider=$4
firstname=$5
middlename=$6
lastname=$7
birthdate=$8
citizenship=$9
residency=${10}
gender=${11}
email=${12}
phone=${13}
user_a=${14}
user_bf=${15}
identityprovider=${16}
acceptcredentialtypes=${17}
acceptpassword=${18}
requiresendertypes=${19}
eph_count=${20}
createwalletsponsor=${21}

echo "service provider: $serviceprovider"
echo "required sender types: $requiresendertypes"
echo "accept credential types: $acceptcredentialtypes"
echo "accept password: $acceptpassword"
echo "create wallet sponsor: $createwalletsponsor"
echo "eph count: $eph_count"

# RESUMABLE, COARSELY.  A user is onboarded as one atomic sequence -- wallet, ephemerals, grants,
# claims -- and the local key for the MAIN wallet is written by the same run that broadcast it, so
# its presence means this user's sequence already completed (or nearly; the widen that follows in
# step_3 re-runs regardless and repairs the grants).  Without this, a step_3 resumed after a
# mid-run failure died here on "friendly name already exists ... aborted", and the only way
# forward was wiping keyrings for wallets the CHAIN still has -- which cannot be re-created.
# A user that died between main and ephemerals is mis-skipped by this; delete its keys to redo.
# KEYED ON THE CHAIN, NOT THE KEYRING.  The first version of this checked `keys show` and was
# wrong in the same way setup_provider_base's skip was: create-wallet writes the local key BEFORE
# broadcasting, so a failed broadcast leaves a key with no wallet, and a keyring-keyed skip then
# refuses to retry it forever.  That is how the fleet ended up with 33 keys and zero wallets
# (2026-09-07) while every downstream step reported success.
_u_addr=$(qadenad_alias keys show "$username" --address 2>/dev/null || true)
if [ -n "$_u_addr" ]; then
    # Single-address query, parsed from the first JSON line -- see wallet_on_chain() in
    # setup_provider_base.sh for why neither `.wallet.walletID` nor a list-wallet scan works.
    #
    # AND A FAILED QUERY IS NOT A "NO".  An empty result here DELETES the user's keys below, so an
    # unreachable node must stop the run rather than look like an absent wallet.
    _u_raw=$(qadenad_alias query qadena show-wallet "$_u_addr" --output json 2>&1 || true)
    case "$_u_raw" in
        *"no route to host"*|*"connection refused"*|*"context deadline exceeded"*|*"post failed"*)
            echo "cannot reach the chain to check whether $username exists -- refusing to continue,"
            echo "  because the next step would delete this key on the assumption it is absent."
            exit 1 ;;
    esac
    _u_onchain=$(print -r -- "$_u_raw" | sed -n '/^{/,$p' | jq -r '.walletID // empty' 2>/dev/null || true)
    if [ -n "$_u_onchain" ]; then
        echo "$username already exists ON CHAIN -- skipping create_user (resume)"
        exit 0
    fi
    echo "$username has a local key but NO wallet on chain -- a previous run failed after"
    echo "  writing the key.  Removing it so create-wallet can be retried."
    qadenad_alias keys delete "$username" --yes > /dev/null 2>&1 || true
    qadenad_alias keys delete "$username-credential" --yes > /dev/null 2>&1 || true
fi


# TOLL-FREE SUPPORT.
#
# In feegrant mode a new wallet holds NOTHING -- the chain's create-wallet incentives are 0 -- so
# every transaction it signs needs a sponsor. Two things are required, and neither alone is enough:
#
#   1. A GRANT WIDE ENOUGH. create-wallet issues its own allowance from the sponsor
#      (x/qadena/client/cli/tx_create_wallet.go grantFee) but it permits only MsgAddPublicKey and
#      MsgCreateWallet. Claiming a credential, registering a signatory and binding a contact are not
#      on it, so they fall through to the wallet's own balance -- which is zero.
#
#   2. THE COMMANDS MUST PRESENT IT. --fee-granter, on every transaction the USER signs.
#
#   And the grant must REVOKE FIRST: a grantee holds at most one allowance per granter, so the wider
#   grant cannot be layered over the one create-wallet already made from the same sponsor.
#
# This runs INSIDE create_user.sh rather than in step_3's fund_wallet because step_3 funds the
# wallet only AFTER create_user.sh returns -- by which time the claims have already failed.
USER_FEE_GRANTER_FLAG=""
USER_MSGS="/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet,/qadena.qadena.MsgClaimCredential,/qadena.qadena.MsgUpdateCredential,/qadena.qadena.MsgClaimUpdatedCredential,/qadena.qadena.MsgProtectPrivateKey,/qadena.dsvs.MsgSignDocument,/qadena.dsvs.MsgRegisterAuthorizedSignatory,/qadena.nameservice.MsgBindCredential,/qadena.nameservice.MsgUnbindCredential"

grant_user_fees() {   # grant_user_fees <key-name>
    [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ] || return 0
    local addr granter
    addr=$(qadenad_alias keys show "$1" --address 2>/dev/null) || return 0
    [ -n "$addr" ] || return 0
    case "$createwalletsponsor" in
        qadena1*) granter="$createwalletsponsor" ;;
        *)        granter=$(qadenad_alias keys show "$createwalletsponsor" --address 2>/dev/null || true)
                  [ -n "$granter" ] || granter="$createwalletsponsor" ;;
    esac
    # Signed by SEC's admin key as a MsgExec when VERITAS_SEC_ADMIN is set, so a real deployment
    # never needs a foundation key here; signed directly by the granter otherwise (harness only).
    if grant_as_foundation "$granter" "$addr" "$USER_MSGS"; then
        echo "  granted $1 the full user message set from $createwalletsponsor" >&2
    else
        echo "  WARNING: could not grant $1 -- its transactions will fall back to its own balance" >&2
    fi
}

# The IDENTITY PROVIDER also holds a grant rather than tokens in this mode, and create-credential is
# signed by IT, not by the user. Its grant already permits MsgCreateCredential -- issued by step_2's
# fund_wallet -- but a grant is only used when the transaction NAMES it, so the flag is what makes
# the difference between working and "spendable balance 0aqdn".
PROVIDER_FEE_GRANTER_FLAG=""
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    # THE SPONSOR MAY BE AN ADDRESS, NOT A KEY NAME.  On a split deployment SEC's keyring holds no
    # foundation key, so `keys show` fails -- and under set -e a failing substitution inside an
    # assignment kills the whole script with NO output past the argument echos (measured
    # 2026-09-06).  Same resolution rule as everywhere else: bech32 passes through untouched.
    case "$createwalletsponsor" in
        qadena1*) _sponsor_addr="$createwalletsponsor" ;;
        *)        _sponsor_addr=$(qadenad_alias keys show $createwalletsponsor --address 2>/dev/null || true) ;;
    esac
    [ -n "$_sponsor_addr" ] || { echo "cannot resolve sponsor '$createwalletsponsor' to an address"; exit 1; }
    USER_FEE_GRANTER_FLAG="--fee-granter $_sponsor_addr"
    PROVIDER_FEE_GRANTER_FLAG="--fee-granter ${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}"
    # resolve the name to an address; --fee-granter takes an address
    # `|| true`: on a split box this is an ADDRESS, keys show fails, and a failing substitution
    # in an assignment is fatal under set -e -- the same silent death as the sponsor line above.
    _fg_addr=$(qadenad_alias keys show "${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}" --address 2>/dev/null || true)
    case "${VERITAS_FOUNDATION_APPSVR:-}" in qadena1*) _fg_addr="$VERITAS_FOUNDATION_APPSVR" ;; esac
    [ -n "$_fg_addr" ] && PROVIDER_FEE_GRANTER_FLAG="--fee-granter $_fg_addr"
fi

banner "$username Create wallet"
run_cmd "qadenad_alias tx qadena create-wallet $username $pioneer $createwalletsponsor --account-mnemonic=\"$usermnemonic\"  --service-provider \"$serviceprovider\" --yes"

banner "$username Create wallet eph"
if [ -n "$eph_count" ] ; then
    for i in $(seq 1 $eph_count); do
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph$i $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"$i\" --yes"
    done
else
    run_cmd "qadenad_alias tx qadena create-wallet $username-eph $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"1\" --yes"
fi

# The wallets exist now, so they can be granted. Main wallet first, then each ephemeral one: a
# grant names ONE address, so every wallet that signs needs its own.
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    grant_user_fees "$username"
    if [ -n "$eph_count" ]; then
        for i in $(seq 1 $eph_count); do grant_user_fees "$username-eph$i"; done
    else
        grant_user_fees "$username-eph"
    fi
fi

banner "$username Create credential personal-info"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf personal-info \"$firstname\" \"$middlename\" \"$lastname\" \"$birthdate\" \"$citizenship\" \"$residency\" \"$gender\" --from \"$identityprovider\" $PROVIDER_FEE_GRANTER_FLAG --yes"

banner "$username Create credential phone"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf phone-contact-info $phone --from \"$identityprovider\" $PROVIDER_FEE_GRANTER_FLAG --yes"

banner "$username Create credential email"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf email-contact-info $email --from \"$identityprovider\" $PROVIDER_FEE_GRANTER_FLAG --yes"

banner "$username Claim credential personal-info"
run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf personal-info --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"

banner "$username Claim credential phone"
run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf phone-contact-info --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"

banner "$username Claim credential email"
run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf email-contact-info --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"

#if serviceprovider is not empty, then do this
if [ -n "$serviceprovider" ] ; then
    if [ -n "$eph_count" ] ; then
        # Directly pass multiple wallet IDs as separate arguments
        echo "Registering multiple ephemeral wallets as authorized signatories"
        cmd="qadenad_alias tx dsvs register-authorized-signatory"
        for i in $(seq 1 $eph_count); do
            banner "$username Setup DSVS authorized signatory as $username-eph$i"
            cmd="$cmd $username-eph$i"
        done
        cmd="$cmd --from $username $USER_FEE_GRANTER_FLAG --yes"
        echo "Executing: $cmd"
        run_cmd "$cmd"
    else
        banner "$username Setup DSVS authorized signatory as $username-eph"
        run_cmd "qadenad_alias tx dsvs register-authorized-signatory $username-eph --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"
    fi
fi

# if eph_count = 1, then do this
if [ "$eph_count" -eq 1 ]; then

    if [ -n "$acceptcredentialtypes" ] ; then
        banner "$username Accept credential types $acceptcredentialtypes"
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph2 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"2\" --accept-credential-types $acceptcredentialtypes --yes"
        banner "$username Bind phone nameservice to $username-eph2"
        run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph2 $USER_FEE_GRANTER_FLAG --yes"
    else
        if [ -n "$eph_count" ] ; then
            banner "$username Bind phone nameservice to $username-eph1"
            run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph1 $USER_FEE_GRANTER_FLAG --yes"
        else
            banner "$username Bind phone nameservice to $username-eph"
            run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph $USER_FEE_GRANTER_FLAG --yes"
        fi
    fi

    if [ -n "$requiresendertypes" ] ; then
        banner "$username require sender credential types $requiresendertypes"
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph3 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"3\" --require-sender-credential-types $requiresendertypes --yes"
        banner "$username Bind email nameservice to $username-eph3"
        run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph3 $USER_FEE_GRANTER_FLAG --yes"
    else 
        if [ -n "$eph_count" ] ; then
            banner "$username Bind email nameservice to $username-eph1"
            run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph1 $USER_FEE_GRANTER_FLAG --yes"
        else
            banner "$username Bind email nameservice to $username-eph"
            run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph $USER_FEE_GRANTER_FLAG --yes"
        fi
    fi

    if [ -n "$acceptpassword" ] ; then
        banner "$username Accept password"
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph4 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"4\" --accept-password=\"$acceptpassword\" --yes"
    fi

fi

