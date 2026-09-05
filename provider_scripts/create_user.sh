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
    granter=$(qadenad_alias keys show "$createwalletsponsor" --address 2>/dev/null)
    [ -n "$granter" ] || granter="$createwalletsponsor"
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
    USER_FEE_GRANTER_FLAG="--fee-granter $(qadenad_alias keys show $createwalletsponsor --address 2>/dev/null)"
    PROVIDER_FEE_GRANTER_FLAG="--fee-granter ${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}"
    # resolve the name to an address; --fee-granter takes an address
    _fg_addr=$(qadenad_alias keys show "${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}" --address 2>/dev/null)
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

