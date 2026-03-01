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

banner "$username Create credential personal-info"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf personal-info \"$firstname\" \"$middlename\" \"$lastname\" \"$birthdate\" \"$citizenship\" \"$residency\" \"$gender\" --from \"$identityprovider\" --yes"

banner "$username Create credential phone"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf phone-contact-info $phone --from \"$identityprovider\" --yes"

banner "$username Create credential email"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf email-contact-info $email --from \"$identityprovider\" --yes"

banner "$username Claim credential personal-info"
run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf personal-info --from \"$username\" --yes"

banner "$username Claim credential phone"
run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf phone-contact-info --from \"$username\" --yes"

banner "$username Claim credential email"
run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf email-contact-info --from \"$username\" --yes"

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
        cmd="$cmd --from $username --yes"
        echo "Executing: $cmd"
        run_cmd "$cmd"
    else
        banner "$username Setup DSVS authorized signatory as $username-eph"
        run_cmd "qadenad_alias tx dsvs register-authorized-signatory $username-eph --from \"$username\" --yes"
    fi
fi

# if eph_count = 1, then do this
if [ "$eph_count" -eq 1 ]; then

    if [ -n "$acceptcredentialtypes" ] ; then
        banner "$username Accept credential types $acceptcredentialtypes"
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph2 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"2\" --accept-credential-types $acceptcredentialtypes --yes"
        banner "$username Bind phone nameservice to $username-eph2"
        run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph2 --yes"
    else
        if [ -n "$eph_count" ] ; then
            banner "$username Bind phone nameservice to $username-eph1"
            run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph1 --yes"
        else
            banner "$username Bind phone nameservice to $username-eph"
            run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph --yes"
        fi
    fi

    if [ -n "$requiresendertypes" ] ; then
        banner "$username require sender credential types $requiresendertypes"
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph3 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"3\" --require-sender-credential-types $requiresendertypes --yes"
        banner "$username Bind email nameservice to $username-eph3"
        run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph3 --yes"
    else 
        if [ -n "$eph_count" ] ; then
            banner "$username Bind email nameservice to $username-eph1"
            run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph1 --yes"
        else
            banner "$username Bind email nameservice to $username-eph"
            run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph --yes"
        fi
    fi

    if [ -n "$acceptpassword" ] ; then
        banner "$username Accept password"
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph4 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"4\" --accept-password=\"$acceptpassword\" --yes"
    fi

fi

