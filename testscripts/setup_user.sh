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

echo "-------------------------"
echo "$username Create wallet"
echo "-------------------------"
qadenad_alias tx qadena create-wallet $username $pioneer $createwalletsponsor --account-mnemonic="$usermnemonic"  --service-provider "$serviceprovider" --yes

echo "-------------------------"
echo "$username Create wallet eph"
echo "-------------------------"
if [ -n "$eph_count" ] ; then
    for i in $(seq 1 $eph_count); do
        qadenad_alias tx qadena create-wallet $username-eph$i $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic="$usermnemonic" --eph-account-index "$i" --yes
    done
else
    qadenad_alias tx qadena create-wallet $username-eph $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic="$usermnemonic" --eph-account-index "1" --yes
fi

echo "-------------------------"
echo "$username Create credential personal-info"
echo "-------------------------"
qadenad_alias tx qadena create-credential $user_a $user_bf personal-info "$firstname" "$middlename" "$lastname" "$birthdate" "$citizenship" "$residency" "$gender" --from $identityprovider --yes

echo "-------------------------"
echo "$username Create credential phone"
echo "-------------------------"
qadenad_alias tx qadena create-credential $user_a $user_bf phone-contact-info $phone --from $identityprovider --yes

echo "-------------------------"
echo "$username Create credential email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $user_a $user_bf email-contact-info $email --from $identityprovider --yes

echo "-------------------------"
echo "$username Claim credential personal-info"
echo "-------------------------"
qadenad_alias tx qadena claim-credential $user_a $user_bf  personal-info --from $username --yes

echo "-------------------------"
echo "$username Claim credential phone"
echo "-------------------------"
qadenad_alias tx qadena claim-credential $user_a $user_bf  phone-contact-info --from $username --yes

echo "-------------------------"
echo "$username Claim credential email"
echo "-------------------------"
qadenad_alias tx qadena claim-credential $user_a $user_bf  email-contact-info --from $username --yes

echo "-------------------------"
echo "$username Setup DSVS authorized signatory as $username-eph"
echo "-------------------------"
if [ -n "$eph_count" ] ; then
    # Directly pass multiple wallet IDs as separate arguments
    echo "Registering multiple ephemeral wallets as authorized signatories"
    cmd="qadenad_alias tx dsvs register-authorized-signatory"
    for i in $(seq 1 $eph_count); do
        cmd="$cmd $username-eph$i"
    done
    cmd="$cmd --from $username --yes"
    echo "Executing: $cmd"
    eval $cmd
else
    qadenad_alias tx dsvs register-authorized-signatory $username-eph --from $username --yes
fi

# if eph_count = 1, then do this
if [ "$eph_count" -eq 1 ]; then

    if [ -n "$acceptcredentialtypes" ] ; then
        echo "-------------------------"
        echo "$username Accept credential types $acceptcredentialtypes"
        echo "-------------------------"
        qadenad_alias tx qadena create-wallet $username-eph2 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic="$usermnemonic" --eph-account-index "2" --accept-credential-types $acceptcredentialtypes --yes
        echo "-------------------------"
        echo "$username Bind phone nameservice to $username-eph2"
        echo "-------------------------"
        qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph2 --yes
    else
        echo "-------------------------"
        echo "$username Bind phone nameservice to $username-eph"
        echo "-------------------------"
        qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph --yes
    fi

    if [ -n "$requiresendertypes" ] ; then
        echo "-------------------------"
        echo "$username require sender credential types $requiresendertypes"
        echo "-------------------------"
        qadenad_alias tx qadena create-wallet $username-eph3 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic="$usermnemonic" --eph-account-index "3" --require-sender-credential-types $requiresendertypes --yes
        echo "-------------------------"
        echo "$username Bind email nameservice to $username-eph3"
        echo "-------------------------"
        qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph3 --yes
    else 
        echo "-------------------------"
        echo "$username Bind email nameservice to $username-eph"
        echo "-------------------------"
        qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph --yes
    fi

    if [ -n "$acceptpassword" ] ; then
        echo "-------------------------"
        echo "$username Accept password"
        echo "-------------------------"
        qadenad_alias tx qadena create-wallet $username-eph4 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic="$usermnemonic" --eph-account-index "4" --accept-password="$acceptpassword" --yes
    fi

fi

