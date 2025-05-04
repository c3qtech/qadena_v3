#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

source "$qadenatestscripts/setup_mnemonic.sh"


echo "-------------------------"
echo "Creating, claiming al personal-info"
echo "-------------------------"
qadenad_alias tx qadena create-credential $al_a $al_bf personal-info "rodolfo alberto" "asuncion" "villarica" "1970-Feb-02" "ph" "us" "M" --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $al_a $al_bf  personal-info --from al --yes || exit 1

echo "-------------------------"
echo "Creating, claiming al phone"
echo "-------------------------"
qadenad_alias tx qadena create-credential $al_a $al_bf  phone-contact-info +639061234567 --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $al_a $al_bf  phone-contact-info --from al --yes || exit 1

echo "-------------------------"
echo "Creating, claiming al email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $al_a $al_bf  email-contact-info alvillarica@c3qtech.com --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $al_a $al_bf  email-contact-info --from al --yes || exit 1

echo "-------------------------"
echo "Creating, claiming ann personal-info"
echo "-------------------------"
qadenad_alias tx qadena create-credential $ann_a $ann_bf personal-info "ann" "a" "cuisia" "1965-Jan-01" "ph" "ph" "f" --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $ann_a $ann_bf personal-info --from ann --yes || exit 1

echo "-------------------------"
echo "Creating, claiming ann phone"
echo "-------------------------"
qadenad_alias tx qadena create-credential $ann_a $ann_bf phone-contact-info +639065551234 --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $ann_a $ann_bf phone-contact-info --from ann --yes || exit 1

echo "-------------------------"
echo "Creating, claiming ann email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $ann_a $ann_bf email-contact-info anncuisia@c3qtech.com --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $ann_a $ann_bf email-contact-info --from ann --yes || exit 1


echo "-------------------------"
echo "Creating, claiming jill personal-info"
echo "-------------------------"
qadenad_alias tx qadena create-credential $jill_a $jill_bf personal-info "jill" "lava" "quimba" "1990-Jan-01" "ph" "ph" "f" --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $jill_a $jill_bf personal-info --from jill --yes || exit 1

echo "-------------------------"
echo "Creating, claiming jill phone"
echo "-------------------------"
qadenad_alias tx qadena create-credential $jill_a $jill_bf phone-contact-info +639065555678 --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $jill_a $jill_bf phone-contact-info --from jill --yes || exit 1

echo "-------------------------"
echo "Creating, claiming jill email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $jill_a $jill_bf email-contact-info jillquimba@c3qtech.com --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $jill_a $jill_bf email-contact-info --from jill --yes || exit 1


echo "-------------------------"
echo "Creating, claiming victor personal-info"
echo "-------------------------"
qadenad_alias tx qadena create-credential $victor_a $victor_bf personal-info "victor" "b" "torres" "1970-Feb-03" "ph" "ph" "M" --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $victor_a $victor_bf personal-info --from victor --yes || exit 1

echo "-------------------------"
echo "Creating, claiming victor email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $victor_a $victor_bf email-contact-info victortorres@c3qtech.com --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $victor_a $victor_bf email-contact-info --from victor --yes || exit 1

echo "-------------------------"
echo "Creating, claiming kelvin email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $kelvin_a $kelvin_bf email-contact-info kelvinsantos@c3qtech.com --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $kelvin_a $kelvin_bf email-contact-info --from kelvin --yes || exit 1

echo "-------------------------"
echo "Creating, claiming alexis email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $alexis_a $alexis_bf email-contact-info alexiscantiga@c3qtech.com --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $alexis_a $alexis_bf email-contact-info --from alexis --yes || exit 1

echo "-------------------------"
echo "Creating, claiming secdsvs email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $secdsvs_a $secdsvs_bf  email-contact-info sec@sec.gov.ph --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $secdsvs_a $secdsvs_bf  email-contact-info --from secdsvs --yes || exit 1

echo "-------------------------"
echo "Creating, claiming secdsvs phone"
echo "-------------------------"
qadenad_alias tx qadena create-credential $secdsvs_a $secdsvs_bf  phone-contact-info +63288888888 --from secidentitysrvprv --yes || exit 1
qadenad_alias tx qadena claim-credential $secdsvs_a $secdsvs_bf  phone-contact-info --from secdsvs --yes || exit 1


echo "-------------------------"
echo "Creating extra sub-wallets"
echo "-------------------------"


qadenad_alias tx qadena create-wallet al-eph2 pioneer1 pioneer1-create-wallet-sponsor --link-to-real-wallet al --account-mnemonic="$almnemonic" --eph-account-index "2" --accept-credential-types first-name-personal-info --yes || exit 1

qadenad_alias tx qadena create-wallet al-eph3 pioneer1 pioneer1-create-wallet-sponsor --link-to-real-wallet al --account-mnemonic="$almnemonic" --eph-account-index "3" --accept-password="1234" --yes || exit 1

qadenad_alias tx qadena create-wallet al-eph4 pioneer1 pioneer1-create-wallet-sponsor --link-to-real-wallet al --account-mnemonic="$almnemonic" --eph-account-index "4" --require-sender-credential-types first-name-personal-info,middle-name-personal-info,last-name-personal-info --yes || exit 1

qadenad_alias tx qadena create-wallet ann-eph2 pioneer1 pioneer1-create-wallet-sponsor --link-to-real-wallet ann --account-mnemonic="$annmnemonic" --eph-account-index "2" --accept-credential-types first-name-personal-info --yes || exit 1

