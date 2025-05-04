#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

cd $qadenabuild

qadenad_alias tx dsvs create-document document1 "ByLaws" "C3Q Technologies, Inc." "test_data/document1.pdf" "no-reply@sec.gov.ph" "" "alvillarica@c3qtech.com" "+639061234567" --from secdsvssrvprv --yes

qadenad_alias tx dsvs sign-document "test_data/document1.pdf" "test_data/document2.pdf" "alvillarica@c3qtech.com" "" --from al-eph --yes

qadenad_alias tx dsvs sign-document "test_data/document2.pdf" "test_data/document3.pdf" "no-reply@sec.gov.ph" "" --from secdsvs-eph --yes
