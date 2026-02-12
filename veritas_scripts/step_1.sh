#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# inputs

treasurymnemonic=$(qadenad_alias keys mnemonic)
treasuryname="sec-treasury"
identityprovidername="secidentitysrvprv"
dsvsprovidername="secdsvssrvprv"
createwalletsponsorname="sec-create-wallet-sponsor"
dsvsname="secdsvs"
signermnemonic=$(qadenad_alias keys mnemonic)
createwalletsponsormnemonic=$(qadenad_alias keys mnemonic)
identityprovidermnemonic=$(qadenad_alias keys mnemonic)
dsvsprovidermnemonic=$(qadenad_alias keys mnemonic)
pioneer="pioneer1"
provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"
email="no-reply@sec.gov.ph"
avalue="200"
firstname="SEC"
birthdate="1936-Oct-26"
phone="+63282504521"

count=30


# accept named parameters to override all these mnemonics
# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --treasurymnemonic)
            treasurymnemonic="$2"
            shift 2
            ;;
        --treasuryname)
            treasuryname="$2"
            shift 2
            ;;
        --identityprovidername)
            identityprovidername="$2"
            shift 2
            ;;
        --dsvsprovidername)
            dsvsprovidername="$2"
            shift 2
            ;;
        --dsvsname)
            dsvsname="$2"
            shift 2
            ;;
        --signermnemonic)
            signermnemonic="$2"
            shift 2
            ;;
        --createwalletsponsormnemonic)
            createwalletsponsormnemonic="$2"
            shift 2
            ;;
        --createwalletsponsorname)
            createwalletsponsorname="$2"
            shift 2
            ;;
        --identityprovidermnemonic)
            identityprovidermnemonic="$2"
            shift 2
            ;;
        --dsvsprovidermnemonic)
            dsvsprovidermnemonic="$2"
            shift 2
            ;;
        --pioneer)
            pioneer="$2"
            shift 2
            ;;
        --provideramount)
            provideramount="$2"
            shift 2
            ;;
        --signeramount)
            signeramount="$2"
            shift 2
            ;;
        --createwalletsponsoramount)
            createwalletsponsoramount="$2"
            shift 2
            ;;
        --email)
            email="$2"
            shift 2
            ;;
        --avalue)
            avalue="$2"
            shift 2
            ;;
        --firstname)
            firstname="$2"
            shift 2
            ;;
        --birthdate)
            birthdate="$2"
            shift 2
            ;;
        --phone)
            phone="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--treasurymnemonic <mnemonic>] [--treasuryname <name>] [--signermnemonic <mnemonic>] [--createwalletsponsormnemonic <mnemonic>] [--identityprovidermnemonic <mnemonic>] [--dsvsprovidermnemonic <mnemonic>] [--count <count>] [--a <a>] [--email <email>] [--firstname <firstname>] [--birthdate <birthdate>] [--phone <phone>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--treasurymnemonic <mnemonic>] [--treasuryname <name>] [--signermnemonic <mnemonic>] [--createwalletsponsormnemonic <mnemonic>] [--identityprovidermnemonic <mnemonic>] [--dsvsprovidermnemonic <mnemonic>] [--count <count>] [--a <a>] [--email <email>] [--firstname <firstname>] [--birthdate <birthdate>] [--phone <phone>]"
            exit 1
            ;;
    esac
done

# write variables to json
jq -n --arg pioneer "$pioneer" --arg count "$count" --arg email "$email" --arg avalue "$avalue" --arg firstname "$firstname" --arg birthdate "$birthdate" --arg phone "$phone" --arg dsvsname "$dsvsname" --arg provideramount "$provideramount" --arg signeramount "$signeramount" --arg createwalletsponsoramount "$createwalletsponsoramount" --arg createwalletsponsorname "$createwalletsponsorname" --arg treasuryname "$treasuryname"  --arg identityprovidername "$identityprovidername" --arg dsvsprovidername "$dsvsprovidername" '{pioneer: $pioneer, count: $count, provideramount: $provideramount, signeramount: $signeramount, createwalletsponsoramount: $createwalletsponsoramount, createwalletsponsorname: $createwalletsponsorname, treasuryname: $treasuryname, identityprovidername: $identityprovidername, dsvsprovidername: $dsvsprovidername, dsvsname: $dsvsname, email: $email, avalue: $avalue, firstname: $firstname, birthdate: $birthdate, phone: $phone}' > variables.json

echo "-------------------------"
echo "Setting up $treasuryname"
echo "-------------------------"
$qadenaproviderscripts/setup_treasury.sh --treasury-name $treasuryname --treasury-mnemonic $treasurymnemonic

echo "Send this information to QFI"
echo "$treasuryname Qadena address:  $(qadenad_alias keys show $treasuryname --address)"

echo "When QFI grants the necessary amount to $treasuryname, run:  $veritasscripts/step_2.sh"

# create a json file containing all the mnemonics
jq -n --arg treasurymnemonic "$treasurymnemonic" --arg signermnemonic "$signermnemonic" --arg createwalletsponsormnemonic "$createwalletsponsormnemonic" --arg identityprovidermnemonic "$identityprovidermnemonic" --arg dsvsprovidermnemonic "$dsvsprovidermnemonic" '{treasurymnemonic: $treasurymnemonic, signermnemonic: $signermnemonic, createwalletsponsormnemonic: $createwalletsponsormnemonic, identityprovidermnemonic: $identityprovidermnemonic, dsvsprovidermnemonic: $dsvsprovidermnemonic}' > mnemonics.json


