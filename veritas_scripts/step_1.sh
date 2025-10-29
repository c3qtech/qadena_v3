#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# inputs

sectreasurymnemonic=$(qadenad_alias keys mnemonic)
signermnemonic=$(qadenad_alias keys mnemonic)
createwalletsponsormnemonic=$(qadenad_alias keys mnemonic)
identityprovidermnemonic=$(qadenad_alias keys mnemonic)
dsvsprovidermnemonic=$(qadenad_alias keys mnemonic)
pioneer="pioneer1"
provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"

count=30


# accept named parameters to override all these mnemonics
# Process command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sectreasurymnemonic)
            sectreasurymnemonic="$2"
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
        --count)
            count="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--sectreasurymnemonic <mnemonic>] [--signermnemonic <mnemonic>] [--createwalletsponsormnemonic <mnemonic>] [--identityprovidermnemonic <mnemonic>] [--dsvsprovidermnemonic <mnemonic>] [--count <count>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--sectreasurymnemonic <mnemonic>] [--signermnemonic <mnemonic>] [--createwalletsponsormnemonic <mnemonic>] [--identityprovidermnemonic <mnemonic>] [--dsvsprovidermnemonic <mnemonic>] [--count <count>]"
            exit 1
            ;;
    esac
done

# write variables to json
jq -n --arg pioneer "$pioneer" --arg count "$count" --arg provideramount "$provideramount" --arg signeramount "$signeramount" --arg createwalletsponsoramount "$createwalletsponsoramount" '{pioneer: $pioneer, count: $count, provideramount: $provideramount, signeramount: $signeramount, createwalletsponsoramount: $createwalletsponsoramount}' > variables.json

echo "-------------------------"
echo "Setting up sec-treasury"
echo "-------------------------"
$qadenaproviderscripts/setup_treasury.sh --treasury-name sec-treasury --treasury-mnemonic $sectreasurymnemonic

echo "Send this information to QFI"
echo "sec-treasury Qadena address:  $(qadenad_alias keys show sec-treasury --address)"

echo "When QFI grants the necessary amount to sec-treasury, run:  $veritas_scripts/step_2.sh"

# create a json file containing all the mnemonics
jq -n --arg sectreasurymnemonic "$sectreasurymnemonic" --arg signermnemonic "$signermnemonic" --arg createwalletsponsormnemonic "$createwalletsponsormnemonic" --arg identityprovidermnemonic "$identityprovidermnemonic" --arg dsvsprovidermnemonic "$dsvsprovidermnemonic" '{sectreasurymnemonic: $sectreasurymnemonic, signermnemonic: $signermnemonic, createwalletsponsormnemonic: $createwalletsponsormnemonic, identityprovidermnemonic: $identityprovidermnemonic, dsvsprovidermnemonic: $dsvsprovidermnemonic}' > mnemonics.json


