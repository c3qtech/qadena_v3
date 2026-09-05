#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# inputs

treasurymnemonic=$(qadenad_alias keys mnemonic)
# SPONSORED IS THE DEFAULT FLOW.  In it the foundation pays for everything and SEC holds no
# tokens at all, so there is no SEC treasury -- step_2 and step_3 both repoint `treasuryname` at
# the foundation account and say "sec-treasury is not used".  Creating one anyway produced an
# account nothing referenced and an address printed as the handoff that was the WRONG address to
# hand over.  Set VERITAS_FUND_MODE=banksend for the retired path that does need it.

treasuryname="sec-treasury"

# THE ADMIN KEY, AND WHY IT HOLDS NOTHING.
#
# A wallet on a toll-free chain cannot pay its own fees -- it cannot even claim its credential --
# so every wallet SEC creates needs a fee grant.  A fee grant is signed by its GRANTER, which must
# be the foundation, and SEC cannot hold a foundation key.
#
# authz closes that: the foundation authorises THIS key to send MsgGrantAllowance on its behalf,
# SEC wraps each grant in a MsgExec signed by this key, and the foundation fee-grants the MsgExec
# so this key never needs a balance.  Its balance staying at exactly zero is the design working,
# not a state to fix.
#
# Dedicated rather than reused: GenericAuthorization cannot cap an amount or restrict a recipient,
# so whoever holds this can drain its granter.  That belongs on a key which can be rotated and
# revoked without disturbing the provider identities governance has registered.
adminname="sec-veritas-admin"
adminmnemonic=$(qadenad_alias keys mnemonic)
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
        --adminname)
            adminname="$2"
            shift 2
            ;;
        --adminmnemonic)
            adminmnemonic="$2"
            shift 2
            ;;
        --fund-mode)
            VERITAS_FUND_MODE="$2"
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
jq -n --arg pioneer "$pioneer" --arg count "$count" --arg email "$email" --arg avalue "$avalue" --arg firstname "$firstname" --arg birthdate "$birthdate" --arg phone "$phone" --arg dsvsname "$dsvsname" --arg provideramount "$provideramount" --arg signeramount "$signeramount" --arg createwalletsponsoramount "$createwalletsponsoramount" --arg createwalletsponsorname "$createwalletsponsorname" --arg treasuryname "$treasuryname" --arg adminname "$adminname" --arg fundmode "$VERITAS_FUND_MODE"  --arg identityprovidername "$identityprovidername" --arg dsvsprovidername "$dsvsprovidername" '{pioneer: $pioneer, count: $count, provideramount: $provideramount, signeramount: $signeramount, createwalletsponsoramount: $createwalletsponsoramount, createwalletsponsorname: $createwalletsponsorname, treasuryname: $treasuryname, adminname: $adminname, fundmode: $fundmode, identityprovidername: $identityprovidername, dsvsprovidername: $dsvsprovidername, dsvsname: $dsvsname, email: $email, avalue: $avalue, firstname: $firstname, birthdate: $birthdate, phone: $phone}' > variables.json

if [ "$VERITAS_FUND_MODE" = "banksend" ]; then
    echo "-------------------------"
    echo "Setting up $treasuryname  (banksend mode)"
    echo "-------------------------"
    $qadenaproviderscripts/setup_treasury.sh --treasury-name $treasuryname --treasury-mnemonic $treasurymnemonic
    echo "Send this information to QFI"
    echo "$treasuryname Qadena address:  $(qadenad_alias keys show $treasuryname --address)"
    echo "When QFI grants the necessary amount to $treasuryname, run:  $veritasscripts/step_2.sh"
else
    echo "-------------------------"
    echo "Setting up $adminname  (sponsored -- no SEC treasury)"
    echo "-------------------------"
    if qadenad_alias keys show "$adminname" > /dev/null 2>&1; then
        echo "$adminname already exists -- keeping it"
    else
        echo "$adminmnemonic" | qadenad_alias keys add "$adminname" --recover --algo eth_secp256k1 > /dev/null
        echo "created $adminname"
    fi
    admin_addr=$(qadenad_alias keys show "$adminname" --address)
    echo ""
    echo "SEND THIS ONE ADDRESS TO QFI:"
    echo "    $adminname : $admin_addr"
    echo ""
    echo "This key holds NO tokens and never will.  QFI authorises it to issue fee grants on the"
    echo "foundation's behalf, and pays for those transactions.  Export it before step_2/step_3:"
    echo "    export VERITAS_SEC_ADMIN=$adminname"
    echo ""
    echo "QFI runs:  foundation_scripts/veritas_sec_delegate_grant_authority.sh --sec-admin $admin_addr"
    echo "Then run:  $veritasscripts/step_2.sh"
fi

# create a json file containing all the mnemonics
jq -n --arg treasurymnemonic "$treasurymnemonic" --arg adminmnemonic "$adminmnemonic" --arg signermnemonic "$signermnemonic" --arg createwalletsponsormnemonic "$createwalletsponsormnemonic" --arg identityprovidermnemonic "$identityprovidermnemonic" --arg dsvsprovidermnemonic "$dsvsprovidermnemonic" '{treasurymnemonic: $treasurymnemonic, adminmnemonic: $adminmnemonic, signermnemonic: $signermnemonic, createwalletsponsormnemonic: $createwalletsponsormnemonic, identityprovidermnemonic: $identityprovidermnemonic, dsvsprovidermnemonic: $dsvsprovidermnemonic}' > mnemonics.json


