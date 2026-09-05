#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"


source "$SCRIPT_DIR/../scripts/setup_env.sh"

# THE KEYRING IS THE NODE'S, AND SO IS ITS BACKEND.  These steps do not choose one.
#
# An earlier version defaulted them to `file`.  That was wrong for a reason worth recording: the
# keys these steps need are not all theirs.  Every create-wallet needs `$pioneer` -- the validator
# key -- which lives in the NODE's keyring-test, the one config/client.toml names and the one the
# node itself reads.  Defaulting to `file` created a SECOND, empty keyring beside it, prompted for
# a passphrase to open it, and would then have failed looking for a key that was never in it.
#
# Encrypting SEC's keys is still the right end state, but it needs a keyring of its own -- the way
# derive_launch_keys.sh uses --home ~/launch/coord -- plus a way to reach the pioneer from there.
# That is a design change, not a default.  Until then: export QADENA_KEYRING_BACKEND=file only if
# you have arranged both.

# inputs

treasurymnemonic=$(qadenad_alias keys mnemonic)
# SPONSORED IS THE DEFAULT FLOW.  In it the foundation pays for everything and SEC holds no
# tokens at all, so there is no SEC treasury -- step_2 and step_3 both repoint `treasuryname` at
# the foundation account and say "sec-treasury is not used".  Creating one anyway produced an
# account nothing referenced and an address printed as the handoff that was the WRONG address to
# hand over.  Set VERITAS_FUND_MODE=banksend for the retired path that does need it.


# SEC'S OWN DIRECTORY, THE WAY THE LAUNCH FLOW HAS ONE.
#
# Until now step_1 wrote variables.json and mnemonics.json into whatever the CURRENT DIRECTORY
# happened to be, and steps 2 and 3 read them the same way -- so the run only worked if every step
# was invoked from the same cwd, and nothing said which.  step_3's pool file went somewhere else
# again (veritas_scripts/).  One directory, named, with the same shape as ~/launch:
#
#   $VERITAS_SEC_HOME/
#       variables.json        the run's configuration -- names, counts, amounts, fund mode
#       mnemonics.json        THE KEYS.  Plaintext, 600, because steps 2 and 3 read it.
#       pool_addresses.json   written by step_3, handed to the foundation
#
# 700 on the directory and 600 on the file are the only protection mnemonics.json has.  It is the
# one artifact here whose loss is unrecoverable and whose disclosure is total: back it up off this
# machine, and delete it when the deployment is established.
: ${VERITAS_SEC_HOME:="$HOME/sec-veritas"}

# SEC'S KEYS LIVE WITH SEC'S FILES.
#
# Steps 1, 2 and 3 are all run by SEC, and every key they create is SEC's: the admin key, the two
# service providers, the create-wallet sponsor, the DSVS user.  None of them belongs to the node,
# and putting them in the node's keyring means `init.sh`'s `rm -rf $QADENAHOME` destroys the
# deployment's identities -- the same trap the launch flow avoids by keeping its keyring in
# ~/launch/coord rather than in the node home.
#
# --home still points at the node (config, and the RPC it talks to); only the KEYRING moves.
# Exported so the provider scripts these steps call inherit it without each needing a flag.
#
# The pioneer is NOT an obstacle: `create-wallet` takes a home-pioneer-ID string
# (x/qadena/client/cli/tx_create_wallet.go:160, argHomePioneerID), not a key name, so nothing here
# needs the validator's key to be in the same keyring.
export QADENA_KEYRING_DIR="$VERITAS_SEC_HOME/keyring"
mkdir -p "$QADENA_KEYRING_DIR" 2>/dev/null; chmod 700 "$QADENA_KEYRING_DIR" 2>/dev/null

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
adminmnemonic=""      # filled by `keys add --output json` below, or by --adminmnemonic
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
        --sec-home)
            VERITAS_SEC_HOME="$2"
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
            echo "  --sec-home <dir>   where variables.json / mnemonics.json / pool_addresses.json"
            echo "                     live.  Default \$VERITAS_SEC_HOME or ~/sec-veritas."
            echo "Usage: $0 [--sec-home <dir>] [--treasurymnemonic <mnemonic>] [--treasuryname <name>] [--signermnemonic <mnemonic>] [--createwalletsponsormnemonic <mnemonic>] [--identityprovidermnemonic <mnemonic>] [--dsvsprovidermnemonic <mnemonic>] [--count <count>] [--a <a>] [--email <email>] [--firstname <firstname>] [--birthdate <birthdate>] [--phone <phone>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "  --sec-home <dir>   where variables.json / mnemonics.json / pool_addresses.json"
            echo "                     live.  Default \$VERITAS_SEC_HOME or ~/sec-veritas."
            echo "Usage: $0 [--sec-home <dir>] [--treasurymnemonic <mnemonic>] [--treasuryname <name>] [--signermnemonic <mnemonic>] [--createwalletsponsormnemonic <mnemonic>] [--identityprovidermnemonic <mnemonic>] [--dsvsprovidermnemonic <mnemonic>] [--count <count>] [--a <a>] [--email <email>] [--firstname <firstname>] [--birthdate <birthdate>] [--phone <phone>]"
            exit 1
            ;;
    esac
done

mkdir -p "$VERITAS_SEC_HOME" || { echo "cannot create $VERITAS_SEC_HOME"; exit 1; }
chmod 700 "$VERITAS_SEC_HOME" 2>/dev/null

# write variables to json
jq -n --arg pioneer "$pioneer" --arg count "$count" --arg email "$email" --arg avalue "$avalue" --arg firstname "$firstname" --arg birthdate "$birthdate" --arg phone "$phone" --arg dsvsname "$dsvsname" --arg provideramount "$provideramount" --arg signeramount "$signeramount" --arg createwalletsponsoramount "$createwalletsponsoramount" --arg createwalletsponsorname "$createwalletsponsorname" --arg treasuryname "$treasuryname" --arg adminname "$adminname" --arg fundmode "$VERITAS_FUND_MODE"  --arg identityprovidername "$identityprovidername" --arg dsvsprovidername "$dsvsprovidername" '{pioneer: $pioneer, count: $count, provideramount: $provideramount, signeramount: $signeramount, createwalletsponsoramount: $createwalletsponsoramount, createwalletsponsorname: $createwalletsponsorname, treasuryname: $treasuryname, adminname: $adminname, fundmode: $fundmode, identityprovidername: $identityprovidername, dsvsprovidername: $dsvsprovidername, dsvsname: $dsvsname, email: $email, avalue: $avalue, firstname: $firstname, birthdate: $birthdate, phone: $phone}' > "$VERITAS_SEC_HOME/variables.json"

# REACHED ONLY WHEN SOMEONE ASKED FOR THE UNENCRYPTED KEYRING.
#
# This script now defaults to `file`, so getting here means the caller exported
# QADENA_KEYRING_BACKEND=test on purpose -- the devnet harness does, because an unattended fleet
# run cannot answer a passphrase prompt.  That is legitimate on a devnet and wrong on SEC's own
# machine, where sec-veritas-admin and the provider keys ARE the deployment.  Say so and continue:
# refusing would break the harness, and the harness is how everything else gets tested.
if [ "${QADENA_KEYRING_BACKEND:-test}" = "test" ]; then
    echo ""
    echo "  ** keyring-backend is 'test' -- an UNENCRYPTED keyring, plaintext on disk."
    echo "     Fine for a devnet.  For a real deployment, stop and re-run with:"
    echo "         export QADENA_KEYRING_BACKEND=file"
    echo "     Keys already created under 'test' do not move by changing this."
    echo ""
fi

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
    elif [ -n "$adminmnemonic" ]; then
        # ONLY WHEN THE OPERATOR SUPPLIED ONE.  --recover needs the mnemonic on stdin AND, under
        # backend=file, the passphrase after it -- two things down one pipe, in that order.
        { echo "$adminmnemonic"
          [ -z "${QADENA_KEYRING_PASS:-}" ] || { echo "$QADENA_KEYRING_PASS"; echo "$QADENA_KEYRING_PASS"; }
        } | qadenad_alias_raw keys add "$adminname" --recover --algo eth_secp256k1 > /dev/null \
            || { echo "   could not recover $adminname from the supplied mnemonic"; exit 1; }
        echo "recovered $adminname from --adminmnemonic"
    else
        # NO --recover, AND NO PIPE.  This script generates the mnemonic itself, so there is no
        # reason to make one with `keys mnemonic` and feed it back in: `keys add --output json`
        # creates the key AND returns the mnemonic in the same call.  That removes the only place
        # step_1 needed to pipe anything, which is what collided with the keyring passphrase under
        # backend=file and produced three bare "EOF" lines and no key.
        _out=$(qadenad_alias keys add "$adminname" --algo eth_secp256k1 --output json 2>&1) \
            || { echo "   could not create $adminname: $(echo "$_out" | tail -1)"; exit 1; }
        adminmnemonic=$(echo "$_out" | grep '^{' | tail -1 | jq -r '.mnemonic // empty')
        _wc=$(echo "$adminmnemonic" | wc -w | tr -d ' ')
        [ "$_wc" = "12" ] || [ "$_wc" = "24" ] || {
            echo "   keys add returned a $_wc-word mnemonic -- refusing to continue"; exit 1; }
        unset _out
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
    echo "QFI runs:  foundation_scripts/sec_veritas_after_step_1.sh --sec-admin $admin_addr"
    echo "Then run:  $veritasscripts/step_2.sh"
fi

# create a json file containing all the mnemonics
jq -n --arg treasurymnemonic "$treasurymnemonic" --arg adminmnemonic "$adminmnemonic" --arg signermnemonic "$signermnemonic" --arg createwalletsponsormnemonic "$createwalletsponsormnemonic" --arg identityprovidermnemonic "$identityprovidermnemonic" --arg dsvsprovidermnemonic "$dsvsprovidermnemonic" '{treasurymnemonic: $treasurymnemonic, adminmnemonic: $adminmnemonic, signermnemonic: $signermnemonic, createwalletsponsormnemonic: $createwalletsponsormnemonic, identityprovidermnemonic: $identityprovidermnemonic, dsvsprovidermnemonic: $dsvsprovidermnemonic}' > "$VERITAS_SEC_HOME/mnemonics.json"
chmod 600 "$VERITAS_SEC_HOME/mnemonics.json" 2>/dev/null


