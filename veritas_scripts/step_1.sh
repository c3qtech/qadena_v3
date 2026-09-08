#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"
# CAPTURE BEFORE SOURCING, AND DEFAULT TO `file`.
#
# setup_env.sh sets QADENA_KEYRING_BACKEND=test for the devnet harness, and this script sources
# it -- so a later ${QADENA_KEYRING_BACKEND:-file} would always see "test" and the intended
# default would be dead code.  The foundation scripts already capture it this way; the SEC steps
# did not, which is why step_1's own comment claimed it "defaults to file" while it did not.
#
# `file` IS THE RIGHT DEFAULT HERE.  These keys are the deployment: secidentitysrvprv signs
# credential issuance as SEC's identity provider, and sec-veritas-admin carries authz to issue fee
# grants as the foundation.  A `test` keyring is JWE-wrapped under a passphrase built into the
# SDK, so it opens with no prompt -- read access to the directory is read access to the keys.
# The unattended harnesses (setup_veritas/enf/ekycph) export `test` explicitly, which is the
# correct way to opt out: stated, not inherited.
_kb_caller="${QADENA_KEYRING_BACKEND:-}"


source "$SCRIPT_DIR/../scripts/setup_env.sh"
export QADENA_KEYRING_BACKEND="${_kb_caller:-file}"

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
# EXPORTED HERE, CREATED LATER.  The mkdir used to be on this line, and it ran BEFORE --sec-home
# was parsed -- so every run with --sec-home left an empty ~/sec-veritas/keyring behind, which
# looks exactly like a second deployment to anyone reading `ls ~`.  The only commands between here
# and the argument loop are `keys mnemonic`, which generates words and touches no keyring, so the
# directory is not needed until after parsing.  It is created there instead.
export QADENA_KEYRING_DIR="$VERITAS_SEC_HOME/keyring"


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
# THE FOUNDATION HANDOFF, AS ARGUMENTS.  QFI's before_step_1 prints these two addresses; they
# enter here ONCE and travel in variables.json, the same way count and pioneer do -- steps 2 and 3
# read them from the file instead of each demanding an exported VERITAS_FOUNDATION_APPSVR.  In
# sponsored mode the appsvr address is REQUIRED: it is the create-wallet sponsor and the fee
# granter for everything SEC does.
appsvraddr=""
usersaddr=""
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
# NO pioneer1 FALLBACK.  This defaulted to the DEVNET's pioneer, and on a launch chain that
# poisoned variables.json silently: every create-wallet then died on "Couldn't get jar for
# pioneer pioneer1" -- twice now.  The chain KNOWS its pioneers; derive it below, override with
# --pioneer (or QADENA_PIONEER) only when the chain has several.
pioneer="${QADENA_PIONEER:-}"
provideramount="100000qdn"
signeramount="100000qdn"
createwalletsponsoramount="100000qdn"
email="no-reply@sec.gov.ph"
avalue="200"
firstname="SEC"
birthdate="1936-Oct-26"
phone="+63282504521"

# NO DEFAULT.  The ephemeral count sizes everything downstream -- 4*(count+1) pre-grants, the
# pool, the per-wallet split of createwalletsponsoramount -- and a silent 30 makes a missing
# decision look like a made one.  Take it from --count or $VERITAS_COUNT; refuse otherwise.
count="${VERITAS_COUNT:-}"


# accept named parameters to override all these mnemonics
# Process command line arguments
_usage() {
    echo "Usage: veritas_scripts/step_1.sh --count <n> --appsvr <addr> [--users <addr>] [options]"
    echo ""
    echo "SEC's first step: creates this deployment's keys, writes \$VERITAS_SEC_HOME/variables.json"
    echo "and mnemonics.json, and prints the ADMIN ADDRESS plus the PRE-GRANT BLOCK for QFI."
    echo ""
    echo "Required:"
    echo "  --count <n>          ephemeral wallets per user.  NO DEFAULT: it sizes the pre-grants"
    echo "                       (4*(n+1)), the sponsor pool (n+1) and the per-wallet split."
    echo "  --appsvr <addr>      QFI's foundation-veritas-appsvr ADDRESS (sponsored mode)."
    echo "  --users  <addr>      QFI's foundation-veritas-users ADDRESS.  QFI's prepare stage"
    echo "                       prints both, as a ready-to-run copy of this command."
    echo ""
    echo "Chain and files:"
    echo "  --node <rpc>         the chain RPC (e.g. tcp://10.211.55.5:26657); the chain-id is"
    echo "                       derived from it, never trusted from a local file."
    echo "  --keyring-passfile <file>  first line is the keyring passphrase.  REQUIRED for an"
    echo "                       unattended run: the default backend is 'file', which otherwise"
    echo "                       prompts, and a prompt with no terminal looks like a hang."
    echo "  --sec-home <dir>     where variables.json / mnemonics.json / pool_addresses.json live."
    echo "                       Default \$VERITAS_SEC_HOME or ~/sec-veritas."
    echo "  --pioneer <name>     derived from the chain when omitted; pass it only if the chain"
    echo "                       has several pioneers."
    echo ""
    echo "Rarely needed:"
    echo "  --fund-mode banksend         restore the retired model where SEC holds a funded"
    echo "                               treasury.  You almost certainly do not want it."
    echo "  --<name>name / --<name>mnemonic    override a key's name, or supply an existing"
    echo "                               mnemonic instead of generating one.  Applies to: admin,"
    echo "                               treasury, signer, createwalletsponsor, identityprovider,"
    echo "                               dsvsprovider, dsvs."
    echo "  --provideramount / --createwalletsponsoramount / --signeramount / --avalue"
    echo "  --email / --firstname / --birthdate / --phone"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --treasurymnemonic)
            treasurymnemonic="$2"
            shift 2
            ;;
        --node)
            export QADENA_NODE="$2"
            shift 2
            ;;
        --keyring-passfile)
            export QADENA_KEYRING_PASSFILE="$2"
            shift 2
            ;;
        --appsvr)
            appsvraddr="$2"
            shift 2
            ;;
        --users)
            usersaddr="$2"
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
        --help|-h)
            _usage
                        exit 0
            ;;
        *)
            echo "Unknown option: $1"
            _usage
                        exit 1
            ;;
    esac
done

# RE-DERIVE AFTER PARSING.  $VERITAS_SEC_HOME is defaulted at the top and QADENA_KEYRING_DIR is
# exported from it there -- both BEFORE this loop runs, so --sec-home arrived too late to move the
# keyring.  The run then SPLIT itself across two directories: keys into the default
# ~/sec-veritas/keyring, mnemonics and variables.json into the requested one.  Everything after
# looked fine (the admin key was created, its address printed), and step_2 -- pointed at the
# requested home -- could not find that key, fell back to signing as the foundation, and died on
# "key with address <sponsor> not found".  Measured 2026-09-08 on the staging box, where
# ~/sec-veritas and ~/sec-veritas-staging both existed, two minutes apart.
export QADENA_KEYRING_DIR="$VERITAS_SEC_HOME/keyring"
mkdir -p "$QADENA_KEYRING_DIR" 2>/dev/null; chmod 700 "$QADENA_KEYRING_DIR" 2>/dev/null

# WARN ABOUT A SPLIT DEPLOYMENT, which is what the ordering bug above used to produce.
#
# step_1 fixed QADENA_KEYRING_DIR from the DEFAULT home before parsing --sec-home, so a run with
# --sec-home wrote keys to ~/sec-veritas and mnemonics to the requested directory.  Nothing said
# so: the admin key was created and its address printed, and the failure surfaced two steps later
# as "key with address <sponsor> not found" while signing as the foundation.  The ordering is
# fixed, but a directory left behind by an earlier run still looks like a working deployment.
if [[ "$VERITAS_SEC_HOME" != "$HOME/sec-veritas" ]] \
   && ls "$HOME/sec-veritas"/keyring/keyring-*/*.info > /dev/null 2>&1; then
    echo ""
    echo "NOTE: $HOME/sec-veritas also holds keys, and this run uses $VERITAS_SEC_HOME."
    echo "  A version of step_1 before 2026-09-08 wrote keys to the default home while writing"
    echo "  mnemonics to --sec-home, splitting a deployment across both.  If this run cannot find"
    echo "  a key it expects, look there:"
    echo "      ls $HOME/sec-veritas/keyring/keyring-file/"
    echo "  and either move them across or start clean.  Nothing is read from there automatically."
    echo ""
fi

# UNLOCK ONCE, HERE.  qadena_keyring_unlock has existed in setup_env.sh since the file backend was
# added and was never called from anywhere -- so with backend=file, QADENA_KEYRING_PASS stayed
# empty, qadenad_alias took its no-passphrase branch, and qadenad blocked reading stdin with the
# prompt swallowed by whatever call site had captured its output.  That is a hang with no message
# and no prompt (measured 2026-09-07 on step_2).  Called after argument parsing so
# --keyring-passfile is already in effect.
qadena_keyring_unlock

mkdir -p "$VERITAS_SEC_HOME" || { echo "cannot create $VERITAS_SEC_HOME"; exit 1; }
chmod 700 "$VERITAS_SEC_HOME" 2>/dev/null

# RE-RUNS REUSE THE EXISTING MNEMONICS.  Every mnemonic above was freshly generated -- which on a
# re-run would ORPHAN everything derived from the previous set: the foundation pre-grants 124
# addresses computed from these exact mnemonics, and regenerating them silently strands every
# grant already signed.  If a mnemonics.json exists, it is the deployment; the generated values
# are discarded in its favour.  Delete the file (or point --sec-home elsewhere) to start over.
# REUSE WHAT EXISTS, WHATEVER FORM IT IS IN.  Regenerating these would orphan every pre-grant the
# foundation has already signed against the derived addresses, so a re-run must reuse them.  Sealed
# files are the current form; mnemonics.json is the legacy one and is still honoured so a
# deployment created before this change keeps working.
if [ -d "$VERITAS_SEC_HOME/mnemonics" ] && ls "$VERITAS_SEC_HOME/mnemonics"/*.mnemonic.enc > /dev/null 2>&1; then
    echo "reusing sealed mnemonics from $VERITAS_SEC_HOME/mnemonics (re-run)"
    for _v in treasurymnemonic adminmnemonic signermnemonic createwalletsponsormnemonic \
              identityprovidermnemonic dsvsprovidermnemonic; do
        _m=$(sec_mnemonic "$VERITAS_SEC_HOME" "$_v" 2>/dev/null || true)
        [ -n "$_m" ] && eval "$_v=\$_m"
    done
elif [ -r "$VERITAS_SEC_HOME/mnemonics.json" ]; then
    echo "reusing mnemonics from $VERITAS_SEC_HOME/mnemonics.json (LEGACY plaintext; seal it with"
    echo "  veritas_scripts/seal_sec_mnemonics.sh --remove-plaintext)"
    for _v in treasurymnemonic adminmnemonic signermnemonic createwalletsponsormnemonic \
              identityprovidermnemonic dsvsprovidermnemonic; do
        _m=$(jq -r ".$_v // empty" "$VERITAS_SEC_HOME/mnemonics.json")
        [ -n "$_m" ] && eval "$_v=\$_m"
    done
fi

# DERIVE THE PIONEER FROM THE CHAIN when not given.
#
# TWO SOURCES, AND THEY ANSWER DIFFERENT QUESTIONS:
#
#   list-interval-public-key-id   WHICH PIONEERS EXIST.  Authoritative -- a pioneer that is not
#                                 registered here cannot serve a jar, so this is the set we are
#                                 allowed to choose from.
#   status .node_info.moniker     WHICH ONE YOU ARE TALKING TO.  A node names itself, and the
#                                 fleet bringup sets moniker = pioneer id (verified on M1/M2,
#                                 2026-09-06).  It cannot be trusted alone -- a moniker is free
#                                 text -- but it is the operator's OWN choice of endpoint, which
#                                 is exactly the information missing when several pioneers exist.
#
# So: the registry decides what is valid, the moniker breaks the tie.  A moniker that is not a
# registered pioneer is ignored rather than trusted.  Never guess: writing a wrong pioneer into
# variables.json surfaces much later as "Couldn't get jar for pioneer X", mid-create-wallet,
# after keys exist.
if [ -z "$pioneer" ]; then
    _pioneers=$(qadenad_alias query qadena list-interval-public-key-id --output json 2>/dev/null \
                  | jq -r '[.intervalPublicKeyID[]? | select(.nodeType=="pioneer") | .nodeID] | .[]' 2>/dev/null)
    _n=$(echo "$_pioneers" | grep -c . || true)
    if [ "$_n" -eq 1 ]; then
        pioneer="$_pioneers"
        echo "pioneer derived from the chain: $pioneer"
    elif [ "$_n" -gt 1 ]; then
        _moniker=$(qadenad_alias status 2>/dev/null | jq -r '.node_info.moniker // empty' 2>/dev/null)
        if [ -n "$_moniker" ] && echo "$_pioneers" | grep -qx "$_moniker"; then
            pioneer="$_moniker"
            echo "this chain has $_n pioneers; using '$pioneer' -- the node you pointed --node at."
            echo "  (override with --pioneer <id>; the others are: $(echo "$_pioneers" | grep -vx "$_moniker" | tr '\n' ' '))"
        else
            echo "this chain has $_n pioneers and the node you are connected to is not one of them"
            echo "(moniker '${_moniker:-<none>}') -- pick one with --pioneer <id>:"
            echo "$_pioneers" | sed 's/^/    /'
            exit 1
        fi
    else
        echo "cannot derive the pioneer (chain unreachable?).  Pass --pioneer <id>, e.g."
        echo "    veritas_scripts/step_1.sh --pioneer qfi-pioneer1 ..."
        exit 1
    fi
fi

if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    case "$appsvraddr" in
        qadena1*) ;;
        *)
            echo "sponsored mode needs the foundation sponsor's ADDRESS:"
            echo "    veritas_scripts/step_1.sh --appsvr qadena1... --users qadena1... --count <n>"
            echo "Both are printed by QFI's sec_veritas_before_step_1.sh."
            exit 1 ;;
    esac
    case "$usersaddr" in
        qadena1*|'') ;;
        *) echo "--users '$usersaddr' is not a qadena address"; exit 1 ;;
    esac
fi

case "$count" in
    ''|*[!0-9]*)
        echo "the ephemeral-wallet count is required and must be a number."
        echo "    veritas_scripts/step_1.sh --count <n>      # or: export VERITAS_COUNT=<n>"
        echo "It sizes the pre-grants (4*(n+1)), the sponsor pool (n+1) and the per-wallet split;"
        echo "there is deliberately no default."
        exit 1 ;;
esac

# write variables to json
jq -n --arg pioneer "$pioneer" --arg count "$count" --arg email "$email" --arg avalue "$avalue" --arg firstname "$firstname" --arg birthdate "$birthdate" --arg phone "$phone" --arg dsvsname "$dsvsname" --arg provideramount "$provideramount" --arg signeramount "$signeramount" --arg createwalletsponsoramount "$createwalletsponsoramount" --arg createwalletsponsorname "$createwalletsponsorname" --arg treasuryname "$treasuryname" --arg adminname "$adminname" --arg fundmode "$VERITAS_FUND_MODE" --arg appsvraddr "$appsvraddr" --arg usersaddr "$usersaddr"  --arg identityprovidername "$identityprovidername" --arg dsvsprovidername "$dsvsprovidername" '{pioneer: $pioneer, count: $count, provideramount: $provideramount, signeramount: $signeramount, createwalletsponsoramount: $createwalletsponsoramount, createwalletsponsorname: $createwalletsponsorname, treasuryname: $treasuryname, adminname: $adminname, fundmode: $fundmode, appsvraddr: $appsvraddr, usersaddr: $usersaddr, identityprovidername: $identityprovidername, dsvsprovidername: $dsvsprovidername, dsvsname: $dsvsname, email: $email, avalue: $avalue, firstname: $firstname, birthdate: $birthdate, phone: $phone}' > "$VERITAS_SEC_HOME/variables.json"

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
    # ------------------------------------------------------------------------------------------
    # EVERY WALLET THE WHOLE BRING-UP WILL CREATE, DERIVED NOW, OFFLINE.
    #
    # Four user families -- the two providers (created by step_2), the create-wallet sponsor and
    # the DSVS user (created by step_3) -- each a main wallet plus $count ephemerals: 4*(count+1)
    # addresses, 124 at the default count.  Each one's FIRST transaction needs a fee allowance
    # SIGNED by the foundation sponsor (chain rule: MsgGrantAllowance is signed by its granter,
    # and the granter's balance pays -- grants do not chain).  Deriving the addresses here, from
    # mnemonics this step just generated, lets QFI pre-grant all of them from their own machine
    # BEFORE anything is created -- so no step of SEC's ever needs a foundation key.  An earlier
    # version emitted this at the end of step_2, which was too late for step_2's own provider
    # wallets: the first create-wallet refused with "no fee allowance ... sponsor's key is not in
    # this keyring", which is exactly the refusal working as designed, one step early.
    #
    # `debug derive-wallet-address` wraps the SAME GetEphAccountAddress create-wallet uses, so
    # what QFI grants against is what the chain will see -- by construction.
    derive_addr() {   # derive_addr <mnemonic> <index>
        echo "$1" | qadenad_alias_raw debug derive-wallet-address "$2" 2>/dev/null | tail -1
    }
    pregrant_file="$VERITAS_SEC_HOME/pregrant_addresses.json"
    {
        printf '{\n'
        printf '  "chain_id": "%s",\n' "$(qadenad_alias status 2>/dev/null | jq -r '.node_info.network // ""')"
        printf '  "sec_admin": "%s",\n' "$admin_addr"
        printf '  "count": %s,\n' "$count"
        printf '  "wallets": [\n'
        _first=1
        for _pair in "$identityprovidername:$identityprovidermnemonic" \
                     "$dsvsprovidername:$dsvsprovidermnemonic" \
                     "$createwalletsponsorname:$createwalletsponsormnemonic" \
                     "$dsvsname:$signermnemonic"; do
            _wname="${_pair%%:*}"; _wmn="${_pair#*:}"
            for _i in $(seq 0 "$count"); do
                _a=$(derive_addr "$_wmn" "$_i")
                [ -n "$_a" ] || { echo "  WARNING: could not derive $_wname index $_i" >&2; continue; }
                if [ "$_i" -eq 0 ]; then _n="$_wname"; else _n="$_wname-eph$_i"; fi
                [ "$_first" -eq 1 ] || printf ',\n'
                printf '    {"name": "%s", "address": "%s"}' "$_n" "$_a"
                _first=0
            done
        done
        printf '\n  ]\n}\n'
    } > "$pregrant_file"

    echo ""
    echo "==================================================================="
    echo "SEND THIS BLOCK TO QFI -- they paste it into a terminal as-is:"
    echo "==================================================================="
    echo ""
    echo "cat > /tmp/veritas-pregrant.json <<'PREGRANTEOF'"
    cat "$pregrant_file"
    echo "PREGRANTEOF"
    echo "foundation_scripts/sec_veritas_after_step_1.sh --pregrant /tmp/veritas-pregrant.json \\"
    echo "    --coord-home ~/launch/coord${QADENA_NODE:+ --node $QADENA_NODE}"
    echo ""
    echo "==================================================================="
    jq -r '"  sec-admin \(.sec_admin)   wallets \(.wallets|length)   chain \(.chain_id)"' "$pregrant_file" 2>/dev/null
    echo ""
    echo "QFI authorises the admin AND pre-grants every wallet above, from their machine."
    echo "Then run:  $veritasscripts/step_2.sh"
fi

# SEALED DIRECTLY FROM THE VARIABLES.  NO PLAINTEXT FILE IS WRITTEN.
#
# This used to write mnemonics.json -- six seed phrases in the clear, protected by 600 on the file
# and 700 on the directory and nothing else.  They derive every SEC wallet on the chain: both
# service providers, the whole citizen sponsor pool, the document counter-signer, the delegation
# key.  One `cat` was the deployment.
#
# The foundation has never done that (derive_launch_keys.sh): the mnemonic goes from qadenad's
# stdout through a shell variable into openssl's stdin and lands as ciphertext, so it is never
# readable at rest and a crash mid-run leaves nothing behind.  Same here now.
#
# THE PASSPHRASE GOES ON FD 3, not stdin.  stdin carries the mnemonic; openssl given both on one
# stream takes the first line as the passphrase and mis-reads the rest as data, producing a file
# that seals "successfully" and never decrypts.  The verification below is what catches that.
_MDIR="$VERITAS_SEC_HOME/mnemonics"
mkdir -p "$_MDIR"; chmod 700 "$_MDIR"
if [ -z "${QADENA_KEYRING_PASS:-}" ]; then
    echo "REFUSING to write mnemonics: no keyring passphrase in this run, so they could only be"
    echo "  stored in the clear.  Re-run with --keyring-passfile <file>, or export"
    echo "  QADENA_KEYRING_BACKEND=test for a throwaway devnet."
    exit 1
fi
_sealed=0
for _spec in "treasurymnemonic:$treasurymnemonic" "adminmnemonic:$adminmnemonic" \
             "signermnemonic:$signermnemonic" "createwalletsponsormnemonic:$createwalletsponsormnemonic" \
             "identityprovidermnemonic:$identityprovidermnemonic" "dsvsprovidermnemonic:$dsvsprovidermnemonic"; do
    _mk="${_spec%%:*}"; _mv="${_spec#*:}"
    [ -n "$_mv" ] || continue
    _mf="$_MDIR/$_mk.mnemonic.enc"
    if ! print -r -- "$_mv" | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
            -out "$_mf" -pass fd:3 3< <(print -r -- "$QADENA_KEYRING_PASS") 2>/dev/null; then
        echo "FAILED to seal $_mk -- the key exists but would be UNRECOVERABLE.  Stopping."
        rm -f "$_mf"
        exit 1
    fi
    chmod 600 "$_mf"
    # VERIFY THE ROUND TRIP BEFORE MOVING ON.  A sealed file that does not decrypt is worse than no
    # file: it looks like a backup.  This is the check that caught the fd-3 problem above.
    _back=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$_mf" \
              -pass fd:3 3< <(print -r -- "$QADENA_KEYRING_PASS") 2>/dev/null || true)
    if [ "$_back" != "$_mv" ]; then
        echo "FAILED to verify $_mk -- it sealed but does not decrypt back.  Stopping."
        rm -f "$_mf"
        exit 1
    fi
    _sealed=$(( _sealed + 1 ))
done
echo "$_sealed mnemonic(s) sealed and verified in $_MDIR -- no plaintext was written"


