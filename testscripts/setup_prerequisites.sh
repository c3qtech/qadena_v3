#!/bin/zsh
#
# Stands up everything testscripts/setup.sh assumes already exists, at RUNTIME rather than in
# genesis.  config/config.yml is now down to two accounts -- pioneer1 and treasury, the chain's own
# bootstrap identity -- and everything else is created here:
#
#   create-wallet-sponsor   imported and funded from the treasury
#   testidentitysrvprv      create-wallet + MsgAddServiceProvider governance proposal
#   testdsvssrvprv          same
#
# Why the providers cannot just be genesis entries:
#
#   A genesis-declared provider is only a funded account plus some hand-written pubK rows.  It never
#   runs `tx qadena create-wallet`, and create-wallet is what derives BOTH keys a provider needs --
#   the transaction key at HD account index 0 and the <name>-credential key at index 1
#   (CredentialWalletType, see x/qadena/types/keys.go and CreatePublicKey in x/qadena/common) -- and
#   registers both pubKs on chain.  Genesis providers therefore have no -credential key at all,
#   which is why sign-recover-key's --is-service-provider branch (x/qadena/client/cli) cannot sign
#   for them when they are named as a key-recovery partner.
#
#   Onboarding through create-wallet + a MsgAddServiceProvider governance proposal is also the shape
#   a live chain needs: providers arrive by governance, not by editing genesis.  This is the same
#   path testscripts/setup_veritas.sh uses for the SEC providers, via the same building blocks in
#   provider_scripts/.
#
#   The sponsor is different: it is only a signer and fee payer, so it needs no create-wallet and no
#   registration.  It lives here purely so that no operational key ships in genesis.
#
# ORDER: run this AFTER the chain is up (scripts/start_qadena.sh) and BEFORE testscripts/setup.sh.
#
# Re-running is safe: anything that already has a keyring entry is skipped.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# set -e goes AFTER the source on purpose.  setup_env.sh's set_min_gas_price queries the chain and
# falls back to a default when that fails; with set -e already active the failed assignment kills
# the script during sourcing, so --help would not print and the "chain is not reachable" preflight
# below could never report anything.
set -e

# setup_env.sh exposes qadenad_alias as an alias.  Aliases only expand at parse time in command
# position, so shadow it with a function -- that keeps it usable from inside the functions below.
function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

# These mnemonics were moved verbatim out of config/config.yml accounts:.  Keeping them unchanged is
# deliberate: create-wallet derives the transaction key at the same path ignite used, so each
# provider keeps the exact address genesis used to give it and existing test data still resolves.
identityprovidername="testidentitysrvprv"
identityprovidermnemonic="lemon onion exit success feature wait admit permit nation behind vintage summer oven weird blue flash motor maple fiber domain cement inmate slogan avoid"

dsvsprovidername="testdsvssrvprv"
dsvsprovidermnemonic="twenty shoulder tomato hawk toilet pave famous critic undo beef country object perfect staff net dilemma fade insane enemy oven barrel organ cherry problem"

# also moved out of config/config.yml.  A create-wallet sponsor is only a signer and fee payer, so
# unlike a provider it needs no create-wallet and no on-chain registration -- a keyring entry with a
# balance is the whole requirement.  Same mnemonic as genesis used, so the address does not move.
sponsorname="create-wallet-sponsor"
sponsormnemonic="guilt decline utility scale crash envelope snap table dress coach tray use detect success lemon fatigue surround project warfare victory mean midnight address before"

# Price oracles, also moved out of config/config.yml.  Genesis ships every market with an EMPTY
# oracle list -- the seeded postedPriceList still yields working current prices, but nobody is
# authorised to post new ones until the pricefeed MsgUpdateParams proposal below runs.
oraclenames=(coingecko-oracle band-protocol-oracle)
oraclemnemonics=(
    "area symptom room bomb atom relief give pole relief truly elbow unknown undo wild clutch ozone liar small occur off enjoy shop busy meadow"
    "verb select bread spirit beyond snow slender lumber ramp rule tribe soldier help area remove guard cage knife witness era mule afford wage like"
)
oracleamount="100000qdn"

pioneer="pioneer1"
treasury="treasury"

# what each provider used to get from genesis coins:
provideramount="1000000qdn"

# what create-wallet-sponsor used to get from genesis coins:
sponsoramount="100000qdn"

# treasury holds 2B qdn at genesis but no delegation, so it has no voting power until it stakes.
# Without this the proposals reach the voting period and then fail quorum.
stakeamount="10000000qdn"

# ephemeral wallets per provider.  Nothing in the test suite addresses <provider>-eph*, so the
# default is 0; veritas uses 30 because its providers hand out ephemeral wallets at scale.
count=0

skip_stake=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pioneer)
            pioneer="$2"
            shift 2
            ;;
        --treasury)
            treasury="$2"
            shift 2
            ;;
        --provider-amount)
            provideramount="$2"
            shift 2
            ;;
        --stake-amount)
            stakeamount="$2"
            shift 2
            ;;
        --sponsor-amount)
            sponsoramount="$2"
            shift 2
            ;;
        --count)
            count="$2"
            shift 2
            ;;
        --skip-stake)
            skip_stake=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--pioneer <pioneer>] [--treasury <treasury>] [--provider-amount <amt>]"
            echo "          [--stake-amount <amt>] [--sponsor-amount <amt>] [--count <eph-wallets>]"
            echo "          [--skip-stake]"
            echo ""
            echo "Creates $sponsorname, then onboards $identityprovidername (identity)"
            echo "and $dsvsprovidername (dsvs) by create-wallet + governance proposal."
            echo "Run after the chain is up, before setup.sh."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Try: $0 --help"
            exit 1
            ;;
    esac
done

fail() {
    echo "FAILED: $1"
    exit 1
}

key_exists() {
    qadenad_alias keys show "$1" --keyring-backend test > /dev/null 2>&1
}

# Every guard below tests the END STATE, not "did we run this before".  A run interrupted partway
# leaves keys without funds, or a wallet without a registration, and a guard that only asked
# "is the key there?" would skip straight past the unfinished half.
provider_registered() {
    qadenad_alias query qadena show-interval-public-key-id "$1" srv-prv > /dev/null 2>&1
}

# echoes the account's balance, or 0 when the account does not exist on chain yet.
# the "|| amt=" matters under set -e: an account with no on-chain presence makes the query fail,
# and a bare failing assignment would abort the script instead of reporting a zero balance.
balance_of() {
    local amt
    amt=$(qadenad_alias query bank balances "$1" --output json 2>/dev/null \
        | jq -r '.balances[0].amount // "0"' 2>/dev/null) || amt=""
    echo "${amt:-0}"
}

# import_and_fund <keyname> <mnemonic> <amount>
#
# Import and funding are guarded SEPARATELY on purpose: a run that died between the two would leave
# a keyring entry with no balance, and a guard that only asked "is the key there?" would skip past
# it -- producing an account that cannot pay fees and fails much later, somewhere unrelated.
import_and_fund() {
    local name="$1" mnemonic="$2" amount="$3" addr

    if key_exists "$name"; then
        echo "$name already in the keyring"
    else
        echo "$mnemonic" | qadenad_alias keys add "$name" --recover --keyring-backend test \
            || fail "could not import $name"
        echo "$name imported"
    fi

    addr=$(qadenad_alias keys show "$name" -a --keyring-backend test) \
        || fail "could not resolve $name address"

    if [ "$(balance_of "$addr")" != "0" ]; then
        echo "$name ($addr) already funded, balance $(balance_of "$addr")"
        return 0
    fi

    echo "funding $name ($addr) with $amount from $treasury"
    local result tx_hash
    result=$(qadenad_alias tx bank send "$treasury" "$addr" "$amount" \
        --from "$treasury" --yes --output json \
        --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment) \
        || fail "bank send to $name failed"

    tx_hash=$(echo "$result" | jq -r .txhash)
    qadenad_alias query wait-tx "$tx_hash" --timeout 30s > /dev/null \
        || fail "funding tx $tx_hash for $name did not land"

    # prove the funds actually arrived rather than trusting the tx receipt
    [ "$(balance_of "$addr")" != "0" ] || fail "$name has no balance after funding"
    echo "$name funded, balance $(balance_of "$addr")"
}

# oracles registered on a market, as a count
oracle_count() {
    local n
    n=$(qadenad_alias query pricefeed oracles "$1" --output json 2>/dev/null \
        | jq -r '.oracles | length' 2>/dev/null) || n=""
    echo "${n:-0}"
}

echo "========================="
echo "preflight"
echo "========================="

qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first (scripts/start_qadena.sh)"

key_exists "$treasury" || fail "treasury key '$treasury' not found in the keyring"
key_exists "$pioneer" || fail "pioneer key '$pioneer' not found in the keyring"

# A REACHABLE CHAIN IS NOT A READY ONE.
#
# The first thing this script does is fund accounts by direct bank send, and every such send is now
# AML-scanned in the enclave.  The enclave is initialised by delayed_init_enclave.sh, which waits for
# block height 4 -- so for the first few blocks the chain answers `status` perfectly well while every
# scanned send is refused, and the funding fails with nothing to say why.
#
# This did not matter while the treasuries were exempt from scanning: their sends never reached the
# enclave, so it did not have to be up.  Removing that exemption made chain readiness depend on
# enclave readiness, and this is the place that discovers it first.
#
# A jar regulator is the signal because it is created BY InitEnclave -- the enclave registers its
# regulator identity as part of coming up -- and it is queryable from the chain.  It is also exactly
# what a report needs, so waiting for it means the scan can both measure and report.
echo "waiting for the enclave to finish initialising..."
enclave_ready=false
for _ in $(seq 1 90); do
    if [ "$(qadenad_alias query qadena list-jar-regulator --output json 2>/dev/null \
            | jq -r '.jarRegulator | length' 2>/dev/null)" -gt 0 ] 2>/dev/null; then
        enclave_ready=true
        break
    fi
    sleep 2
done
[ "$enclave_ready" = "true" ] \
    || fail "the enclave did not initialise within 180s -- no jar regulator on chain, so every scanned bank send would be refused"

echo "chain up, enclave initialised, '$treasury' and '$pioneer' present"

echo "========================="
echo "create-wallet sponsor: $sponsorname"
echo "========================="
# No create-wallet here on purpose.  A sponsor is only the signer and fee payer of somebody else's
# MsgCreateWallet, so a plain keyring entry with a balance is enough -- which is exactly what the
# genesis account was.  The on-chain account materialises when the treasury funds it.
import_and_fund "$sponsorname" "$sponsormnemonic" "$sponsoramount"

echo "========================="
echo "voting power for $treasury"
echo "========================="
if [ "$skip_stake" = "true" ]; then
    echo "skipping stake (--skip-stake); assuming $treasury already has voting power"
else
    # Staking is the one step with no natural skip condition -- gov_stake_from_treasury.sh just
    # delegates again -- so check first.  Any existing delegation means the treasury can already
    # vote, which is all this step is for.
    treasuryaddr=$(qadenad_alias keys show "$treasury" -a --keyring-backend test) \
        || fail "could not resolve $treasury address"
    # same set -e guard as balance_of: a treasury with no delegations makes the query fail
    delegated=$(qadenad_alias query staking delegations "$treasuryaddr" --output json 2>/dev/null \
        | jq -r '[.delegation_responses[]?.balance.amount // 0 | tonumber] | add // 0' 2>/dev/null) || delegated=""

    if [ "${delegated:-0}" != "0" ]; then
        echo "$treasury already has $delegated staked, skipping"
    else
        echo "staking $stakeamount from $treasury to $pioneer"
        $qadenatestscripts/gov_stake_from_treasury.sh "$pioneer" "$stakeamount" \
            || fail "could not stake from $treasury to $pioneer"
    fi
fi

echo "========================="
echo "pricefeed oracles"
echo "========================="
# Genesis registers no oracles at all, so this proposal is what makes MsgPostPrice possible.  It
# must run AFTER the staking above, since it needs the treasury to have voting power.
#
# MsgUpdateParams REPLACES the whole params object (proto/qadena/pricefeed/tx.proto: "All parameters
# must be supplied"), and Params.Validate() is a no-op that will not catch a dropped market.  So the
# proposal is built FROM the live params -- every market preserved, only .oracles rewritten -- never
# hand-written.
probemarket="cn:qdn:php"
if [ "$(oracle_count "$probemarket")" != "0" ]; then
    echo "oracles already registered ($(oracle_count "$probemarket") on $probemarket), skipping"
else
    oracleaddrs=()
    for i in {1..${#oraclenames[@]}}; do
        import_and_fund "${oraclenames[$i]}" "${oraclemnemonics[$i]}" "$oracleamount"
        oracleaddrs+=("$(qadenad_alias keys show "${oraclenames[$i]}" -a --keyring-backend test)")
    done

    authority=$(jq -r '.messages[0].authority' \
        "$qadenaproviderscripts/templates/add_service_provider_proposal.json") \
        || fail "could not read the gov authority address"

    liveparams=$(qadenad_alias query pricefeed params --output json) \
        || fail "could not read live pricefeed params"

    addrsjson=$(printf '%s\n' "${oracleaddrs[@]}" | jq -R . | jq -s .)
    newparams=$(echo "$liveparams" | jq --argjson addrs "$addrsjson" \
        '.params | .markets |= map(.oracles = $addrs)') \
        || fail "could not build the updated params"

    marketcount=$(echo "$newparams" | jq -r '.markets | length')
    echo "registering ${#oracleaddrs[@]} oracles across $marketcount markets"
    [ "$marketcount" = "6" ] || fail "expected 6 markets, got $marketcount -- refusing to submit a proposal that would drop markets"

    proposalfile="$qadenaproviderscripts/proposals/pricefeed-oracles.gen.json"
    mkdir -p "$qadenaproviderscripts/proposals"
    jq -n --arg authority "$authority" --argjson params "$newparams" '{
        messages: [ { "@type": "/qadena.pricefeed.MsgUpdateParams", authority: $authority, params: $params } ],
        metadata: "ipfs://CID",
        deposit: "100000qdn",
        title: "register pricefeed oracles",
        summary: "register the price oracles authorised to post prices for all markets",
        expedited: true
    }' > "$proposalfile" || fail "could not write $proposalfile"

    result=$(qadenad_alias tx gov submit-proposal "$proposalfile" --from "$treasury" -y --output json \
        --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment) \
        || fail "could not submit the pricefeed oracle proposal"
    [ "$(echo "$result" | jq -r .code)" = "0" ] || fail "oracle proposal tx failed: $(echo "$result" | jq -r .raw_log)"

    tx_hash=$(echo "$result" | jq -r .txhash)
    qadenad_alias query wait-tx "$tx_hash" --timeout 30s > /dev/null \
        || fail "oracle proposal tx $tx_hash did not land"

    proposal_id=$(qadenad_alias query tx "$tx_hash" --output json \
        | jq -r '.events[] | select(.type=="submit_proposal") | .attributes[] | select(.key=="proposal_id") | .value')
    [ -n "$proposal_id" ] || fail "could not read the oracle proposal id"
    echo "oracle proposal id: $proposal_id"

    $qadenatestscripts/gov_vote_from_treasury.sh "$proposal_id" yes \
        || fail "could not vote on the oracle proposal"
    $qadenaproviderscripts/query_service_provider_proposal.sh "$proposal_id" --wait \
        || fail "oracle proposal $proposal_id did not pass"

    # the params update is only real if the oracles are actually queryable on every market
    for m in $(echo "$newparams" | jq -r '.markets[].marketId'); do
        [ "$(oracle_count "$m")" != "0" ] || fail "no oracles registered on $m after the proposal passed"
    done
    echo "oracles registered on all $marketcount markets"
fi

# onboard <providername> <serviceProviderType> <mnemonic>
#
# setup_provider_base.sh does the create-wallet (which mints <name> AND <name>-credential), funds
# the provider from the treasury, optionally creates eph wallets, and submits the
# MsgAddServiceProvider proposal -- writing the id to provider_scripts/proposals/<name>.proposal_id.
# It also deposits 100000qdn, which is already far above the expedited_min_deposit in config.yml, so
# the proposal is in its voting period by the time we vote.
verify_provider() {
    local providername="$1"
    key_exists "$providername" || fail "$providername missing from the keyring"
    # the whole point of this script: a provider onboarded through create-wallet has a credential
    # key, so it can act as a key-recovery partner
    key_exists "$providername-credential" || fail "$providername-credential was not derived by create-wallet"
    provider_registered "$providername" || fail "$providername is not registered as a srv-prv node"
    echo "$providername verified: keys + credential key + srv-prv registration"
}

onboard() {
    local providername="$1"
    local providertype="$2"
    local providermnemonic="$3"

    echo "========================="
    echo "$providername ($providertype)"
    echo "========================="

    # Registration is the real end state, so that -- not the keyring -- is what decides whether
    # there is anything left to do.
    if provider_registered "$providername"; then
        echo "$providername already registered"
        verify_provider "$providername"
        return 0
    fi

    if key_exists "$providername"; then
        # A previous run minted the wallet but never got it registered.  create-wallet cannot simply
        # be repeated -- CreatePublicKey aborts with "friendly name already exists" -- so re-running
        # setup_provider_base.sh would fail on its first step.  Resume at the proposal instead,
        # which is the part that did not finish.
        echo "$providername has keys but no registration -- resuming at the proposal"
        $qadenaproviderscripts/submit_service_provider_proposal.sh \
            "$treasury" "$providername" add_service_provider_proposal "$providertype" \
            || fail "could not submit proposal for $providername"
    else
        $qadenaproviderscripts/setup_provider_base.sh "$providername" "$providertype" \
            --pioneer "$pioneer" \
            --treasury "$treasury" \
            --provider-mnemonic "$providermnemonic" \
            --provider-amount "$provideramount" \
            --count "$count" \
            || fail "setup_provider_base.sh failed for $providername"
    fi

    local proposal_id_file="$qadenaproviderscripts/proposals/$providername.proposal_id"
    [ -f "$proposal_id_file" ] || fail "no proposal id written for $providername"
    local proposal_id=$(cat "$proposal_id_file")
    echo "$providername proposal id: $proposal_id"

    echo "-------------------------"
    echo "voting yes on proposal $proposal_id"
    echo "-------------------------"
    # re-voting on a proposal already voted on just replaces the vote, so this is safe to repeat
    $qadenatestscripts/gov_vote_from_treasury.sh "$proposal_id" yes \
        || fail "could not vote on proposal $proposal_id"

    echo "-------------------------"
    echo "waiting for proposal $proposal_id to pass (expedited_voting_period is 30s in config.yml)"
    echo "-------------------------"
    $qadenaproviderscripts/query_service_provider_proposal.sh "$proposal_id" --wait \
        || fail "proposal $proposal_id did not pass"

    verify_provider "$providername"
}

onboard "$identityprovidername" identity "$identityprovidermnemonic"
onboard "$dsvsprovidername" dsvs "$dsvsprovidermnemonic"

echo "========================="
echo "SERVICE PROVIDERS ONBOARDED"
echo "========================="
echo "next: testscripts/setup.sh"
