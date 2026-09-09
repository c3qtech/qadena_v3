#!/bin/zsh
#
# Create and fund the two DEVNET foundation sponsor accounts, idempotently.
#
#   ./testscripts/setup_foundation_accounts.sh
#   ./testscripts/setup_foundation_accounts.sh --amount 2000000qdn
#
# WHY THIS IS ITS OWN SCRIPT.  foundation-appsvr and foundation-users are the granters for every
# sponsored deployment on the devnet -- veritas, ekycph and enf all draw on them.  They used to be
# created inline by setup_veritas.sh, which made the other two harnesses depend on a full VERITAS
# bring-up (30 wallets, two governance proposals) just to get two keys and a bank send.  They are
# two keys and a bank send; this does exactly that and nothing else.
#
# SHARED ON PURPOSE.  In production each programme gets its own pair -- see
# foundation_scripts/deployment_profile.sh -- because the keyring has no namespaces and the buckets
# are separate allocations.  On the devnet there is ONE foundation, one keyring and one chain.
# Sharing costs nothing: authz and feegrant are keyed on (granter, grantee), so three deployments
# granting from one granter to three disjoint sets of grantees do not overwrite each other.
#
# FIXED MNEMONICS so the two addresses are the SAME on every re-init.  Without this each init
# produced fresh random accounts and the two addresses had to be copied by hand into .env after
# every rebuild.
#
#   foundation-users  qadena1j75rmpk86n2ln27p9c42qa2qkw4zy4zkgrzpjm
#   foundation-appsvr qadena13vvrf5879hfgrv3krucpkpgmph549gnzv923vq
#
# TEST KEYS ONLY.  They are in a public repo, so anyone can spend from them.  A real deployment's
# foundation accounts belong to the Qadena Foundation and their addresses go into the production and
# staging SSM parameters instead -- never these.  The addresses above are safe to bake into the dev
# env files precisely because the money behind them is worthless.

set -e

SCRIPT_DIR="${0:A:h}"

# UNATTENDED, SO 'test' IS DELIBERATE -- the same reasoning as every other harness here: this cannot
# answer a passphrase prompt, so it opts out explicitly rather than relying on a permissive default.
: ${QADENA_KEYRING_BACKEND:=test}
export QADENA_KEYRING_BACKEND

source "$SCRIPT_DIR/../scripts/setup_env.sh"

foundation_appsvr="foundation-appsvr"
foundation_users="foundation-users"
# Sized well above a provider endowment because these accounts pay FEES for many wallets rather than
# endowing a few, and credential issuance is by far the most expensive operation on this chain
# (~5.9e19 aqdn against ~3.2e14 for a document signature).
amount="2000000qdn"

foundationusersmnemonic="airport south group aerobic august arm source candy tilt damp stage fork mention clerk plunge garbage nut blood fall flight indoor season broken fog"
foundationappsvrmnemonic="angle unknown bean lunch base vague awful together dismiss swallow climb common upgrade jelly machine plunge paper vote maple frog junk brisk bind weekend"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --amount)  amount="$2"; shift 2 ;;
        --appsvr)  foundation_appsvr="$2"; shift 2 ;;
        --users)   foundation_users="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--amount <qdn>] [--appsvr <name>] [--users <name>]"
            echo ""
            echo "  Creates (from fixed dev mnemonics) and funds the two devnet foundation sponsor"
            echo "  accounts every sponsored deployment grants from.  Idempotent: an account that"
            echo "  exists is kept, and the funding is topped up each run."
            echo ""
            echo "  --amount   granted to EACH account from treasury, default $amount"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "-------------------------"
echo "Foundation sponsor accounts"
echo "-------------------------"

for f in "$foundation_appsvr" "$foundation_users"; do
    if qadenad_alias keys show "$f" > /dev/null 2>&1; then
        echo "$f already exists"
    else
        echo "recovering $f from its fixed mnemonic"
        if [ "$f" = "$foundation_users" ]; then mn="$foundationusersmnemonic"; else mn="$foundationappsvrmnemonic"; fi
        # --algo eth_secp256k1 MATTERS: a standard secp256k1 key derives a DIFFERENT address from
        # the same mnemonic, so getting this wrong silently produces accounts that are not the ones
        # baked into the dev env files.
        echo "$mn" | qadenad_alias keys add "$f" --recover --algo eth_secp256k1 > /dev/null 2>&1 \
            || { echo "FAILED: could not recover $f"; exit 1; }
    fi
    echo "  $f  $(qadenad_alias keys show "$f" -a)"
    $qadenatestscripts/grant_from_treasury.sh "$f" "$amount"
done

# NOTE: no whitelist_bank_send.sh here, deliberately.  The AML exemption exists only because a
# treasury making DIRECT transfers looks exactly like the pattern the scanner is there to catch.
# These accounts pay by fee grant, and fee grants are not bank sends, so the hole is not needed and
# is not opened.
echo ""
echo "Both foundation sponsor accounts are funded."
