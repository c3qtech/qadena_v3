#!/bin/zsh
#
# PARTNER SIDE, step 1 of 3.  Mint the keys, derive every address this partner will ever hold,
# and emit the pre-grant block for the foundation.
#
#   ekycph_partner_scripts/step_1.sh <partner-name> --sponsor <address> [options]
#
# WHAT RUNS WHERE.  This directory is the PARTNER's half.  It holds no foundation key and no
# eKYC PH key, and nothing in it can spend the foundation's money -- it can only present grants
# the foundation signed in advance.  The other two halves are:
#
#   foundation_scripts/ekycph_partner_after_step_1.sh   FOUNDATION  pre-grants (after this script)
#   foundation_scripts/ekycph_partner_after_step_2.sh   FOUNDATION  submits the proposal
#   ekycph_partner_scripts/ekycph_issue_credentials.sh  eKYC PH     issues the contact credentials
#
# and testscripts/setup_ekycph_partner.sh plays all three on one devnet box.
#
# WHY THE ADDRESSES ARE DERIVED HERE, BEFORE ANYTHING EXISTS.  A fee allowance is signed by its
# GRANTER and the granter's balance pays; grants do not chain.  So the partner's very first
# transaction -- create-wallet -- already needs an allowance that only the foundation can sign.
# `debug derive-wallet-address` wraps the same GetEphAccountAddress create-wallet uses, so the
# addresses computed here offline are what the chain will see, by construction.  The foundation
# grants against them from its own machine and no foundation key ever reaches this one.
#
# Options:
#   --sponsor ADDR       the foundation's ekycph appsvr sponsor ADDRESS.  Required: it is both
#                        the fee granter and create-wallet's sponsor argument, and the two must
#                        be the same account or step_2 will not find the allowance.
#   --friendly-name S    display name for the Add Partner form   (default: the partner name)
#   --logo URL           logo for the form (the field is `binding:"required"` server side)
#   --email ADDR         email-contact-info credential           (default: <name>@example.com)
#   --phone NUM          phone-contact-info credential           (default: +639060000000)
#   --rep-first-name S   ) a personal-info credential for the partner's authorized representative.
#   --rep-middle-name S  ) OPT-IN: issued only when both --rep-first-name and --rep-last-name are
#   --rep-last-name S    ) given.  The house precedent for an institution is contact credentials
#   --rep-birthdate S    ) only -- secdsvs, the SEC, holds email and phone and no personal-info --
#   --rep-citizenship S  ) because personal-info describes a PERSON and inventing one puts
#   --rep-residency S    ) fabricated identity data on an immutable chain.
#   --rep-gender S       )
#   --pioneer N          home pioneer     (default: $QADENA_PIONEER or pioneer1)
#   --count N            ephemeral wallets                        (default: 2; 0 for none)
#   --mnemonic "..."     recover an existing partner              (default: a fresh one)
#   --find-a N / --find-bf N   the find-credential Pedersen pair  (default: derived from the name)
#   --home DIR           state directory
#                        (default: $QADENA_LAUNCH_ROOT/ekycph_partners/<name>)
#   --node RPC           chain RPC, for the chain-id stamped into the pre-grant block
#
# OUTPUT CONTAINS A MNEMONIC.  Everything under --home is 0600 and none of it belongs in git.

set -e

SCRIPT_DIR="${0:A:h}"
_HERE="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"
# EXPORT THE RESOLVED BACKEND, for the same reason setup_ekycph.sh does: setup_env.sh resolves it
# from client.toml but never exports it, so a child defaulting it to `test` would look in a
# different keyring than the one this script just read.
export QADENA_KEYRING_BACKEND

# DEV STATE, KEPT APART FROM FLEET STATE.  ~/qadena-launch holds c3q-mainnet custody directories
# and the fleet launch dirs; a partner's throwaway key must not share a parent with them.
export QADENA_LAUNCH_ROOT="${QADENA_LAUNCH_ROOT:-$HOME/qadena-dev-launch}"

pioneer="${QADENA_PIONEER:-pioneer1}"
count="2"
logo="https://placehold.co/128x128?text=LOGO"
unset partner friendly_name email phone mnemonic home sponsor find_a find_bf
unset rep_first rep_middle rep_last rep_birthdate rep_citizenship rep_residency rep_gender

# ONE PASS, NOT THE TWO-PASS SCAN THE OTHER SETUP SCRIPTS USE.  setup_provider.sh collects every
# argument that does not start with `--` as a positional first, which cannot tell a bare name from
# an option's VALUE: `--email a@b.com acme` makes a@b.com the name.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sponsor)           sponsor="$2"; shift 2 ;;
        --friendly-name)     friendly_name="$2"; shift 2 ;;
        --logo)              logo="$2"; shift 2 ;;
        --email)             email="$2"; shift 2 ;;
        --phone)             phone="$2"; shift 2 ;;
        --rep-first-name)    rep_first="$2"; shift 2 ;;
        --rep-middle-name)   rep_middle="$2"; shift 2 ;;
        --rep-last-name)     rep_last="$2"; shift 2 ;;
        --rep-birthdate)     rep_birthdate="$2"; shift 2 ;;
        --rep-citizenship)   rep_citizenship="$2"; shift 2 ;;
        --rep-residency)     rep_residency="$2"; shift 2 ;;
        --rep-gender)        rep_gender="$2"; shift 2 ;;
        --pioneer)           pioneer="$2"; shift 2 ;;
        --count)             count="$2"; shift 2 ;;
        --mnemonic)          mnemonic="$2"; shift 2 ;;
        --find-a)            find_a="$2"; shift 2 ;;
        --find-bf)           find_bf="$2"; shift 2 ;;
        --home)              home="$2"; shift 2 ;;
        --node)              export QADENA_NODE="$2"; shift 2 ;;
        --help)
            awk 'NR<3{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
            exit 0
            ;;
        --*) echo "Unknown option: $1" >&2; exit 1 ;;
        *)   [ -z "${partner:-}" ] && partner="$1"; shift 1 ;;
    esac
done

if [ -z "${partner:-}" ]; then
    echo "Usage: $0 <partner-name> --sponsor <address> [options]   (--help for the full list)" >&2
    exit 1
fi

# THE NAME IS A chain nodeID, A KEYRING NAME AND A FORM FIELD AT THE SAME TIME.  A space or an
# uppercase letter is accepted by the keyring and by this script, survives the proposal, and then
# fails to match when the app server looks the partner up by name -- at which point the
# registration is already on chain and the nodeID cannot be reused.
# AN EXPLICIT CHARACTER LIST, NOT A GLOB RANGE.  `case $partner in [a-z0-9-]*)` reads as though it
# says this and does not: a range follows the LOCALE's collation order, and with no locale set --
# the normal state in these scripts -- zsh matches `acme_corp` against [a-z0-9][a-z0-9-]*.
_illegal=$(printf '%s' "$partner" \
             | LC_ALL=C tr -d 'abcdefghijklmnopqrstuvwxyz0123456789-')
if [ -n "$_illegal" ] || [ "${partner#-}" != "$partner" ] || [ "${partner%-}" != "$partner" ]; then
    echo "partner name must be lowercase letters, digits and inner dashes, got '$partner'" >&2
    exit 1
fi
unset _illegal

if [ -z "${sponsor:-}" ]; then
    echo "--sponsor is required: the foundation's ekycph appsvr sponsor ADDRESS." >&2
    echo "  It is the fee granter for every wallet below AND create-wallet's sponsor" >&2
    echo "  argument in step_2; a different account there would miss the allowance." >&2
    echo "  The foundation prints it from foundation_scripts/ekycph_before_step_1.sh." >&2
    exit 1
fi
case "$sponsor" in
    qadena1*) ;;
    *) echo "--sponsor '$sponsor' is not a qadena address" >&2; exit 1 ;;
esac

: ${friendly_name:="$partner"}
: ${email:="$partner@example.com"}
: ${phone:="+639060000000"}
: ${home:="$QADENA_LAUNCH_ROOT/ekycph_partners/$partner"}

# THE find-credential PEDERSEN PAIR, DERIVED FROM THE NAME RATHER THAN HARDCODED.
# testscripts/setup_mnemonic.sh hands every demo user a distinct `a` by hand (al 1234, ann 2234,
# ...) against a shared bf.  A script that can be run for any number of partners cannot pick from
# a fixed list, and two partners sharing a pair collide on the chain's credential-uniqueness
# check.  A hash of the name is distinct per partner and identical across re-runs, which is what
# claim-credential needs -- it is given the same pair the issuer used.  All credential types for
# one wallet share one pair, exactly as they do for a user.
if [ -z "${find_a:-}" ]; then
    # shasum on macOS, sha256sum on most Linuxes, cksum as the POSIX floor.  The value only has to
    # be stable and collision-free across the handful of partners a devnet carries -- but it must
    # be the SAME one on every run for this name, which is why the order is fixed rather than
    # "whichever is first on PATH".
    if command -v shasum >/dev/null 2>&1; then
        find_a=$((16#$(printf '%s' "$partner" | shasum | cut -c1-8)))
    elif command -v sha256sum >/dev/null 2>&1; then
        find_a=$((16#$(printf '%s' "$partner" | sha256sum | cut -c1-8)))
    else
        find_a=$(printf '%s' "$partner" | cksum | cut -d" " -f1)
    fi
fi
: ${find_bf:="5678"}

mkdir -p "$home"
chmod 700 "$home"

echo "============================================================"
echo "PARTNER step_1          : $partner"
echo "friendly name           : $friendly_name"
echo "foundation sponsor      : $sponsor"
echo "pioneer                 : $pioneer"
echo "ephemeral wallets       : $count"
echo "find-credential pair    : $find_a / $find_bf"
echo "state directory         : $home"
echo "============================================================"

# ------------------------------------------------------------------------------------------
# The mnemonic.  THE ONLY WAY BACK TO THIS WALLET: the armored key step_3 exports is encrypted
# with a passphrase and the keyring entry lives on whichever machine ran this; neither survives a
# lost laptop.  Written before it is used, so a failure later still leaves the key recoverable.
# ------------------------------------------------------------------------------------------
if [ -z "${mnemonic:-}" ]; then
    if [ -r "$home/$partner.mnemonic" ]; then
        echo "--- re-using the mnemonic already in $home/$partner.mnemonic"
        mnemonic=$(head -1 "$home/$partner.mnemonic")
    else
        echo "--- generating a mnemonic for $partner"
        mnemonic=$(qadenad_alias keys mnemonic)
    fi
fi
umask 077
print -r -- "$mnemonic" > "$home/$partner.mnemonic"
chmod 600 "$home/$partner.mnemonic"
echo "    mnemonic: $home/$partner.mnemonic  (<redacted, $(print -r -- "$mnemonic" | wc -w | tr -d ' ') words>)"

# ------------------------------------------------------------------------------------------
# variables.json -- this run's configuration.  step_2 and step_3 read it rather than taking the
# same fifteen flags again, for the same reason veritas_scripts/step_1.sh writes one: a value
# re-typed at step 3 that disagrees with step 1 produces a wallet nobody can sign for.
# ------------------------------------------------------------------------------------------
chain_id=$(qadenad_alias status 2>/dev/null | sed -n '/^{/,$p' | jq -r '.node_info.network // ""')
jq -n --arg partner "$partner" --arg friendly "$friendly_name" --arg logo "$logo" \
      --arg email "$email" --arg phone "$phone" --arg pioneer "$pioneer" \
      --arg sponsor "$sponsor" --arg count "$count" --arg chain "$chain_id" \
      --arg finda "$find_a" --arg findbf "$find_bf" \
      --arg rf "${rep_first:-}" --arg rm "${rep_middle:-}" --arg rl "${rep_last:-}" \
      --arg rb "${rep_birthdate:-}" --arg rc "${rep_citizenship:-}" \
      --arg rr "${rep_residency:-}" --arg rg "${rep_gender:-}" \
   '{partner:$partner, friendly_name:$friendly, logo:$logo, email:$email, phone:$phone,
     pioneer:$pioneer, sponsor:$sponsor, count:($count|tonumber), chain_id:$chain,
     find_a:$finda, find_bf:$findbf,
     rep:{first:$rf, middle:$rm, last:$rl, birthdate:$rb, citizenship:$rc,
          residency:$rr, gender:$rg}}' > "$home/variables.json"
chmod 600 "$home/variables.json"

# ------------------------------------------------------------------------------------------
# EVERY WALLET THIS PARTNER WILL CREATE, DERIVED NOW, OFFLINE.  One family -- the partner itself
# -- plus $count ephemerals, so count+1 addresses.  `families: 1` is what tells the foundation's
# pre-grant script how many to expect; the VERITAS block carries 4 (two providers, the
# create-wallet sponsor, the DSVS user) and the arithmetic check would otherwise reject this one.
# ------------------------------------------------------------------------------------------
derive_addr() {   # derive_addr <mnemonic> <index>
    print -r -- "$1" | "${qadenabin:-$HOME/qadena/bin}/qadenad" \
        debug derive-wallet-address "$2" 2>/dev/null | tail -1
}

pregrant_file="$home/pregrant_addresses.json"
{
    printf '{\n'
    printf '  "partner": "%s",\n' "$partner"
    printf '  "chain_id": "%s",\n' "$chain_id"
    printf '  "sponsor": "%s",\n' "$sponsor"
    printf '  "families": 1,\n'
    printf '  "count": %s,\n' "$count"
    printf '  "wallets": [\n'
    _first=1
    for _i in $(seq 0 "$count"); do
        _a=$(derive_addr "$mnemonic" "$_i")
        [ -n "$_a" ] || { echo "  WARNING: could not derive index $_i" >&2; continue; }
        if [ "$_i" -eq 0 ]; then _n="$partner"; else _n="$partner-eph$_i"; fi
        [ "$_first" -eq 1 ] || printf ',\n'
        printf '    {"name": "%s", "address": "%s"}' "$_n" "$_a"
        _first=0
    done
    printf '\n  ]\n}\n'
} > "$pregrant_file"
chmod 600 "$pregrant_file"

# TRUST THE FILE, NOT THE LOOP.  The loop above warns and continues when a derivation fails, so a
# short file is a real outcome -- and a partner whose eph wallet was never granted fails in
# step_2, far from here.  The foundation's script checks this too; checking on both sides means
# neither has to trust the other's copy.
_n=$(jq -r '.wallets | length' "$pregrant_file" 2>/dev/null || echo 0)
if [ "$_n" -ne $(( count + 1 )) ]; then
    echo "FAILED: count=$count implies $(( count + 1 )) wallets; derived $_n." >&2
    echo "        Nothing has been created on chain -- fix and re-run." >&2
    exit 1
fi

echo ""
echo "==================================================================="
# THE HEREDOC IS PASTEABLE; THE COMMAND IS NOT.  /tmp is portable and this side chooses it, so
# the file half can be pasted verbatim.  The FLAGS are the foundation's own filesystem, which this
# machine has no way to know.
echo "SEND THIS BLOCK TO THE FOUNDATION.  The heredoc pastes as-is;"
echo "the last line is theirs to fill in:"
echo "==================================================================="
echo ""
echo "cat > /tmp/$partner-pregrant.json <<'PREGRANTEOF'"
cat "$pregrant_file"
echo "PREGRANTEOF"
echo "foundation_scripts/ekycph_partner_after_step_1.sh \\"
echo "    --pregrant /tmp/$partner-pregrant.json${QADENA_NODE:+ --node $QADENA_NODE} \\"
echo "    --coord-home <the foundation's coordinator dir> --keyring-passfile <its passphrase file>"
echo ""
echo "==================================================================="
jq -r '"  partner \(.partner)   wallets \(.wallets|length)   chain \(.chain_id)"' "$pregrant_file" 2>/dev/null
echo ""
echo "Then run step_2:  ekycph_partner_scripts/step_2.sh $partner"
