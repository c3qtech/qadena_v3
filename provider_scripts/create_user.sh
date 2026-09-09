#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

username=$1
usermnemonic=$2
pioneer=$3
serviceprovider=$4
firstname=$5
middlename=$6
lastname=$7
birthdate=$8
citizenship=$9
residency=${10}
gender=${11}
email=${12}
phone=${13}
user_a=${14}
user_bf=${15}
identityprovider=${16}
acceptcredentialtypes=${17}
acceptpassword=${18}
requiresendertypes=${19}
eph_count=${20}
createwalletsponsor=${21}

echo "service provider: $serviceprovider"
echo "required sender types: $requiresendertypes"
echo "accept credential types: $acceptcredentialtypes"
echo "accept password: $acceptpassword"
echo "create wallet sponsor: $createwalletsponsor"
echo "eph count: $eph_count"

# RESUMABLE, COARSELY.  A user is onboarded as one atomic sequence -- wallet, ephemerals, grants,
# claims -- and the local key for the MAIN wallet is written by the same run that broadcast it, so
# its presence means this user's sequence already completed (or nearly; the widen that follows in
# step_3 re-runs regardless and repairs the grants).  Without this, a step_3 resumed after a
# mid-run failure died here on "friendly name already exists ... aborted", and the only way
# forward was wiping keyrings for wallets the CHAIN still has -- which cannot be re-created.
# A user that died between main and ephemerals is mis-skipped by this; delete its keys to redo.
# KEYED ON THE CHAIN, NOT THE KEYRING.  The first version of this checked `keys show` and was
# wrong in the same way setup_provider_base's skip was: create-wallet writes the local key BEFORE
# broadcasting, so a failed broadcast leaves a key with no wallet, and a keyring-keyed skip then
# refuses to retry it forever.  That is how the fleet ended up with 33 keys and zero wallets
# (2026-09-07) while every downstream step reported success.
# THE MAIN WALLET'S ADDRESS COMES FROM THE MNEMONIC, NOT THE KEYRING.
#
# `keys show` was the source here, and it is exactly wrong for this decision: create-wallet's
# cleanup DELETES the local key when a broadcast fails, so after any failed attempt the address is
# unknowable from the keyring, the on-chain check is skipped entirely, and the script re-creates a
# wallet that already exists -- "Public key already exists", forever (measured 2026-09-07, three
# runs in a row).  The address is a pure function of the mnemonic, so derive it; that answer is
# available whether or not a key survives locally.
_u_addr=$(print -r -- "$usermnemonic" | "${qadenabin:-$HOME/qadena/bin}/qadenad" \
            debug derive-wallet-address 0 2>/dev/null | tail -1)
_u_keyring_addr=$(qadenad_alias keys show "$username" --address 2>/dev/null || true)
if [ -n "$_u_addr" ]; then
    # Single-address query, parsed from the first JSON line -- see wallet_on_chain() in
    # setup_provider_base.sh for why neither `.wallet.walletID` nor a list-wallet scan works.
    #
    # AND A FAILED QUERY IS NOT A "NO".  An empty result here DELETES the user's keys below, so an
    # unreachable node must stop the run rather than look like an absent wallet.
    _u_raw=$(qadenad_alias query qadena show-wallet "$_u_addr" --output json 2>&1 || true)
    case "$_u_raw" in
        *"no route to host"*|*"connection refused"*|*"context deadline exceeded"*|*"post failed"*)
            echo "cannot reach the chain to check whether $username exists -- refusing to continue,"
            echo "  because the next step would delete this key on the assumption it is absent."
            exit 1 ;;
    esac
    _u_onchain=$(print -r -- "$_u_raw" | sed -n '/^{/,$p' | jq -r '.walletID // empty' 2>/dev/null || true)

# credential_claimed <type> -- non-empty when this user has already claimed that credential type.
#
# CLAIMING IS NOT IDEMPOTENT.  x/qadena/keeper/msg_server_claim_credential.go:25-30 WRITES a new
# credential keyed by (CredentialID, CredentialType) and rejects a second attempt with
# ErrCredentialExists -- the same error text `create-credential` produces, so a repeat claim reads
# in the logs as an issuance problem rather than a re-claim.  (The intended ErrCredentialClaimed
# guard at :52 is commented out; the existence check is what actually rejects it.)
#
# The CredentialID is the CREDENTIAL WALLET's address -- account 1 of the same mnemonic -- so it is
# derivable offline, exactly like the wallet addresses.  Exit status is NOT usable here: the
# command returns 0 either way and prints "err rpc error: ... NotFound" for a missing one, so
# match on the output.
credential_claimed() {
    local _type="$1" _cw _out
    _cw=$(print -r -- "$usermnemonic" | "${qadenabin:-$HOME/qadena/bin}/qadenad" \
            debug derive-wallet-address 0 --credential 2>/dev/null | tail -1)
    [ -n "$_cw" ] || return 0
    _out=$(qadenad_alias query qadena show-credential "$_cw" "$_type" 2>&1 || true)
    case "$_out" in
        *"no route to host"*|*"connection refused"*|*"post failed"*)
            echo "cannot reach the chain to check $username's $_type credential -- stopping" >&2
            exit 1 ;;
        *NotFound*|*"not found"*) return 0 ;;
        *CREDENTIAL:*) print -r -- "claimed" ;;
    esac
}

# eph_ready <index> -- "skip" if that ephemeral already exists on chain, "" if it must be created.
#
# THIRD PLACE THIS PATTERN WAS MISSING.  The main wallet above got a chain-keyed check; the
# ephemerals had none at all, so a local key left by any earlier attempt made create-wallet abort
# with "friendly name already exists ... Couldn't create public key ... aborted" -- before any
# broadcast, and with no way to recover by re-running (2026-09-07).
#
# The address is derived from the mnemonic, NOT read from the keyring: the whole point is to know
# the answer when the local key is absent or stale.  A query that cannot be answered stops the run
# rather than being read as "does not exist", because the branch below DELETES keys.
eph_ready() {
    local _i="$1" _addr _raw _on
    _addr=$(print -r -- "$usermnemonic" | "${qadenabin:-$HOME/qadena/bin}/qadenad" \
              debug derive-wallet-address "$_i" 2>/dev/null | tail -1)
    [ -n "$_addr" ] || return 0
    _raw=$(qadenad_alias query qadena show-wallet "$_addr" --output json 2>&1 || true)
    case "$_raw" in
        *"no route to host"*|*"connection refused"*|*"context deadline exceeded"*|*"post failed"*)
            echo "cannot reach the chain to check $username-eph$_i -- refusing to continue" >&2
            exit 1 ;;
    esac
    _on=$(print -r -- "$_raw" | sed -n '/^{/,$p' | jq -r '.walletID // empty' 2>/dev/null || true)
    [ -n "$_on" ] && print -r -- "skip"
}

    # SKIP ONLY IF THE WHOLE FAMILY IS THERE.
    #
    # This used to exit as soon as the MAIN wallet existed, which is the state a run that died on
    # its first ephemeral leaves behind -- so every retry skipped the ephemerals, the claims and
    # the grants, and reported success.  On the fleet that left sec-create-wallet-sponsor with a
    # main wallet and none of its three ephemerals, while step_3 finished green (2026-09-07).
    #
    # Every create-wallet below now has its own on-chain guard, so re-entering a partial user is
    # safe: what exists is skipped individually.  The coarse exit is kept ONLY for the fully
    # complete case, where re-running would repeat claims that are not idempotent.
    _fam_missing=0
    if [ -n "$_u_onchain" ] && [ -n "${eph_count:-}" ]; then
        for _fi in $(seq 1 $eph_count); do
            [ -n "$(eph_ready "$_fi")" ] || { _fam_missing=1; break; }
        done
    fi
    # THE RESUME EXIT IS KEYED ON WALLETS AND GUARDS WORK THAT IS NOT WALLETS.
    #
    # Claims, contact binds and the DSVS signatory registration all happen AFTER the wallets, and
    # exiting here skipped every one of them for a user whose wallets already existed.  On the
    # fleet that left secdsvs with 16 wallets, 18 credentials and NO authorized signatory, so SEC
    # could not counter-sign anything -- and the run reported success (2026-09-07, found by the
    # app-server team hitting "Unauthorized signer", qadena 1137).
    #
    # So: only skip when the SIGNATORY is also in place, which is the last thing this script does
    # and therefore a reasonable proxy for "this user is fully set up".  When it is missing, fall
    # through -- every wallet step below is individually guarded and will skip itself.
    _sig_ok=0
    if [ -n "$_u_onchain" ] && [ "$_fam_missing" -eq 0 ]; then
        if [ -z "$serviceprovider" ]; then
            _sig_ok=1          # no signatory is registered for a user with no service provider
        elif qadenad_alias query dsvs show-authorized-signatory "$_u_addr" > /dev/null 2>&1; then
            _sig_ok=1
        fi
    fi
    if [ -n "$_u_onchain" ] && [ "$_fam_missing" -eq 0 ] && [ "$_sig_ok" -eq 1 ]; then
        echo "$username is fully set up ON CHAIN -- skipping create_user (resume)"
        # FULLY SET UP ON CHAIN STILL NEEDS THE LOCAL KEYS.  This exited 0 without them, and the
        # caller's very next `keys show $username` failed with
        #     is not a valid name or address: decoding bech32 failed
        # -- qadenad parsing the NAME as an address, naming neither the keyring nor the key.
        #
        # The self-heal below the skip already handles this for a half-created wallet; the
        # fully-created one needs it too, and hits it whenever the chain outlives the keyring: a
        # wiped ~/sec-<name>, or a deployment moved from keyring-test to keyring-file.  Both keys
        # are pure functions of the mnemonic, so recovering cannot produce a different address.
        # THE WHOLE FAMILY, NOT JUST THE TWO MAIN KEYS.  The pool's ephemerals sign as much as the
        # main wallet does, and the caller reads every one of their addresses back, so recovering
        # two of eight just moves the same bech32 error one line down.  Ephemeral i is account 0 /
        # account 1 at address INDEX i -- the same derivation --eph-account-index creates.
        _heal=("$username:0:0" "$username-credential:1:0")
        if [ -n "${eph_count:-}" ]; then
            for _hi in $(seq 1 $eph_count); do
                _heal+=("$username-eph$_hi:0:$_hi" "$username-eph$_hi-credential:1:$_hi")
            done
        fi
        if ! qadenad_alias keys show "$username" --address > /dev/null 2>&1; then
            echo "  its local keys are missing -- recovering the family from the mnemonic"
            for _spec in "${_heal[@]}"; do
                _kn="${_spec%%:*}"; _rest="${_spec#*:}"; _ka="${_rest%%:*}"; _kx="${_rest##*:}"
                # _raw, NOT qadenad_alias.  When QADENA_KEYRING_PASS is set the wrapper REPLACES
                # stdin with its own passphrase feed, so the mnemonic this pipe supplies never
                # arrives and --recover fails -- silently, because of the `|| true`.  Latent until
                # the node keyring moved to `file` and something finally exported that variable.
                { print -r -- "$usermnemonic"
                  [ -z "${QADENA_KEYRING_PASS:-}" ] || repeat 8 print -r -- "$QADENA_KEYRING_PASS"
                } | qadenad_alias_raw keys add "$_kn" --recover --account "$_ka" --index "$_kx" > /dev/null 2>&1 || true
                qadenad_alias keys show "$_kn" --address > /dev/null 2>&1 \
                    && echo "    recovered $_kn" \
                    || { echo "    FAILED to recover $_kn -- cannot continue"; exit 1; }
            done
        fi
        exit 0
    fi
    if [ -n "$_u_onchain" ] && [ "$_fam_missing" -eq 0 ]; then
        echo "$username wallets exist but its authorized signatory does not -- resuming"
    fi
    # THE DELETE BELONGS TO THE not-on-chain CASE ONLY.  Left unconditional (as it briefly was),
    # it deleted the key of a main wallet that EXISTS, and the re-create then failed with "Public
    # key already exists" -- turning a resumable partial user into a stuck one.
    if [ -n "$_u_onchain" ]; then
        echo "$username exists but its ephemerals do not -- resuming this user"
        SKIP_MAIN_WALLET=1
        # SELF-HEAL THE KEYS THE FAILED RUN TOOK WITH IT.
        #
        # create-wallet's cleanup deletes the local key when its broadcast fails, so the common
        # state here is: wallet ON CHAIN, key GONE.  Skipping create-wallet is then correct and
        # not sufficient -- everything downstream signs as $username (claims, grants, the pool's
        # own operations) and has nothing to sign with.  Both keys are pure functions of the
        # mnemonic: account 0 is the transaction key, account 1 the credential key (see
        # hd.CreateHDPath(coinType, accountType, ephIndex) in x/qadena/common/common.go).
        if [ -z "$_u_keyring_addr" ]; then
            echo "  its local keys are missing -- recovering both from the mnemonic"
            for _spec in "$username:0" "$username-credential:1"; do
                _kn="${_spec%%:*}"; _ka="${_spec##*:}"
                # _raw, NOT qadenad_alias.  When QADENA_KEYRING_PASS is set the wrapper REPLACES
                # stdin with its own passphrase feed, so the mnemonic this pipe supplies never
                # arrives and --recover fails -- silently, because of the `|| true`.  Latent until
                # the node keyring moved to `file` and something finally exported that variable.
                { print -r -- "$usermnemonic"
                  [ -z "${QADENA_KEYRING_PASS:-}" ] || repeat 8 print -r -- "$QADENA_KEYRING_PASS"
                } | qadenad_alias_raw keys add "$_kn" --recover --account "$_ka" > /dev/null 2>&1 || true
                qadenad_alias keys show "$_kn" --address > /dev/null 2>&1 \
                    && echo "    recovered $_kn" \
                    || { echo "    FAILED to recover $_kn -- cannot continue"; exit 1; }
            done
        fi
    elif [ -n "$_u_keyring_addr" ]; then
        echo "$username has a local key but NO wallet on chain -- a previous run failed after"
        echo "  writing the key.  Removing it so create-wallet can be retried."
        qadenad_alias keys delete "$username" --yes > /dev/null 2>&1 || true
        qadenad_alias keys delete "$username-credential" --yes > /dev/null 2>&1 || true
    fi
fi


# TOLL-FREE SUPPORT.
#
# In feegrant mode a new wallet holds NOTHING -- the chain's create-wallet incentives are 0 -- so
# every transaction it signs needs a sponsor. Two things are required, and neither alone is enough:
#
#   1. A GRANT WIDE ENOUGH. create-wallet issues its own allowance from the sponsor
#      (x/qadena/client/cli/tx_create_wallet.go grantFee) but it permits only MsgAddPublicKey and
#      MsgCreateWallet. Claiming a credential, registering a signatory and binding a contact are not
#      on it, so they fall through to the wallet's own balance -- which is zero.
#
#   2. THE COMMANDS MUST PRESENT IT. --fee-granter, on every transaction the USER signs.
#
#   And the grant must REVOKE FIRST: a grantee holds at most one allowance per granter, so the wider
#   grant cannot be layered over the one create-wallet already made from the same sponsor.
#
# This runs INSIDE create_user.sh rather than in step_3's fund_wallet because step_3 funds the
# wallet only AFTER create_user.sh returns -- by which time the claims have already failed.
USER_FEE_GRANTER_FLAG=""
USER_MSGS="/qadena.qadena.MsgAddPublicKey,/qadena.qadena.MsgCreateWallet,/qadena.qadena.MsgClaimCredential,/qadena.qadena.MsgUpdateCredential,/qadena.qadena.MsgClaimUpdatedCredential,/qadena.qadena.MsgProtectPrivateKey,/qadena.dsvs.MsgSignDocument,/qadena.dsvs.MsgRegisterAuthorizedSignatory,/qadena.nameservice.MsgBindCredential,/qadena.nameservice.MsgUnbindCredential"

grant_user_fees() {   # grant_user_fees <key-name>
    [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ] || return 0
    local addr granter
    addr=$(qadenad_alias keys show "$1" --address 2>/dev/null) || return 0
    [ -n "$addr" ] || return 0
    case "$createwalletsponsor" in
        qadena1*) granter="$createwalletsponsor" ;;
        *)        granter=$(qadenad_alias keys show "$createwalletsponsor" --address 2>/dev/null || true)
                  [ -n "$granter" ] || granter="$createwalletsponsor" ;;
    esac
    # Signed by SEC's admin key as a MsgExec when VERITAS_SEC_ADMIN is set, so a real deployment
    # never needs a foundation key here; signed directly by the granter otherwise (harness only).
    if grant_as_foundation "$granter" "$addr" "$USER_MSGS"; then
        echo "  granted $1 the full user message set from $createwalletsponsor" >&2
    else
        # STOP, DO NOT WARN.  "Falls back to its own balance" is not a degraded mode on this
        # chain: the wallet incentives are zero, so the balance is zero, and every transaction this
        # user makes from here fails.  Continuing produces a user that looks created and cannot
        # act, and the first symptom appears in a later step with no reference to this grant.
        echo "  FAILED to grant $1 -- on a zero-incentive chain that wallet cannot transact." >&2
        echo "  Fix the grant and re-run; this step is resumable." >&2
        exit 1
    fi
}

# The IDENTITY PROVIDER also holds a grant rather than tokens in this mode, and create-credential is
# signed by IT, not by the user. Its grant already permits MsgCreateCredential -- issued by step_2's
# fund_wallet -- but a grant is only used when the transaction NAMES it, so the flag is what makes
# the difference between working and "spendable balance 0aqdn".
PROVIDER_FEE_GRANTER_FLAG=""
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    # THE SPONSOR MAY BE AN ADDRESS, NOT A KEY NAME.  On a split deployment SEC's keyring holds no
    # foundation key, so `keys show` fails -- and under set -e a failing substitution inside an
    # assignment kills the whole script with NO output past the argument echos (measured
    # 2026-09-06).  Same resolution rule as everywhere else: bech32 passes through untouched.
    case "$createwalletsponsor" in
        qadena1*) _sponsor_addr="$createwalletsponsor" ;;
        *)        _sponsor_addr=$(qadenad_alias keys show $createwalletsponsor --address 2>/dev/null || true) ;;
    esac
    [ -n "$_sponsor_addr" ] || { echo "cannot resolve sponsor '$createwalletsponsor' to an address"; exit 1; }
    USER_FEE_GRANTER_FLAG="--fee-granter $_sponsor_addr"
    PROVIDER_FEE_GRANTER_FLAG="--fee-granter ${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}"
    # resolve the name to an address; --fee-granter takes an address
    # `|| true`: on a split box this is an ADDRESS, keys show fails, and a failing substitution
    # in an assignment is fatal under set -e -- the same silent death as the sponsor line above.
    _fg_addr=$(qadenad_alias keys show "${VERITAS_FOUNDATION_APPSVR:-foundation-veritas-appsvr}" --address 2>/dev/null || true)
    case "${VERITAS_FOUNDATION_APPSVR:-}" in qadena1*) _fg_addr="$VERITAS_FOUNDATION_APPSVR" ;; esac
    [ -n "$_fg_addr" ] && PROVIDER_FEE_GRANTER_FLAG="--fee-granter $_fg_addr"
fi

banner "$username Create wallet"
# GUARDED LIKE EVERY OTHER SITE.  This one was missed because the audit counted the string
# "already exists ON CHAIN", which the resume block and the ephemeral guards both contain -- so it
# reported 6/6 while the main wallet's create was bare.  Count call sites, not messages.
if [ "${SKIP_MAIN_WALLET:-0}" = "1" ]; then
    echo "$username main wallet already exists ON CHAIN -- skipping create-wallet"
else
    run_cmd "qadenad_alias tx qadena create-wallet $username $pioneer $createwalletsponsor --account-mnemonic=\"$usermnemonic\"  --service-provider \"$serviceprovider\" --yes"
fi


banner "$username Create wallet eph"
if [ -n "$eph_count" ] ; then
    for i in $(seq 1 $eph_count); do
        if [ -n "$(eph_ready "$i")" ]; then
            echo "$username-eph$i already exists ON CHAIN -- skipping create-wallet"
        else
            if qadenad_alias keys show "$username-eph$i" --address > /dev/null 2>&1; then
                echo "$username-eph$i has a local key but NO wallet on chain -- removing and retrying"
                qadenad_alias keys delete "$username-eph$i" --yes > /dev/null 2>&1 || true
                qadenad_alias keys delete "$username-eph$i-credential" --yes > /dev/null 2>&1 || true
            fi
            run_cmd "qadenad_alias tx qadena create-wallet $username-eph$i $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"$i\" --yes"
        fi
    done
else
    # Same guard as the indexed loop above -- this branch runs when no --eph-count was given.
    if [ -n "$(eph_ready 1)" ]; then
        echo "$username-eph already exists ON CHAIN -- skipping create-wallet"
    else
        if qadenad_alias keys show "$username-eph" --address > /dev/null 2>&1; then
            echo "$username-eph has a local key but NO wallet on chain -- removing and retrying"
            qadenad_alias keys delete "$username-eph" --yes > /dev/null 2>&1 || true
            qadenad_alias keys delete "$username-eph-credential" --yes > /dev/null 2>&1 || true
        fi
        run_cmd "qadenad_alias tx qadena create-wallet $username-eph $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"1\" --yes"
    fi
fi

# The wallets exist now, so they can be granted. Main wallet first, then each ephemeral one: a
# grant names ONE address, so every wallet that signs needs its own.
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    grant_user_fees "$username"
    if [ -n "$eph_count" ]; then
        for i in $(seq 1 $eph_count); do grant_user_fees "$username-eph$i"; done
    else
        grant_user_fees "$username-eph"
    fi
fi

banner "$username Create credential personal-info"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf personal-info \"$firstname\" \"$middlename\" \"$lastname\" \"$birthdate\" \"$citizenship\" \"$residency\" \"$gender\" --from \"$identityprovider\" $PROVIDER_FEE_GRANTER_FLAG --yes"

banner "$username Create credential phone"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf phone-contact-info $phone --from \"$identityprovider\" $PROVIDER_FEE_GRANTER_FLAG --yes"

banner "$username Create credential email"
run_cmd "qadenad_alias tx qadena create-credential $user_a $user_bf email-contact-info $email --from \"$identityprovider\" $PROVIDER_FEE_GRANTER_FLAG --yes"

banner "$username Claim credential personal-info"
if [ -n "$(credential_claimed personal-info)" ]; then
    echo "$username already holds a personal-info credential -- skipping claim"
else
    run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf personal-info --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"
fi

banner "$username Claim credential phone"
if [ -n "$(credential_claimed phone-contact-info)" ]; then
    echo "$username already holds a phone-contact-info credential -- skipping claim"
else
    run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf phone-contact-info --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"
fi

banner "$username Claim credential email"
if [ -n "$(credential_claimed email-contact-info)" ]; then
    echo "$username already holds a email-contact-info credential -- skipping claim"
else
    run_cmd "qadenad_alias tx qadena claim-credential $user_a $user_bf email-contact-info --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"
fi

#if serviceprovider is not empty, then do this
if [ -n "$serviceprovider" ] ; then
    if [ -n "$eph_count" ] ; then
        # Directly pass multiple wallet IDs as separate arguments
        echo "Registering multiple ephemeral wallets as authorized signatories"
        cmd="qadenad_alias tx dsvs register-authorized-signatory"
        for i in $(seq 1 $eph_count); do
            banner "$username Setup DSVS authorized signatory as $username-eph$i"
            cmd="$cmd $username-eph$i"
        done
        cmd="$cmd --from $username $USER_FEE_GRANTER_FLAG --yes"
        echo "Executing: $cmd"
        run_cmd "$cmd"
    else
        banner "$username Setup DSVS authorized signatory as $username-eph"
        run_cmd "qadenad_alias tx dsvs register-authorized-signatory $username-eph --from \"$username\" $USER_FEE_GRANTER_FLAG --yes"
    fi
fi

# if eph_count = 1, then do this
if [ "$eph_count" -eq 1 ]; then

    if [ -n "$acceptcredentialtypes" ] ; then
        banner "$username Accept credential types $acceptcredentialtypes"
        # Guarded like every other create-wallet here: a local key from an earlier attempt
        # makes this abort with "friendly name already exists" before any broadcast.
        if [ -n "$(eph_ready 2)" ]; then
            echo "$username-eph2 already exists ON CHAIN -- skipping create-wallet"
        else
            if qadenad_alias keys show "$username-eph2" --address > /dev/null 2>&1; then
                echo "$username-eph2 has a local key but NO wallet on chain -- removing and retrying"
                qadenad_alias keys delete "$username-eph2" --yes > /dev/null 2>&1 || true
                qadenad_alias keys delete "$username-eph2-credential" --yes > /dev/null 2>&1 || true
            fi
            run_cmd "qadenad_alias tx qadena create-wallet $username-eph2 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"2\" --accept-credential-types $acceptcredentialtypes --yes"
        fi
        banner "$username Bind phone nameservice to $username-eph2"
        run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph2 $USER_FEE_GRANTER_FLAG --yes"
    else
        if [ -n "$eph_count" ] ; then
            banner "$username Bind phone nameservice to $username-eph1"
            run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph1 $USER_FEE_GRANTER_FLAG --yes"
        else
            banner "$username Bind phone nameservice to $username-eph"
            run_cmd "qadenad_alias tx nameservice bind-credential $username phone-contact-info --from $username-eph $USER_FEE_GRANTER_FLAG --yes"
        fi
    fi

    if [ -n "$requiresendertypes" ] ; then
        banner "$username require sender credential types $requiresendertypes"
        # Guarded like every other create-wallet here: a local key from an earlier attempt
        # makes this abort with "friendly name already exists" before any broadcast.
        if [ -n "$(eph_ready 3)" ]; then
            echo "$username-eph3 already exists ON CHAIN -- skipping create-wallet"
        else
            if qadenad_alias keys show "$username-eph3" --address > /dev/null 2>&1; then
                echo "$username-eph3 has a local key but NO wallet on chain -- removing and retrying"
                qadenad_alias keys delete "$username-eph3" --yes > /dev/null 2>&1 || true
                qadenad_alias keys delete "$username-eph3-credential" --yes > /dev/null 2>&1 || true
            fi
            run_cmd "qadenad_alias tx qadena create-wallet $username-eph3 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"3\" --require-sender-credential-types $requiresendertypes --yes"
        fi
        banner "$username Bind email nameservice to $username-eph3"
        run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph3 $USER_FEE_GRANTER_FLAG --yes"
    else 
        if [ -n "$eph_count" ] ; then
            banner "$username Bind email nameservice to $username-eph1"
            run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph1 $USER_FEE_GRANTER_FLAG --yes"
        else
            banner "$username Bind email nameservice to $username-eph"
            run_cmd "qadenad_alias tx nameservice bind-credential $username email-contact-info --from $username-eph $USER_FEE_GRANTER_FLAG --yes"
        fi
    fi

    if [ -n "$acceptpassword" ] ; then
        banner "$username Accept password"
        # Guarded like every other create-wallet here: a local key from an earlier attempt
        # makes this abort with "friendly name already exists" before any broadcast.
        if [ -n "$(eph_ready 4)" ]; then
            echo "$username-eph4 already exists ON CHAIN -- skipping create-wallet"
        else
            if qadenad_alias keys show "$username-eph4" --address > /dev/null 2>&1; then
                echo "$username-eph4 has a local key but NO wallet on chain -- removing and retrying"
                qadenad_alias keys delete "$username-eph4" --yes > /dev/null 2>&1 || true
                qadenad_alias keys delete "$username-eph4-credential" --yes > /dev/null 2>&1 || true
            fi
            run_cmd "qadenad_alias tx qadena create-wallet $username-eph4 $pioneer $createwalletsponsor --link-to-real-wallet $username --account-mnemonic=\"$usermnemonic\" --eph-account-index \"4\" --accept-password=\"$acceptpassword\" --yes"
        fi
    fi

fi

