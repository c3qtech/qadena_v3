#!/bin/zsh

set -e

# get script dir
SCRIPT_DIR="${0:A:h}"
# This script's own directory, captured BEFORE setup_env.sh is sourced: that file sets
# SCRIPT_DIR="${0:A:h}" at its own top level, so afterwards SCRIPT_DIR points at scripts/.
# $_DEPLOY_HERE is not assigned anywhere else.
_DEPLOY_HERE="${0:A:h}"

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

# WHICH DEPLOYMENT THIS IS -- pre-scanned, because $VERITAS_SEC_HOME is defaulted from it below and
# QADENA_KEYRING_DIR is derived from that.  Must match the --deployment step_1 ran with: these read
# the variables.json step_1 wrote, and reading the wrong home is how a run reports a clean chain
# while operating on another deployment's keys.
DEPLOYMENT="${DEPLOYMENT:-veritas}"
_dep_i=1
while (( _dep_i <= $# )); do
    [[ "${@[$_dep_i]}" == "--deployment" ]] && DEPLOYMENT="${@[$((_dep_i+1))]:?--deployment needs a name}"
    _dep_i=$(( _dep_i + 1 ))
done
source "$_DEPLOY_HERE/../foundation_scripts/deployment_profile.sh"
deployment_profile_load "$DEPLOYMENT" || exit 1
export QADENA_KEYRING_BACKEND="${_kb_caller:-file}"

# Minimal argument handling: the chain's location is a per-run fact and belongs on the command
# line, not in ambient environment.  The flag exports QADENA_NODE so every child script and
# qadenad_alias call inherits it; the chain-id is then derived from that node by setup_env.
while [ $# -gt 0 ]; do
    case "$1" in
        --node) export QADENA_NODE="$2"; shift 2 ;;
        --keyring-passfile) export QADENA_KEYRING_PASSFILE="$2"; shift 2 ;;
        --sec-home) export VERITAS_SEC_HOME="$2"; shift 2 ;;
        --deployment) shift 2 ;;   # pre-scanned at the top; consumed so it is not "unknown"
        *) echo "unknown option: $1"
           echo "usage: $0 [--deployment <name>] [--node <rpc>] [--sec-home <dir>] [--keyring-passfile <file>]"
           echo "  --deployment  $(deployment_profile_list); default $DEPLOY_NAME.  MUST match step_1's."
           exit 1 ;;
    esac
done

# UNLOCK ONCE, HERE.  qadena_keyring_unlock has existed in setup_env.sh since the file backend was
# added and was never called from anywhere -- so with backend=file, QADENA_KEYRING_PASS stayed
# empty, qadenad_alias took its no-passphrase branch, and qadenad blocked reading stdin with the
# prompt swallowed by whatever call site had captured its output.  That is a hang with no message
# and no prompt (measured 2026-09-07 on step_2).  Called after argument parsing so
# --keyring-passfile is already in effect.
qadena_keyring_unlock

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

# FUNDING MODE.
#
#   feegrant (default) -- the Qadena foundation pays these wallets' fees by fee grant. Nothing is
#                         transferred, so there is no SEC treasury to hold, no AML whitelist needed
#                         to move it, and the sponsorship is revocable, expiring and spend-limited.
#   banksend           -- the original behaviour: sec-treasury transfers tokens to every wallet.
#
# Set VERITAS_FUND_MODE=banksend to restore the old path.
# THE RENAMED ACCOUNT.  The foundation sponsors more than one programme out of bucket 10 -- its
# notes list "SEC PH VERITAS 60M; future MOUs; OTC swap reserve" -- so the sponsor accounts carry
# the programme in their names.  A default of `foundation-appsvr` now points at an account that
# does not exist, and step_2 would wait forever for funds in it.
: ${VERITAS_FOUNDATION_APPSVR:=foundation-veritas-appsvr}

# Every message a VERITAS provider/signer wallet broadcasts, from the trace of the app-server's
# GenerateOrBroadcastTxCLISync call sites. A type missing here fails closed at the operation that
# needs it, so this list and the app-server's allowlist must move together.
# THE UNION OF BOTH WIDE SETS, DELIBERATELY.
#
# Two "wide" allowances used to exist: this operational set, and create_user's USER_MSGS (claims,
# credential updates, signatory registration, binds, ProtectPrivateKey).  A grantee holds ONE
# allowance per granter, and step_3's widen ran LAST -- so the end state silently dropped every
# claim/rotation/bind message, and the bring-up's own claims passed only because they executed
# between the two grants.  An ordering dependency invisible from the final state.
#
# MsgRevokeAllowance joins MsgGrantAllowance because the server always does revoke-then-grant
# (api/handlers/fee_grant.go:224-232) -- allowances do not layer, so a re-grant must revoke
# first.  Permitting the grant but not the revoke allows half of a pair that is only ever
# used together: with FoundationUsersAddress blank, wrapForGranter returns the BARE message
# and the pool wallet signs a raw revoke this allowance would refuse.  Verified in the
# app-server source 2026-09-06.
#
# The app-server itself never needs the dropped messages (verified against its code, 2026-09-06),
# so nothing broke in steady state -- but any re-run, repair or partial recovery would hit the
# narrowed set with no diagnosis.  The union costs nothing and removes the dependency.
# FROM THE PROFILE.  This was a literal here and an identical literal in provider_scripts/setup_provider_base.sh; ENF needs one type
# the others do not (MsgExecuteContract), so the list is per-deployment now.  See
# foundation_scripts/deployment_profile.sh.
VERITAS_APPSVR_MSGS="$DEPLOY_APPSVR_MSGS"

# FAIL LOUD ON AN EMPTY SET.  The value is EXPORTED by the profile and this script is a CHILD
# process -- setup_prerequisites.sh calls it too, and does not load a profile.  An empty
# allow-list is not a no-op: the grant is issued and permits NOTHING, so every wallet it covers
# looks funded and cannot transact, with the first symptom arriving far from here.
if [ -z "$VERITAS_APPSVR_MSGS" ]; then
    echo "FAILED: no DEPLOY_APPSVR_MSGS in the environment -- the caller did not load a"
    echo "  deployment profile, and granting an empty allow-list would produce wallets that"
    echo "  cannot transact.  Source foundation_scripts/deployment_profile.sh first."
    exit 1
fi


# fund_wallet <address> -- give this wallet the means to transact, however this deployment does it.
fund_wallet() {
    local qadena_addr="$1"
    if [ "$VERITAS_FUND_MODE" = "banksend" ]; then
        echo "Sending $per_account_amount to $qadena_addr from $treasuryname" >&2
        qadenad_alias tx bank send $treasuryname $qadena_addr $per_account_amount \
            --from $treasuryname --yes --output json \
            --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment
        return
    fi
    # Toll-free: a GRANT, not a transfer. Routed through grant_as_foundation so it is signed by
    # SEC's admin key as a MsgExec when VERITAS_SEC_ADMIN is set -- step_3 is SEC's step and must not
    # require a foundation key. Progress goes to STDERR: the caller captures stdout as JSON, and a
    # stray echo there corrupts it and kills jq with "Invalid numeric literal".
    local granter
    granter=$(qadenad_alias keys show "$VERITAS_FOUNDATION_APPSVR" --address 2>/dev/null || true)
    [ -n "$granter" ] || granter="$VERITAS_FOUNDATION_APPSVR"
    echo "Granting fees to $qadena_addr from $VERITAS_FOUNDATION_APPSVR" >&2
    # REPORT THE RESULT, DO NOT ERASE IT.  grant_as_foundation waits for the grant and checks its
    # on-chain code; this then printed code 0 unconditionally, so a FAILED grant was announced as a
    # warning on stderr and reported as success on stdout -- and the caller, which reads stdout as
    # a tx result, carried on.  The wallet then exists with no allowance and cannot pay for
    # anything, which surfaces much later as "spendable balance 0aqdn" on an unrelated operation.
    if grant_as_foundation "$granter" "$qadena_addr" "$VERITAS_APPSVR_MSGS"; then
        echo '{"code":0,"txhash":"","note":"feegrant"}'
    else
        echo "  WARNING: grant failed for $qadena_addr" >&2
        echo '{"code":1,"txhash":"","note":"feegrant-failed"}'
    fi
}

# read variables from json file

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
: ${VERITAS_SEC_HOME:="$DEPLOY_SEC_HOME"}

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

# WARN ABOUT A SPLIT DEPLOYMENT, which is what the ordering bug above used to produce.
#
# step_1 fixed QADENA_KEYRING_DIR from the DEFAULT home before parsing --sec-home, so a run with
# --sec-home wrote keys to ~/sec-veritas and mnemonics to the requested directory.  Nothing said
# so: the admin key was created and its address printed, and the failure surfaced two steps later
# as "key with address <sponsor> not found" while signing as the foundation.  The ordering is
# fixed, but a directory left behind by an earlier run still looks like a working deployment.
if [[ "$VERITAS_SEC_HOME" != "$DEPLOY_SEC_HOME" ]] \
   && ls "$DEPLOY_SEC_HOME"/keyring/keyring-*/*.info > /dev/null 2>&1; then
    echo ""
    echo "NOTE: $DEPLOY_SEC_HOME also holds keys, and this run uses $VERITAS_SEC_HOME."
    echo "  A version of step_1 before 2026-09-08 wrote keys to the default home while writing"
    echo "  mnemonics to --sec-home, splitting a deployment across both.  If this run cannot find"
    echo "  a key it expects, look there:"
    echo "      ls $DEPLOY_SEC_HOME/keyring/keyring-file/"
    echo "  and either move them across or start clean.  Nothing is read from there automatically."
    echo ""
fi

# READ FROM SEC'S DIRECTORY, AND SAY SO WHEN IT IS NOT THERE.  A missing variables.json used to
# surface as jq errors and empty variables, which then flowed into transactions as blanks.
# mnemonics.json is no longer written -- step_1 seals directly -- so require only
# variables.json here and let sec_mnemonic() report a missing mnemonic in either form.
for _f in variables.json; do
    [ -r "$VERITAS_SEC_HOME/$_f" ] || {
        echo "$VERITAS_SEC_HOME/$_f is missing -- run step_1.sh first,"
        echo "or point at the right directory:  --sec-home <dir>"
        exit 1; }
done

provideramount=$(jq -r .provideramount "$VERITAS_SEC_HOME/variables.json")
signeramount=$(jq -r .signeramount "$VERITAS_SEC_HOME/variables.json")
createwalletsponsoramount=$(jq -r .createwalletsponsoramount "$VERITAS_SEC_HOME/variables.json")
pioneer=$(jq -r .pioneer "$VERITAS_SEC_HOME/variables.json")
count=$(jq -r .count "$VERITAS_SEC_HOME/variables.json")
identityprovidername=$(jq -r .identityprovidername "$VERITAS_SEC_HOME/variables.json")
dsvsprovidername=$(jq -r .dsvsprovidername "$VERITAS_SEC_HOME/variables.json")
createwalletsponsorname=$(jq -r .createwalletsponsorname "$VERITAS_SEC_HOME/variables.json")
dsvsname=$(jq -r .dsvsname "$VERITAS_SEC_HOME/variables.json")
email=$(jq -r .email "$VERITAS_SEC_HOME/variables.json")
avalue=$(jq -r .avalue "$VERITAS_SEC_HOME/variables.json")
phone=$(jq -r .phone "$VERITAS_SEC_HOME/variables.json")
firstname=$(jq -r .firstname "$VERITAS_SEC_HOME/variables.json")
birthdate=$(jq -r .birthdate "$VERITAS_SEC_HOME/variables.json")
treasuryname=$(jq -r .treasuryname "$VERITAS_SEC_HOME/variables.json")

# TOLL-FREE: the SPONSOR must be an account that EXISTS ON CHAIN.  create-wallet takes it as a
# message field (and has grantFee() pay from it), so it cannot be fee-granted and it cannot be
# sec-treasury -- in this mode sec-treasury is never funded, so it has no account at all and
# create-wallet fails with "account ... not found" / "Couldn't grant fee".  The foundation account
# is funded and is already the payer for SEC's operational wallets, so it plays the sponsor role.
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    echo "toll-free: $VERITAS_FOUNDATION_APPSVR sponsors wallet creation; $treasuryname is not used"
    # RESOLVE THE SPONSOR TO AN ADDRESS, HERE, ONCE -- SEC's keyring does not hold it.
    #
    # The foundation account lives in QFI's coordinator keyring; after the keyring split SEC's box
    # has no entry for the NAME, so every place that passed it to a query or a sponsor argument
    # spun on "unknown address" forever (the funds-wait loop did exactly that).  On a SEC box the
    # variable holds the ADDRESS -- printed by QFI's prepare stage -- and a name is accepted only
    # where a keyring can actually resolve it (the single-operator harness).
    # THE FILE IS THE RUN'S TRUTH.  step_1 recorded the handoff address in variables.json when it
    # was given --appsvr; that value wins.  When the file has none (the single-keyring harness,
    # which passes no --appsvr), the exported VERITAS_FOUNDATION_APPSVR fills in, and the name
    # default after that.  The resolved value is exported so create_user and the provider scripts
    # inherit one consistent answer.
    _file_appsvr=$(jq -r '.appsvraddr // empty' "$VERITAS_SEC_HOME/variables.json" 2>/dev/null || true)
    [ -n "$_file_appsvr" ] && VERITAS_FOUNDATION_APPSVR="$_file_appsvr"
    export VERITAS_FOUNDATION_APPSVR
    case "$VERITAS_FOUNDATION_APPSVR" in
        qadena1*) sponsor_addr="$VERITAS_FOUNDATION_APPSVR" ;;
        *)
            sponsor_addr=$(qadenad_alias keys show "$VERITAS_FOUNDATION_APPSVR" --address 2>/dev/null | tr -d '\r')
            [ -n "$sponsor_addr" ] || {
                echo "cannot resolve '$VERITAS_FOUNDATION_APPSVR' -- not an address, and not in this keyring."
                echo "On the $DEPLOY_DISPLAY machine export the ADDRESS QFI handed over:"
                echo "    export VERITAS_FOUNDATION_APPSVR=qadena1..."
                exit 1
            } ;;
    esac
    treasuryname="$sponsor_addr"

    # THE DELEGATED SIGNER, SELF-DETECTED.  The admin's key NAME is in variables.json (step_1
    # wrote it), so nobody has to export VERITAS_SEC_ADMIN -- but the name alone is not enough:
    # using it is only correct if QFI has actually granted the authz, and the harness never does.
    # So: explicit env still wins; otherwise use the recorded admin IF AND ONLY IF the chain shows
    # an authz grant from the sponsor to it.  Delegation-if-delegated, direct-sign otherwise --
    # the run adapts to what is true on chain instead of what someone remembered to export.
    if [ -z "${VERITAS_SEC_ADMIN:-}" ]; then
        # SAY WHICH CONDITION FAILED.  This had ONE message for four different causes -- no
        # adminname recorded, no local key, an unreachable chain, or a genuinely absent grant --
        # and then fell back to direct signing, which needs the FOUNDATION's key.  On a split
        # keyring that key is not here, so the run continued and died much later with
        # "key with address <sponsor> not found", naming the granter rather than the delegation
        # that should have avoided needing it.  Measured 2026-09-08 on the staging chain, where
        # the three authz grants were present the whole time.
        _adm=$(jq -r '.adminname // empty' "$VERITAS_SEC_HOME/variables.json" 2>/dev/null || true)
        if [ -z "$_adm" ]; then
            echo "no adminname in $VERITAS_SEC_HOME/variables.json -- signing directly (harness mode)"
        else
            _adm_addr=$(qadenad_alias keys show "$_adm" --address 2>/dev/null || true)
            if [ -z "$_adm_addr" ]; then
                echo "WARNING: '$_adm' is recorded but NOT in this keyring -- cannot use the delegation."
                echo "  Signing will fall back to the foundation's own key, which the $DEPLOY_DISPLAY box does not have."
                echo "  Is VERITAS_SEC_HOME ($VERITAS_SEC_HOME) the home step_1 wrote?"
            else
                _gr=$(qadenad_alias query authz grants "$sponsor_addr" "$_adm_addr" --output json 2>&1 || true)
                case "$_gr" in
                    *"no route to host"*|*"connection refused"*|*"post failed"*)
                        echo "WARNING: cannot reach the chain to check the delegation -- NOT falling back"
                        echo "  silently.  Fix --node and re-run."
                        exit 1 ;;
                esac
                if print -r -- "$_gr" | jq -e '(.grants|length) > 0' >/dev/null 2>&1; then
                    export VERITAS_SEC_ADMIN="$_adm"
                    echo "delegated signing: $_adm ($_adm_addr) -- authz from $sponsor_addr verified on chain"
                else
                    echo "WARNING: '$_adm' ($_adm_addr) holds NO authz from $sponsor_addr."
                    echo "  Has the foundation run sec_veritas_after_step_1.sh against THIS chain?"
                    echo "  Signing will fall back to the foundation's own key, which the $DEPLOY_DISPLAY box does not have."
                fi
            fi
        fi
    else
        export VERITAS_SEC_ADMIN
    fi
fi




# read mnemonics from json file
createwalletsponsormnemonic=$(sec_mnemonic "$VERITAS_SEC_HOME" createwalletsponsormnemonic)
signermnemonic=$(sec_mnemonic "$VERITAS_SEC_HOME" signermnemonic)

# read proposal id from identityprovidername.proposal_id
identityproposal_id=$(cat $qadenaproviderscripts/proposals/$identityprovidername.proposal_id)
dsvsproposal_id=$(cat $qadenaproviderscripts/proposals/$dsvsprovidername.proposal_id)
# ASK WHETHER THE PROVIDER IS REGISTERED, NOT WHETHER A PARTICULAR PROPOSAL PASSED.
#
# The ids come from files step_2 writes, and step_2 OVERWRITES them every run.  A re-run therefore
# points this wait at the newest proposal -- which, when the provider was already registered by an
# earlier one, is a duplicate nobody will deposit on.  It then waits forever for something that
# cannot pass, while the condition it actually cares about has been true the whole time.
# (Measured 2026-09-07: step_2 re-ran, wrote ids 5 and 6, and step_3 hung on them while proposals
# 1 and 2 had registered both providers.)
#
# Registration is the real precondition -- a provider is usable when it has a TRANSACTION public
# key, which create-wallet registers and which nothing else here can fake.  Check that first and
# only fall back to watching a proposal if it is genuinely absent.
provider_registered() {
    local _p="$1" _id
    _id=$(qadenad_alias query qadena list-interval-public-key-id --output json 2>/dev/null \
            | jq -r --arg n "$_p" '(.intervalPublicKeyID // [])[] | select(.nodeID==$n) | .pubKID' 2>/dev/null)
    [ -n "$_id" ] || return 1
    local _k
    _k=$(qadenad_alias query qadena list-public-key --output json 2>/dev/null \
           | jq -r --arg i "$_id" '[(.publicKey // [])[] | select(.pubKID==$i and .pubKType=="transaction")] | length' 2>/dev/null)
    [ "${_k:-0}" -gt 0 ]
}

echo "Waiting for approval of providers"
for _pv in "$identityprovidername:$identityproposal_id" "$dsvsprovidername:$dsvsproposal_id"; do
    _name="${_pv%%:*}"; _pid="${_pv##*:}"
    if provider_registered "$_name"; then
        echo "  $_name is already registered on chain -- not waiting on proposal $_pid"
    else
        echo "  $_name not registered yet -- waiting on proposal $_pid"
        $qadenaproviderscripts/query_service_provider_proposal.sh $_pid --wait
    fi
done

echo "Providers approved"


########################################################
# Create wallet sponsor
########################################################

name="$createwalletsponsorname"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$createwalletsponsormnemonic
a="$avalue"
bf="5678"
middlename=""
lastname="Create Wallet Sponsor"
gender="M"
citizenship="PH"
residency="PH"
identityprovider="$identityprovidername"
dsvsserviceprovider=""
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$count"

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${createwalletsponsoramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${createwalletsponsoramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$createwalletsponsoramount
fi

# $mnemonic is ARG 2 and this echoed it verbatim -- the same seed phrase the command below
# consumes.  Print the call without it; the command itself still receives it.
echo "create-user.sh" $name "<mnemonic redacted>" $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf "$identityprovider" "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"
qadena_addr=$(qadenad_alias keys show $name --address)
# SAY WHAT ACTUALLY HAPPENS.  In sponsored mode nothing is sent -- fund_wallet issues a fee
# grant and zero tokens move.  The old unconditional "Sending Nqdn" printed banksend vocabulary
# with a real-looking amount (the banksend-era per-wallet split), and operators reasonably read
# it as a transfer that never occurred.
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    echo "Widening the fee grant for $qadena_addr (sponsored: no tokens move)"
else
    echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
fi
result=$(fund_wallet "$qadena_addr")
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
# The feegrant sentinel carries no hash; `wait-tx` with an EMPTY argument does not error, it
# WAITS -- the run sat at 3216 log lines for minutes doing exactly that (measured 2026-09-06).
if [ -n "$tx_hash" ]; then
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
else
result='{"code":0}'
fi
echo "Result: $result"
if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
    echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
    exit 1
fi

# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    # SAY WHAT ACTUALLY HAPPENS.  In sponsored mode nothing is sent -- fund_wallet issues a fee
# grant and zero tokens move.  The old unconditional "Sending Nqdn" printed banksend vocabulary
# with a real-looking amount (the banksend-era per-wallet split), and operators reasonably read
# it as a transfer that never occurred.
    if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
        echo "Widening the fee grant for $qadena_addr (sponsored: no tokens move)"
    else
        echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
    fi
    result=$(fund_wallet "$qadena_addr")
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    # The feegrant sentinel carries no hash; `wait-tx` with an EMPTY argument does not error, it
# WAITS -- the run sat at 3216 log lines for minutes doing exactly that (measured 2026-09-06).
if [ -n "$tx_hash" ]; then
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
else
result='{"code":0}'
fi
    echo "Result: $result"
    if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
        echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
        exit 1
    fi
done


name="$dsvsname"
echo "-------------------------"
echo "Setting up $name"
echo "-------------------------"

mnemonic=$signermnemonic
# add 1 to avalue
avalue=$((avalue + 1))
a="$avalue"
bf="5678"
middlename=""
gender="F"
citizenship="PH"
residency="PH"
dsvsserviceprovider="$dsvsprovidername"
identityprovider="$identityprovidername"
acceptcredentialtypes=""
acceptpassword=""
requiresendertypes=""
eph_count="$count"

# compute per-account amount
if [ $count -gt 0 ]; then
    echo "count is greater than 0"
    # Extract numeric prefix (digits)
    numeric_part=${signeramount%%[!0-9]*}

    # Extract suffix (non-digits after the number)
    token_suffix=${signeramount#$numeric_part}

    # Divide
    per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

    # Output
    echo "per_account_amount: $per_account_amount"
else
    echo "count is 0"
    per_account_amount=$signeramount
fi

$qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$treasuryname"
qadena_addr=$(qadenad_alias keys show $name --address)
# SAY WHAT ACTUALLY HAPPENS.  In sponsored mode nothing is sent -- fund_wallet issues a fee
# grant and zero tokens move.  The old unconditional "Sending Nqdn" printed banksend vocabulary
# with a real-looking amount (the banksend-era per-wallet split), and operators reasonably read
# it as a transfer that never occurred.
if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
    echo "Widening the fee grant for $qadena_addr (sponsored: no tokens move)"
else
    echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
fi
result=$(fund_wallet "$qadena_addr")
echo "Result: $result"
# get tx hash
tx_hash=$(echo $result | jq -r .txhash)
echo "tx hash: $tx_hash"
# wait for result
# The feegrant sentinel carries no hash; `wait-tx` with an EMPTY argument does not error, it
# WAITS -- the run sat at 3216 log lines for minutes doing exactly that (measured 2026-09-06).
if [ -n "$tx_hash" ]; then
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
else
result='{"code":0}'
fi
echo "Result: $result"
if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
    echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
    exit 1
fi
# fund eph wallets
for i in $(seq 1 $eph_count); do
    qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
    # SAY WHAT ACTUALLY HAPPENS.  In sponsored mode nothing is sent -- fund_wallet issues a fee
# grant and zero tokens move.  The old unconditional "Sending Nqdn" printed banksend vocabulary
# with a real-looking amount (the banksend-era per-wallet split), and operators reasonably read
# it as a transfer that never occurred.
    if [ "$VERITAS_FUND_MODE" = "foundation-sponsored" ]; then
        echo "Widening the fee grant for $qadena_addr (sponsored: no tokens move)"
    else
        echo "Sending $per_account_amount to $qadena_addr from $treasuryname"
    fi
    result=$(fund_wallet "$qadena_addr")
    echo "Result: $result"
    # get tx hash
    tx_hash=$(echo $result | jq -r .txhash)
    echo "tx hash: $tx_hash"
    # wait for result
    # The feegrant sentinel carries no hash; `wait-tx` with an EMPTY argument does not error, it
# WAITS -- the run sat at 3216 log lines for minutes doing exactly that (measured 2026-09-06).
if [ -n "$tx_hash" ]; then
result=$(qadenad_alias query wait-tx $tx_hash --output json --timeout 30s)
else
result='{"code":0}'
fi
    echo "Result: $result"
    if [ "$(echo $result | jq -r '.code // -1')" -ne 0 ]; then
        echo "Failed to send $per_account_amount to $qadena_addr from $treasuryname"
        exit 1
    fi
done

$qadenatestscripts/extract_ephem_keys.sh --provider $identityprovidername# --count $count --include-base-provider --include-base-provider-credential
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsprovidername# --count $count --include-base-provider
$qadenatestscripts/extract_ephem_keys.sh --provider $createwalletsponsorname# --count $count --include-base-provider
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsname# --count $count
$qadenatestscripts/extract_ephem_keys.sh --provider $dsvsname#-credential --count $count

# ---------------------------------------------------------------------------------------------
# THE HANDOFF TO QFI.
#
# The foundation's last action authorises this sponsor pool -- two grants per wallet, both signed
# by foundation-users, which only the foundation can sign.  It therefore needs every pool member's
# ADDRESS, and cannot work them out: the ephemerals are HD derivations of THIS wallet's mnemonic
# (--eph-account-index), so deriving them means holding a key the foundation must never have.
#
# Until now nothing emitted them.  step_4 resolved the names from its own keyring instead, which
# works only in a harness where one keyring holds both sides' keys -- and fails per-wallet and
# silently on a real deployment, leaving a partly-authorised pool that breaks onboarding for SOME
# users and not others.
#
# Written as JSON with the chain-id and the count so step_4 can CHECK it rather than trust it.
pool_file="$VERITAS_SEC_HOME/pool_addresses.json"
{
    printf '{\n'
    printf '  "chain_id": "%s",\n'     "$(qadenad_alias status 2>/dev/null | jq -r '.node_info.network // ""')"
    printf '  "sponsor_base": "%s",\n' "$createwalletsponsorname"
    printf '  "count": %s,\n'          "$count"
    printf '  "pool": [\n'
    _first=1
    for i in $(seq 0 "$count"); do
        if [ "$i" -eq 0 ]; then _w="$createwalletsponsorname"; else _w="$createwalletsponsorname-eph$i"; fi
        _a=$(qadenad_alias keys show "$_w" --address 2>/dev/null | tr -d '\r')
        [ -n "$_a" ] || { echo "  WARNING: $_w has no address -- pool handoff will be short" >&2; continue; }
        [ "$_first" -eq 1 ] || printf ',\n'
        printf '    {"name": "%s", "address": "%s"}' "$_w" "$_a"
        _first=0
    done
    printf '\n  ]\n}\n'
} > "$pool_file"

# EMITTED AS A PASTE BLOCK, NOT A FILE TO TRANSFER.
#
# The two sides are different machines and often different organisations; "send them this file"
# means email, a bucket, or a chat attachment, each of which is a chance to send the wrong one or
# a stale one.  A block the foundation operator pastes into a terminal recreates the file locally
# and runs the command in one action, and the JSON inside it still carries the chain-id and count
# so step_4 verifies rather than trusts.
echo ""
echo "==================================================================="
echo "SEND THIS BLOCK TO QFI -- they paste it into a terminal as-is:"
echo "==================================================================="
echo ""
echo "cat > /tmp/veritas-pool.json <<'POOLEOF'"
cat "$pool_file"
echo "POOLEOF"
echo "foundation_scripts/sec_veritas_after_step_3.sh --pool-addresses /tmp/veritas-pool.json${QADENA_NODE:+ --node $QADENA_NODE}"
echo ""
echo "==================================================================="
jq -r '"  \(.pool|length) wallet(s), base \(.sponsor_base), chain \(.chain_id)"' "$pool_file" 2>/dev/null
echo "  QFI's script verifies the chain-id, the count, the bech32 form and that every address"
echo "  exists on chain BEFORE it grants anything -- a short, stale or mangled block is refused"
echo "  outright rather than half-applied."
