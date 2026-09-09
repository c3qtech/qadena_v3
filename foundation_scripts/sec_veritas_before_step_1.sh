#!/bin/zsh
#
# RUN BY THE QADENA FOUNDATION, BEFORE the SEC VERITAS group runs veritas_scripts/step_1.sh.
#
# Everything here is the FOUNDATION's to do and none of it is SEC's.  SEC cannot do any of it:
# every transaction is signed by a foundation bucket multisig, and step_1 assumes the result
# already exists.
#
#   HERE     FOUNDATION  stake for voting power; create and fund the two sponsor accounts
#   step_1   SEC         creates its keys, reports its admin address
#   *        FOUNDATION  foundation_scripts/sec_veritas_after_step_1.sh --sec-admin <addr>
#   step_2   SEC         creates its providers, reports two proposal ids
#   *        FOUNDATION  sec_veritas_before_step_1.sh --approve <id> <id>   (deposit + vote, expedited)
#   step_3   SEC         creates its wallets and users
#   *        FOUNDATION  sec_veritas_after_step_3.sh -- the app-server's sponsor pool
#
# WHY THIS EXISTS RATHER THAN testscripts/setup_veritas.sh.  That one is a TEST HARNESS: it plays
# both roles, holds every key in one keyring, and funds everything with `tx bank send --from
# treasury` because on the devnet `treasury` is a single key the primary holds.  On a launch chain
# there is no such key.  Each bucket is an N-of-M multisig whose members are on separate machines
# by design, so every spend here is a ceremony -- build, sign per member, combine, broadcast.
#
# WHICH BUCKET PAYS, AND WHY IT IS NOT A CHOICE.  tokenomics/allocations.csv is the authority and
# it names them:
#
#   10 Public Sector Programs (pubsec)  "Sub-allocations: SEC PH VERITAS 60M; future MOUs; OTC
#                                        swap reserve.  Entities only, never individuals.
#                                        Funds feegrant sponsor account."
#                                       -> the two VERITAS sponsor accounts below.  stakes=no.
#   03 Foundation Treasury (foundation) the ONLY bucket with stakes=yes.  Voting power comes from
#                                       here and nowhere else.
#
# Taking the sponsor float from Adoption or Node Operations would fund SEC out of an allocation
# earmarked for something else, and the CSV is the record anyone later reconciles against.
#
# THE MEMBER KEYS.  --members names the bucket members that will sign, in this keyring:
#     --members pubsec-m1,pubsec-m2,pubsec-m3
# With no --members it PROMPTS for them.  Either way the keys stay here; nothing is relayed.  If
# the members are on separate machines, use --print-ceremony and hand each one their command.
#
#   sec_veritas_before_step_1.sh --stage prepare  --members foundation-m1,foundation-m2,foundation-m3 \
#                      --fund-members pubsec-m1,pubsec-m2,pubsec-m3
#   sec_veritas_before_step_1.sh --stage approve 12 13 --members foundation-m1,foundation-m2,foundation-m3

HERE="${0:A:h}"
# The name to PRINT in usage.  A per-deployment wrapper execs this file, so a hard-coded
# "sec_veritas_*.sh" told an ekycph operator to run a script whose --help they were not
# reading.  The wrapper exports QADENA_PROG; direct callers get the real name.
PROG="${QADENA_PROG:-sec_veritas_before_step_1.sh}"
# CAPTURE BEFORE SOURCING.  setup_env.sh defaults QADENA_KEYRING_BACKEND to `test` for the
# harness, and every script here sources it first -- so a later ${QADENA_KEYRING_BACKEND:-file}
# always saw "test" and the intended file default was dead code.  Foundation tooling operates on
# the ENCRYPTED coordinator keyring; only an explicit caller choice may say otherwise.
_kb_caller="${QADENA_KEYRING_BACKEND:-}"
source "$HERE/../scripts/setup_env.sh"

# setup_env.sh CLOBBERS SCRIPT_DIR.  Captured above, before the source, because three scripts have
# already been broken by assuming it survives.
SCRIPT_DIR="$HERE"
MSIG="$SCRIPT_DIR/../scripts/multisig_sign.sh"

set -e

# --deployment IS PRE-SCANNED, BEFORE THE MAIN PARSE LOOP.  Two reasons, both learned the hard way.
# usage() prints the profile's key names as the defaults, and --help is handled inside that loop, so
# a profile resolved after it would document veritas's names for an ekycph run.  And step_1.sh was
# broken for a week by deriving a path from $VERITAS_SEC_HOME at the top while --sec-home was parsed
# 120 lines later: every run wrote half its state into the default directory.  Resolve first,
# override in the loop.
DEPLOYMENT="${DEPLOYMENT:-veritas}"
_dep_i=1
while (( _dep_i <= $# )); do
    [[ "${@[$_dep_i]}" == "--deployment" ]] && DEPLOYMENT="${@[$((_dep_i+1))]:?--deployment needs a name}"
    _dep_i=$(( _dep_i + 1 ))
done
source "$SCRIPT_DIR/deployment_profile.sh"
deployment_profile_load "$DEPLOYMENT" || exit 1

STAGE="prepare"
FUND_BUCKET="$DEPLOY_FUND_BUCKET"    # allocations.csv bucket 10 for veritas; see the profile
STAKE_BUCKET="$DEPLOY_STAKE_BUCKET"  # 03 Foundation Treasury -- the only bucket with stakes=yes
# NAMED FOR THE DEPLOYMENT, NOT JUST THE ROLE.  Bucket 10's notes list "SEC PH VERITAS 60M;
# future MOUs; OTC swap reserve" -- so the foundation will sponsor more than one programme out of
# the same bucket, and a bare `foundation-appsvr` would collide the moment the second one starts.
# The keyring has no namespaces: a name is unique per keyring and nothing warns on reuse.
APPSVR="$DEPLOY_APPSVR"
USERS="$DEPLOY_USERS"
# 100,000 QDN PER SPONSOR ACCOUNT -- THE MAINNET FIGURE, DECIDED 2026-09-05.
#
# testscripts/setup_veritas.sh uses 2,000,000 for these same two accounts, and its reasoning is
# about FEE VOLUME rather than endowment: they pay for many wallets, and credential issuance is
# by far the most expensive operation on this chain (~5.9e19 aqdn each, against ~3.2e14 for a
# document signature).  100,000 is the deliberate choice here; raise it with --amount if the
# deployment's credential volume warrants it.
#
# TOPPING UP IS CHEAP, OVERFUNDING IS NOT.  Another transfer from pubsec is one more ceremony.
# Getting money back OUT is not: a sponsor account is not a wallet and is not on the AML
# whitelist, so a send from it is refused with code 1159 and recovering it needs a governance
# proposal.  When unsure, fund less.
AMOUNT="100000"               # qdn, per sponsor account
STAKE=""                      # qdn; empty = compute what expedited voting needs
VALIDATOR=""
MEMBERS=""
FUND_MEMBERS=""
MNEMONICS_DIR=""
COORD_HOME=""
KEYRING_PASSFILE=""
# FILE, NOT test.  These scripts operate on the COORDINATOR keyring, which derive_launch_keys.sh
# creates with --keyring-backend file -- encrypted.  `test` is an UNENCRYPTED keyring, and pointing
# foundation tooling at one by default is wrong twice: it is the wrong keyring (the buckets are not
# in it, so every lookup fails with "no key"), and an unencrypted default has no business anywhere
# near launch custody.  Pass --keyring-backend test explicitly for a devnet.
BACKEND="${_kb_caller:-file}"
WORKDIR=""
PRINT_ONLY=0
VIA_SSH=""
PROPOSALS=()
SEALPASS=""
# EVERY TRANSACTION THIS RUN SENDS, WITH ITS HASH.  A ceremony is many transactions and the only
# durable evidence of what happened is the hash -- printed once, mid-run, in scrollback that a
# long ceremony will bury.  Collected here and printed at the end so the operator can re-check any
# of them later with `qadenad query tx <hash>`.
TXLOG=()

usage() {
    print "Usage:"
    print "  $PROG --stage prepare  [options]      # BEFORE SEC's step_1"
    print "  $PROG --stage approve <proposal-id>... [options]"
    print ""
    print "  --members <m1,m2,..>        members of the STAKE bucket ($STAKE_BUCKET) that sign."
    print "                              Omit to be prompted."
    print "  --fund-members <m1,..>      members of the FUND bucket ($FUND_BUCKET).  Defaults to"
    print "                              --members if the same people hold both."
    print "  --deployment <name>         which programme this is: $(deployment_profile_list)."
    print "                              Default $DEPLOY_NAME.  Selects the sponsor key names and"
    print "                              the sponsors/pregrant/pool filenames -- everything below"
    print "                              defaults from it."
    print "  --fund-bucket <name>        default $FUND_BUCKET  (allocations.csv: pubsec is bucket"
    print "                              10 Public Sector Programs, adoption is 01 Adoption"
    print "                              Programs -- and they have DIFFERENT thresholds, 5of7"
    print "                              against 3of5)"
    print "  --stake-bucket <name>       default $STAKE_BUCKET  (allocations.csv bucket 03)"
    print "  --amount <qdn>              per sponsor account, default $AMOUNT"
    print "  --stake <qdn>               override the computed expedited-voting stake"
    print "  --validator <valoper>       delegate to this validator (default: the largest)"
    print "  --appsvr / --users <name>   account names, defaults $APPSVR / $USERS"
    print "  --print-ceremony            print the commands for members on other machines; sign"
    print "                              nothing here"
    print "  --node <rpc>                the chain RPC, e.g. tcp://10.211.55.5:26657.  Default"
    print "                              \$QADENA_NODE or tcp://localhost:26657.  The chain-id is"
    print "                              then asked of that node -- never trusted from a local file."
    print "  --via-ssh <user@host>       run chain-touching calls on that node (see multisig_sign.sh)"
    print "  --workdir <dir>             where the unsigned/partial tx files go"
    print "  --coord-home <dir>          the COORDINATOR keyring holding the bucket multisigs --"
    print "                              derive_launch_keys.sh --home.  The node's own keyring does"
    print "                              NOT hold them, and should not."
    print "  --keyring-backend <b>       default $BACKEND (encrypted); 'test' for a devnet keyring"
    print "  --keyring-passfile <f>      read the keyring passphrase from a file instead of asking"
    print "  --mnemonics-dir <dir>       REQUIRED if $APPSVR/$USERS do not exist yet: where"
    print "                              each new key's mnemonic is SEALED.  Same format as"
    print "                              derive_launch_keys.sh; read back with mnemonic.sh show."
    exit ${1:-1}
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stage)           STAGE="$2"; shift 2 ;;
        --deployment)      shift 2 ;;   # pre-scanned above; consumed here so it is not "unknown"
        --members)         MEMBERS="$2"; shift 2 ;;
        # --fund-members is the name; --pubsec-members is the original and still works.  The flag
        # was named for the bucket back when pubsec was the only one that funded a deployment;
        # ekycph and enf draw on 01 Adoption Programs, so the bucket-specific name is now wrong for
        # two of the three profiles.
        --fund-members)    FUND_MEMBERS="$2"; shift 2 ;;
        --pubsec-members)  FUND_MEMBERS="$2"; shift 2 ;;
        --fund-bucket)     FUND_BUCKET="$2"; shift 2 ;;
        --stake-bucket)    STAKE_BUCKET="$2"; shift 2 ;;
        --amount)          AMOUNT="$2"; shift 2 ;;
        --stake)           STAKE="$2"; shift 2 ;;
        --validator)       VALIDATOR="$2"; shift 2 ;;
        --appsvr)          APPSVR="$2"; shift 2 ;;
        --users)           USERS="$2"; shift 2 ;;
        --print-ceremony)  PRINT_ONLY=1; shift ;;
        --node)            export QADENA_NODE="$2"; shift 2 ;;
        --via-ssh)         VIA_SSH="$2"; shift 2 ;;
        --workdir)         WORKDIR="$2"; shift 2 ;;
        --mnemonics-dir)   MNEMONICS_DIR="$2"; shift 2 ;;
        --coord-home)      COORD_HOME="$2"; shift 2 ;;
        --keyring-backend) BACKEND="$2"; shift 2 ;;
        --keyring-passfile) KEYRING_PASSFILE="$2"; shift 2 ;;
        --help|-h)         usage 0 ;;
        -*)                print -u2 "unknown option: $1"; usage ;;
        *)                 PROPOSALS+=("$1"); shift ;;
    esac
done

[[ -n "$FUND_MEMBERS" ]] || FUND_MEMBERS="$MEMBERS"
: ${WORKDIR:="${TMPDIR:-/tmp}/$DEPLOY_WORKDIR_TAG.$$"}
mkdir -p "$WORKDIR"; chmod 700 "$WORKDIR"

# THE BUCKET KEYS ARE NOT IN THE NODE'S KEYRING, AND MUST NOT BE.  derive_launch_keys.sh mints
# them into a COORDINATOR home (--home ~/launch/coord), deliberately separate from $QADENAHOME --
# which init.sh does `rm -rf` on.  Point every keyring operation there, and export it so
# multisig_sign.sh (which reads QADENAHOME/QADENA_KEYRING_BACKEND) signs from the same place.
QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
NODE_HOME="${QADENAHOME:-$HOME/qadena}"
[[ -n "$COORD_HOME" ]] || COORD_HOME="$NODE_HOME"
export QADENAHOME="$COORD_HOME"
export QADENA_KEYRING_BACKEND="$BACKEND"

# keyring ops go to the coordinator; queries go to the node.  --keyring-backend is NOT a global
# flag -- `query` rejects it outright -- so the two cannot share one wrapper.
# ASK ONCE, FEED IT IN.  With backend=file the keyring prompts on EVERY read, on stderr -- and
# this script makes a dozen of them plus one per member signature.  Worse, the calls that capture
# output sent stderr to /dev/null, so the prompt was INVISIBLE and the script simply sat there
# looking hung while cosmos waited on stdin.  Measured 2026-09-05.
#
# Twice per call: the backend asks for confirmation the first time it opens a keyring and ignores
# the surplus line every time after.  Same pattern as derive_launch_keys.sh.
KRPASS=""
if [[ "$BACKEND" == "file" ]]; then
    if [[ -n "$KEYRING_PASSFILE" ]]; then
        KRPASS=$(head -1 "$KEYRING_PASSFILE")
        [[ -n "$KRPASS" ]] || { print -u2 "$KEYRING_PASSFILE is empty"; exit 1 }
    else
        print -u2 "The coordinator keyring at $COORD_HOME is encrypted."
        print -u2 "This is the ONE passphrase derive_launch_keys.sh asked for -- the same one that"
        print -u2 "opens the sealed mnemonics.  Check it with:"
        print -u2 "    foundation_scripts/mnemonic.sh show ${MNEMONICS_DIR:-<mnemonics-dir>} qfi-pioneer1"
        print -u2 -n "  passphrase (hidden, will not echo): "
        read -s KRPASS; print -u2 ""
        [[ -n "$KRPASS" ]] || { print -u2 "empty passphrase"; exit 1 }
    fi
fi
qk() {
    if [[ -n "$KRPASS" ]]; then
        { print -r -- "$KRPASS"; print -r -- "$KRPASS" } \
            | "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    else
        "$QBIN" --home "$COORD_HOME" --keyring-backend "$BACKEND" "$@"
    fi
}
qq() { "$QBIN" --home "$NODE_HOME" "$@" --node "${QADENA_NODE:-tcp://localhost:26657}" }

CHAIN="${QADENA_CHAIN_ID:-$(qq status 2>/dev/null | jq -r '.node_info.network // empty')}"
[[ -n "$CHAIN" ]] || { print -u2 "cannot determine the chain-id; set QADENA_CHAIN_ID"; exit 1 }
ssh_args=(); [[ -n "$VIA_SSH" ]] && ssh_args=(--via-ssh "$VIA_SSH")

# multisig_sign.sh runs qadenad itself, in its own process, so it prompts on its own.  Feed it the
# same passphrase rather than making the operator type it once per member signature.
# EXPORTED, NOT PIPED.  multisig_sign.sh runs qadenad several times per invocation, so a pipe is
# drained by the first one and every later call gets EOF -- which the file backend counts as a
# failed attempt and locks the keyring after three.  It feeds each call itself from this variable.
# QADENA_CHAIN_ID TOO.  `broadcast` takes no --chain-id argument at its call site, but
# multisig_sign.sh requires one for every subcommand -- and its "missing --chain-id" message was
# itself unprintable, so the failure surfaced as `print: bad option: -h` after five good
# signatures.  Exporting it once covers every subcommand.
# QADENA_SIGNERS SIZES THE GAS.  WritePerByte charges per byte of the SIGNED tx, so the limit has
# to account for signatures that do not exist yet when the tx is generated.  Measured 2026-09-06:
# a 7-signature pubsec MsgSend used 302221 against a flat 300000 default and failed -- burning the
# fee, consuming the sequence, and making the NEXT ceremony die on "account sequence mismatch".
# `--gas auto` does not help: it simulates the UNSIGNED tx (signer_infos: []) and returned 186907,
# lower still.  The count is per-ceremony, set by each call below.
# EVERY EXIT IS EXPLAINED, INCLUDING THE ONES NOBODY WROTE A MESSAGE FOR.
#
# A ceremony is dozens of screens, and its failures are not all anticipated: the one measured on
# 2026-09-06 was a `set -e` death inside a command substitution, which by construction prints
# nothing at all -- the run ended between "signing as pubsec-m7" and the shell prompt.  A trap is
# the only thing that catches THAT class, because no branch was ever reached.
#
# It also prints the TXLOG, which previously appeared only on the success path -- so a run that
# died mid-way took the record of what it had already sent with it, and those transactions are
# real money that is NOT undone by the failure.
_LAST_STEP="starting up"
step() { _LAST_STEP="$1" }

_on_exit() {
    local rc=$?
    (( rc == 0 )) && return 0
    print -u2 ""
    print -u2 "==========================================================="
    print -u2 "FAILED during: $_LAST_STEP   (exit $rc)"
    print -u2 "==========================================================="
    if (( ${#TXLOG} )); then
        print -u2 "  transactions this run already sent -- these are NOT undone:"
        for t in "${TXLOG[@]}"; do print -u2 "    $t"; done
    else
        print -u2 "  no transaction was broadcast."
    fi
    case "${_LAST_CODE:-}" in
        11)   print -u2 ""
              print -u2 "  code 11 is OUT OF GAS.  The tx landed, burned its fee and CONSUMED THE"
              print -u2 "  SEQUENCE -- so a re-run may next fail with 'account sequence mismatch'."
              print -u2 "  Raise the limit and run again:   QADENA_GAS=600000 $ME ..." ;;
        1159) print -u2 ""
              print -u2 "  code 1159 is the AML gate: the SENDER is not on the bank-send whitelist."
              print -u2 "  A launch genesis whitelists only what launch-config.yml lists." ;;
        32)   print -u2 ""
              print -u2 "  code 32 is a SEQUENCE MISMATCH -- an earlier tx from this bucket landed"
              print -u2 "  (possibly having FAILED) and took the sequence.  Look before re-running:"
              print -u2 "  the shares were signed for the old number and cannot be reused." ;;
    esac
    print -u2 ""
    print -u2 "  look at the state before deciding anything:"
    print -u2 "      foundation_scripts/query_accounts.sh --coord-home $COORD_HOME --sponsors"
    print -u2 "  the ceremony's files are kept:  ${WORKDIR:-<none>}"
    return $rc
}
trap _on_exit EXIT

msig() { QADENA_KEYRING_PASS="$KRPASS" QADENA_CHAIN_ID="$CHAIN" QADENA_SIGNERS="${_SIGNERS:-3}" "$MSIG" "$@" }

# _SIGNERS is set to the member count of whichever bucket is signing, before each ceremony.
_count_members() { print -r -- "${#${(s:,:)1}}" }

# RETURNS NON-ZERO WHEN THERE IS NO SUCH KEY.  The obvious one-liner pipes into `tr`, and a
# pipeline's status is the LAST command's -- so it returned 0 for a missing key and every
# `addr_of X || fail` guard in this script silently never fired.
addr_of() {
    local a
    a=$(qk keys show "$1" -a 2>/dev/null | tr -d '\r')
    [[ -n "$a" ]] || return 1
    print -r -- "$a"
}

# ASK FOR THE MEMBERS RATHER THAN GUESS.  A bucket's member key names are a local convention
# (pubsec-m1..m5 here, but not necessarily elsewhere), and signing with the wrong subset produces
# a combine that fails only at the end.
ask_members() {
    local bucket="$1" have="$2" thr
    if [[ -n "$have" ]]; then print -- "$have"; return 0; fi
    thr=$(qk keys show "$bucket" --output json 2>/dev/null \
            | jq -r '.threshold // empty' 2>/dev/null)
    print -u2 ""
    print -u2 "Which members of '$bucket' will sign?${thr:+  (threshold $thr)}"
    print -u2 "  comma-separated key names in this keyring, e.g. ${bucket}-m1,${bucket}-m2,${bucket}-m3"
    print -u2 -n "  members: "
    local reply; read reply
    [[ -n "$reply" ]] || { print -u2 "no members given"; exit 1 }
    print -- "$reply"
}

# ONE CEREMONY: build (already done by the caller) -> sign per member -> combine -> broadcast.
run_ceremony() {
    local label="$1" unsigned="$2" bucket="$3" members="$4" so="${5:-0}"
    local -a mem; mem=(${(s:,:)members})
    local _SIGNERS=${#mem}          # gas sizing for every msig call in this ceremony
    local -a shares; shares=()
    local i=1 m sig
    local -a soff; soff=(); (( so > 0 )) && soff=(--sequence-offset "$so")

    if (( PRINT_ONLY )); then
        print ""
        print "# $label -- run these where the members are:"
        for m in $mem; do
            print "  scripts/multisig_sign.sh sign --tx $unsigned --multisig $bucket --from $m \\"
            print "        --chain-id $CHAIN${so:+ --sequence-offset $so} --out ${unsigned:r}.s${i}.json"
            i=$(( i + 1 ))
        done
        print "  scripts/multisig_sign.sh combine --tx $unsigned --multisig $bucket \\"
        print "        --chain-id $CHAIN --out ${unsigned:r}.signed.json ${unsigned:r}.s*.json"
        print "  scripts/multisig_sign.sh broadcast --tx ${unsigned:r}.signed.json"
        return 0
    fi

    for m in $mem; do
        sig="${unsigned:r}.s${i}.json"
        print "    signing as $m"
        msig sign --tx "$unsigned" --multisig "$bucket" --from "$m" \
                --chain-id "$CHAIN" "${soff[@]}" "${ssh_args[@]}" --out "$sig" > /dev/null \
            || { print -u2 "  FAILED to sign as $m"; exit 1 }
        shares+=("$sig"); i=$(( i + 1 ))
    done
    msig combine --tx "$unsigned" --multisig "$bucket" --chain-id "$CHAIN" \
            "${ssh_args[@]}" --out "${unsigned:r}.signed.json" "${shares[@]}" > /dev/null \
        || { print -u2 "  FAILED to combine -- too few shares for the threshold?"; exit 1 }
    # THREE OUTCOMES FROM broadcast, AND THEY NEED DIFFERENT ANSWERS.
    #   0  executed, code 0
    #   1  definitively failed -- rejected before inclusion, or executed and failed
    #   2  UNKNOWN -- accepted but not yet in a block
    # Treating 2 as failure is what makes an operator re-send a transfer that is about to land,
    # and money out of a sponsor account cannot be recovered without a governance proposal.
    # CAPTURED, NOT JUST PRINTED.  The hash is the only thing that lets anyone answer "did it
    # land?" after the fact, and it scrolls away.
    local _out rc _h
    # `x=$(cmd)` IS FATAL UNDER set -e WHEN cmd FAILS -- and this captured stderr too, so the
    # diagnosis went into a variable the script died before printing.  Measured 2026-09-06: a
    # funding tx failed with "EXECUTED AND FAILED, code 11" and the operator saw NOTHING between
    # the last signature and the shell prompt.  The `|| rc=$?` form puts the substitution in a
    # list, which set -e does not act on, so rc survives and $_out gets printed.
    rc=0
    _out=$(msig broadcast --tx "${unsigned:r}.signed.json" "${ssh_args[@]}" 2>&1) || rc=$?
    print -r -- "$_out"
    _h=$(print -r -- "$_out" | grep -oE '\b[0-9A-F]{64}\b' | head -1)
    TXLOG+=("${_h:-<no-hash>}  rc=$rc  $label")
    case $rc in
        0) print "    $label: landed, code 0" ;;
        2) print -u2 ""
           print -u2 "  $label: NOT CONFIRMED -- accepted, but not in a block yet."
           print -u2 "  DO NOT re-run until you have looked: it may have landed a second later."
           print -u2 "    foundation_scripts/query_accounts.sh --coord-home $COORD_HOME \\"
           print -u2 "        --keyring-backend $BACKEND --sponsors"
           exit 2 ;;
        *) # Keep the code the chain reported so _on_exit can say what it MEANS.
           _LAST_CODE=$(print -r -- "$_out" | grep -oE 'code [0-9]+' | tail -1 | tr -dc '0-9')
           print -u2 "  $label: FAILED (see above)"; exit 1 ;;
    esac
}

# ---------------------------------------------------------------------------------------------
# HOW MUCH STAKE AN EXPEDITED PROPOSAL NEEDS.
#
# Voting power follows BONDED stake and is credited to the DELEGATOR.  An expedited proposal needs
# expedited_threshold (0.667) of the votes cast, on top of quorum -- so if the foundation is the
# only voter, its bonded stake must exceed twice everyone else's:  F/(F+O) > 2/3  <=>  F > 2O.
#
# Computed rather than hardcoded because it depends on what the other validators have bonded,
# which changes every time a node joins.  A 20% margin absorbs a joiner landing mid-ceremony.
expedited_stake_needed() {
    local bonded self
    bonded=$(qq query staking pool --output json 2>/dev/null \
               | jq -r '.bonded_tokens // .pool.bonded_tokens // empty')
    [[ -n "$bonded" ]] || { print -u2 "cannot read the staking pool"; return 1 }
    self=$(qq query staking delegations "$(addr_of "$STAKE_BUCKET")" --output json 2>/dev/null \
             | jq -r '.delegation_responses[]?.balance.amount // empty' | python3 -c "import sys; print(sum(int(x) for x in sys.stdin.read().split() or ['0']))")
    : ${self:=0}
    # THE ARITHMETIC IS DONE IN PYTHON, NOT IN THE SHELL, AND THAT IS NOT FUSSINESS.
    # These are aqdn: 504M QDN is 5.04e26, and zsh truncates integers after 20 digits.
    # `2 * other * 12` on real bonded stake evaluates NEGATIVE (measured), which would either
    # skip the delegation entirely or delegate a nonsense amount.  HARD RULE 3: integer
    # arithmetic only, Python int, no floats anywhere near an amount.
    python3 - "$bonded" "$self" <<'PY'
import sys
bonded, self_ = int(sys.argv[1]), int(sys.argv[2])
other = max(0, bonded - self_)
AQDN = 10**18
# Expedited needs > 2/3 of the votes cast.  If the foundation is the only voter:
#     self/(self+other) > 2/3   <=>   self > 2*other
# 20% margin absorbs a validator joining mid-ceremony.  Ceiling division so the margin is
# never rounded away.
target = (2 * other * 12) // 10
need_a = target - self_
print(0 if need_a <= 0 else -(-need_a // AQDN))
PY
}

largest_validator() {
    qq query staking validators --output json 2>/dev/null \
      | jq -r '[.validators[] | select(.status=="BOND_STATUS_BONDED")]
               | sort_by(.tokens|tonumber) | last | .operator_address // empty'
}

case "$STAGE" in
prepare)
    print "==========================================================="
    print "FOUNDATION -> ${(U)DEPLOY_NAME} sponsorship, PREPARE (before step_1)"
    print "==========================================================="
    print "  chain        : $CHAIN"
    print "  deployment   : $DEPLOY_NAME"
    # The bucket's CSV row, resolved rather than asserted -- this line claimed "10 Public Sector
    # Programs" for whatever --fund-bucket happened to be, which is wrong for every adoption-funded
    # deployment and is the one line an operator reads to confirm they are spending the right money.
    case "$FUND_BUCKET" in
        pubsec)     _fb_desc="allocations.csv 10 Public Sector Programs, 5of7" ;;
        adoption)   _fb_desc="allocations.csv 01 Adoption Programs, 3of5" ;;
        grants)     _fb_desc="allocations.csv 04 Builder & Partner Grants" ;;
        foundation) _fb_desc="allocations.csv 03 Foundation Treasury" ;;
        *)          _fb_desc="allocations.csv bucket not recognised by this script" ;;
    esac
    print "  fund bucket  : $FUND_BUCKET     ($_fb_desc)"
    print "  stake bucket : $STAKE_BUCKET  (allocations.csv 03 Foundation Treasury)"
    print "  keyring      : $COORD_HOME  (backend $BACKEND)"
    print "  workdir      : $WORKDIR"

    # SAY IT OUT LOUD WHEN THE BUCKET IS A GUESS.  allocations.csv is human-owned (never edited by
    # tooling) and it earmarks bucket 10 for "SEC PH VERITAS 60M; future MOUs" -- it does not name
    # ekycph or enf.  Defaulting them to pubsec is a placeholder so the tooling runs, NOT a decision
    # that they are public-sector programmes; bucket 04 Builder & Partner Grants may well be right.
    # This spends real tokens out of a real allocation, so the operator is told before, not after.
    if (( ${DEPLOY_FUND_BUCKET_ASSUMED:-0} )) && [[ "$FUND_BUCKET" == "$DEPLOY_FUND_BUCKET" ]]; then
        print ""
        print "  !! FUND BUCKET NOT EARMARKED FOR '$DEPLOY_NAME'"
        print "     allocations.csv bucket 10 names SEC PH VERITAS; it does not name $DEPLOY_NAME."
        print "     '$FUND_BUCKET' is this profile's placeholder, not a decision.  Confirm which"
        print "     allocation funds $DEPLOY_NAME and pass --fund-bucket, or pin it once in"
        print "     ${QADENA_DEPLOYMENT_DIR:-$HOME/launch/deployments}/$DEPLOY_NAME.env"
        print "     (DEPLOY_FUND_BUCKET=... ; DEPLOY_FUND_BUCKET_ASSUMED=0) to stop this notice."
        print ""
    fi

    for b in "$FUND_BUCKET" "$STAKE_BUCKET"; do
        addr_of "$b" > /dev/null || {
            print -u2 "no key '$b' in the keyring at $COORD_HOME (backend $BACKEND)"
            print -u2 "  The bucket multisigs live in the COORDINATOR keyring, not the node's."
            print -u2 "  Pass --coord-home <dir> -- the same --home you gave derive_launch_keys.sh."
            exit 1 }
    done

    # ---- 1. the two sponsor accounts ------------------------------------------------------
    # ADDRESSES, NOT KEYS, ARE WHAT THE DEPLOYMENT NEEDS.  These accounts sign nothing here; they
    # exist to be the grantee of fee grants and the payer of record.  If they already exist in
    # this keyring they are reused -- re-minting would change the address SSM already points at.
    print ""
    step "creating the two sponsor accounts"
    print -r -- "--- 1. sponsor accounts"
    for n in "$APPSVR" "$USERS"; do
        if addr_of "$n" > /dev/null 2>&1; then
            print "  $n exists: $(addr_of $n)"
        else
            # A KEY WHOSE MNEMONIC WAS NOT CAPTURED IS AN UNRECOVERABLE ACCOUNT.  `keys add` prints
            # the mnemonic ONCE, to stdout, and nothing else ever will.  An earlier version of this
            # script redirected that to /dev/null and then told the operator to record it -- which
            # would have created two funded foundation accounts nobody could ever sign for.
            [[ -n "$MNEMONICS_DIR" ]] || {
                print -u2 ""
                print -u2 "  $n does not exist, and --mnemonics-dir was not given."
                print -u2 "  Refusing to mint a key whose mnemonic has nowhere safe to go."
                print -u2 "  Either pass --mnemonics-dir <dir>, or create the account first with"
                print -u2 "  foundation_scripts/derive_launch_keys.sh and re-run."
                exit 1 }
            mkdir -p "$MNEMONICS_DIR"; chmod 700 "$MNEMONICS_DIR"
            mf="$MNEMONICS_DIR/$n.mnemonic.enc"
            [[ -e "$mf" ]] && { print -u2 "  $mf exists but the key does not -- refusing to overwrite"; exit 1 }
            # ONE PASSPHRASE, NOT TWO.  derive_launch_keys.sh uses a single string for the
            # keyring AND for sealing every mnemonic, so mnemonic.sh show, init.sh
            # --pioneer-mnemonic-enc and the whole mnemonics directory all open with the same
            # one.  Prompting for a second here would produce two files in that directory that
            # need different passphrases -- discoverable only on the day one is needed.
            if [[ -z "$SEALPASS" ]]; then
                if [[ -n "$KRPASS" ]]; then
                    SEALPASS="$KRPASS"
                    print "  sealing with the coordinator keyring passphrase (one passphrase, as"
                    print "  derive_launch_keys.sh set it)"
                else
                    print -u2 -n "  Passphrase to seal new mnemonics (hidden, will not echo): "
                    read -s SEALPASS; print -u2 ""
                    print -u2 -n "  confirm: "
                    read -s _p2; print -u2 ""
                    [[ "$SEALPASS" == "$_p2" ]] || { print -u2 "  passphrases do not match"; exit 1 }
                    unset _p2
                fi
            fi
            print "  creating $n"
            # eth_secp256k1 to match every other account on this chain: a standard secp256k1 key
            # derives a DIFFERENT address and the mismatch only shows up as a failed grant.
            _out=$(qk keys add "$n" --algo eth_secp256k1 --output json 2>&1) \
                || { print -u2 "  could not create $n: $(print -r -- "$_out" | tail -1)"; exit 1 }
            _mn=$(print -r -- "$_out" | grep '^{' | tail -1 | jq -r '.mnemonic // empty')
            _wc=$(print -r -- "$_mn" | wc -w | tr -d ' ')
            [[ "$_wc" == "12" || "$_wc" == "24" ]] \
                || { print -u2 "  keys add returned a $_wc-word mnemonic -- refusing to proceed"; exit 1 }
            print -r -- "$_mn" | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
                    -out "$mf" -pass fd:3 3< <(print -r -- "$SEALPASS") 2>/dev/null \
                || { print -u2 "  FAILED to seal $mf"; rm -f "$mf"; exit 1 }
            chmod 600 "$mf"
            # VERIFY BEFORE TRUSTING IT.  A cipher that wrote garbage and one that worked look
            # identical until the day the mnemonic is needed.
            _back=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$mf" \
                      -pass fd:3 3< <(print -r -- "$SEALPASS") 2>/dev/null)
            [[ "$_back" == "$_mn" ]] \
                || { print -u2 "  ROUND-TRIP FAILED for $mf -- the key exists but is NOT backed up"; rm -f "$mf"; exit 1 }
            unset _mn _back _out
            print "  $n created: $(addr_of $n)"
            print "  mnemonic sealed -> $mf   (read: foundation_scripts/mnemonic.sh show $MNEMONICS_DIR $n)"
        fi
    done

    # ---- 2. fund them from pubsec ---------------------------------------------------------
    print ""
    step "funding the sponsors from $FUND_BUCKET"
    print -r -- "--- 2. funding ${AMOUNT}qdn each from $FUND_BUCKET"
    FUND_MEMBERS=$(ask_members "$FUND_BUCKET" "$FUND_MEMBERS")
    # ALREADY-FUNDED ACCOUNTS ARE SKIPPED, AND THAT IS WHAT MAKES THIS RESUMABLE.
    #
    # A ceremony is many steps and any of them can fail late -- a broadcast that reports failure
    # for a transaction that landed (observed 2026-09-05: tx 64943BA6 at height 4027, code 0,
    # reported as "FAILED to broadcast") leaves the operator with no safe move.  Re-running would
    # send a SECOND transfer, and getting it back needs a governance proposal, because a sponsor
    # account is not a wallet and is not on the AML whitelist (code 1159).
    #
    # So check the chain, not the script's own idea of what it did.
    funded_enough() {
        local addr="$1" want_qdn="$2" have
        have=$(qq query bank balances "$addr" --output json 2>/dev/null \
                 | jq -r '(.balances[]? | select(.denom=="aqdn") | .amount) // "0"')
        : ${have:=0}
        python3 -c "import sys; print('yes' if int(sys.argv[1]) >= int(sys.argv[2])*10**18 else 'no')" \
                "$have" "$want_qdn" 2>/dev/null
    }
    for acct in "$APPSVR" "$USERS"; do
        _a=$(addr_of "$acct")
        if [[ "$(funded_enough "$_a" "$AMOUNT")" == "yes" ]]; then
            _bal=$(qq query bank balances "$_a" --output json 2>/dev/null \
                     | jq -r '(.balances[]? | select(.denom=="aqdn") | .amount) // "0"')
            print "  $acct already holds $(python3 -c "print(f'{int($_bal)//10**18:,}')") qdn -- skipping"
            continue
        fi
        u="$WORKDIR/fund-$acct.json"
        # The GAS is fixed HERE, at build time, and must already cover signatures that do not
        # exist yet -- see the note on msig().  pubsec is 5-of-7 on the fleet.
        _SIGNERS=$(_count_members "$FUND_MEMBERS")
        msig build-send --from "$FUND_BUCKET" --to "$(addr_of $acct)" \
                --amount "${AMOUNT}qdn" --chain-id "$CHAIN" "${ssh_args[@]}" --out "$u" > /dev/null \
            || { print -u2 "  build failed for $acct"; exit 1 }
        print "  $acct <- ${AMOUNT}qdn"
        # THE SECOND TX OF A PAIR MUST BE SIGNED ONE SEQUENCE AHEAD.  Both are signed in this
        # sitting, from the same account, so without the offset the second is invalid the moment
        # the first lands -- and every share of it must agree on the number.
        # NO SEQUENCE OFFSET, AND THE REASON IS THE WAIT.
        #
        # --sequence-offset exists for the case where several transactions from one account are
        # signed BEFORE any of them is broadcast: they would all carry the same sequence and only
        # the first could land.  That is not this.  run_ceremony broadcasts and then WAITS for
        # inclusion, so by the time the next transaction is signed the chain has already advanced
        # and `sign` reads the correct next sequence for itself.
        #
        # Adding an offset here double-counts it: the shares get sequence+1 when the account is
        # already at sequence, and `combine` fails with "unable to verify single signer signature"
        # -- after every member has signed.  Measured 2026-09-05.
        run_ceremony "fund $acct" "$u" "$FUND_BUCKET" "$FUND_MEMBERS"
    done

    # ---- 3. stake for expedited voting power ----------------------------------------------
    print ""
    step "staking from $STAKE_BUCKET for expedited voting"
    print -r -- "--- 3. stake for EXPEDITED voting power"
    [[ -n "$VALIDATOR" ]] || VALIDATOR=$(largest_validator)
    [[ -n "$VALIDATOR" ]] || { print -u2 "no bonded validator found; pass --validator"; exit 1 }
    if [[ -z "$STAKE" ]]; then
        STAKE=$(expedited_stake_needed) || exit 1
        print "  computed ${STAKE}qdn -- enough for >2/3 of bonded stake (expedited_threshold 0.667)"
        print "  plus a 20% margin.  Override with --stake."
    fi
    if (( STAKE <= 0 )); then
        print "  already holds enough bonded stake; nothing to delegate"
    else
        u="$WORKDIR/stake.json"
        _SIGNERS=$(_count_members "$MEMBERS")
        msig build-delegate --from "$STAKE_BUCKET" --validator "$VALIDATOR" \
                --amount "${STAKE}qdn" --chain-id "$CHAIN" "${ssh_args[@]}" --out "$u" > /dev/null \
            || { print -u2 "  build failed"; exit 1 }
        print "  ${STAKE}qdn -> $VALIDATOR"
        MEMBERS=$(ask_members "$STAKE_BUCKET" "$MEMBERS")
        run_ceremony "stake" "$u" "$STAKE_BUCKET" "$MEMBERS"
    fi

    # ---- 4. VERIFY WHAT ACTUALLY LANDED ---------------------------------------------------
    #
    # DO NOT TRUST THIS SCRIPT'S OWN ACCOUNT OF WHAT IT DID.  Every step above reports success or
    # failure from a broadcast, and a broadcast can be wrong in BOTH directions: on 2026-09-05 it
    # printed "FAILED to broadcast" for tx 64943BA6, which was in block 4027 with code 0, and the
    # run stopped with one account funded and the operator believing none were.  The opposite --
    # a reported success that never landed -- is equally possible and worse, because nothing
    # prompts anyone to look.
    #
    # So finish by asking the CHAIN what is true, and exit non-zero if it disagrees with intent.
    print ""
    step "verifying against the chain"
    print -r -- "--- 4. verifying against the chain"
    _fail=0
    for acct in "$APPSVR" "$USERS"; do
        _a=$(addr_of "$acct")
        _b=$(qq query bank balances "$_a" --output json 2>/dev/null \
               | jq -r '(.balances[]? | select(.denom=="aqdn") | .amount) // "0"')
        : ${_b:=0}
        if [[ "$(funded_enough "$_a" "$AMOUNT")" == "yes" ]]; then
            print "  OK    $acct holds $(python3 -c "print(f'{int($_b)//10**18:,}')") qdn"
        else
            print -u2 "  FAIL  $acct holds $(python3 -c "print(f'{int($_b)//10**18:,}')") qdn, wanted $AMOUNT"
            _fail=1
        fi
    done
    _sb=$(qq query staking delegations "$(addr_of "$STAKE_BUCKET")" --output json 2>/dev/null \
            | jq -r '.delegation_responses[]?.balance.amount // empty' | python3 -c "import sys; print(sum(int(x) for x in sys.stdin.read().split() or ['0']))")
    : ${_sb:=0}
    _need=$(expedited_stake_needed 2>/dev/null || print 0)
    if (( _need > 0 )); then
        print -u2 "  FAIL  $STAKE_BUCKET is bonded $(python3 -c "print(f'{int($_sb)//10**18:,}')") qdn --"
        print -u2 "        still ${_need} qdn short of carrying an expedited vote alone"
        _fail=1
    else
        print "  OK    $STAKE_BUCKET bonded $(python3 -c "print(f'{int($_sb)//10**18:,}')") qdn -- enough for an expedited vote"
    fi
    if (( _fail )); then
        print -u2 ""
        print -u2 "PREPARE INCOMPLETE -- the chain does not match what was intended."
        print -u2 "Re-run this exact command: funded accounts are skipped, so it resumes rather"
        print -u2 "than double-funding.  Inspect first with:"
        print -u2 "    foundation_scripts/query_accounts.sh --coord-home $COORD_HOME \\"
        print -u2 "        --keyring-backend $BACKEND --sponsors"
        exit 1
    fi

    if (( ${#TXLOG} )); then
        print ""
        print -r -- "--- transactions this run sent"
        for t in "${TXLOG[@]}"; do print "  $t"; done
        print "  re-check any of them:  qadenad query tx <hash>"
    fi

    print ""
    # THE FOUNDATION'S OWN RECORD, the counterpart to SEC's variables.json.  Until now this side
    # persisted nothing but a keyring: the two sponsor addresses existed only in this printout, so
    # every later step made an operator retype them from scrollback -- and retyping a stale pair
    # from an earlier deployment reads as a green run against the wrong accounts.  Written beside
    # the keyring that holds the keys, so the record travels with them.
    _STATE="$COORD_HOME/$DEPLOY_STATE_FILE"
    # THE NODE IS PART OF THE RECORD.  Without it, a later --coord-home run defaults to
    # localhost, and every check fails against a chain that is merely absent -- which reads as a
    # broken deployment rather than a wrong endpoint (measured 2026-09-06).
    jq -n --arg a "$(addr_of $APPSVR)" --arg u "$(addr_of $USERS)" \
          --arg an "$APPSVR" --arg un "$USERS" --arg c "$CHAIN" --arg n "${QADENA_NODE:-}" \
        '{appsvr:$a, users:$u, appsvr_name:$an, users_name:$un, chain_id:$c, node:$n}' > "$_STATE" \
        && chmod 600 "$_STATE" \
        && print -r -- "recorded the sponsor addresses in $_STATE"
    print ""
    print "==================================================================="
    print "PREPARE DONE -- both sponsors are funded and the stake is delegated."
    print ""
    print "1. SEND SEC THIS COMMAND.  The addresses ride as arguments, so it is"
    print "   paste-and-run; only --count is theirs to choose (wallets per user):"
    print ""
    print "     veritas_scripts/step_1.sh --count 30 \\"
    print "         --appsvr $(addr_of $APPSVR) \\"
    # A ${VAR:+...} expansion cannot span two print statements -- the closing brace lands on the
    # next line and the word `print` is emitted literally.  Branch instead.
    if [[ -n "${QADENA_NODE:-}" ]]; then
        print "         --users  $(addr_of $USERS) \\"
        print "         --node   $QADENA_NODE"
    else
        print "         --users  $(addr_of $USERS)"
    fi
    print ""
    print "   Use a small --count (3) to rehearse: it sizes the pre-grants (4*(n+1)),"
    print "   the sponsor pool and the per-wallet split, so a rehearsal is much faster."
    print ""
    print "2. SEC RETURNS a PRE-GRANT BLOCK -- their admin address plus every wallet"
    print "   address this deployment will ever create.  Save it to a file, then:"
    print ""
    print "     foundation_scripts/sec_veritas_after_step_1.sh --pregrant <that file> \\"
    print "         --coord-home $COORD_HOME${QADENA_NODE:+ --node $QADENA_NODE}"
    print ""
    print "   That one command does BOTH halves: it delegates the three authorities to"
    print "   SEC's admin, and pre-grants every wallet in the block -- before any of them"
    print "   exists, which is what keeps a foundation key off SEC's machine entirely."
    print ""
    print "   The admin address is NOT the sec-treasury address step_1 also prints: that"
    print "   belongs to the retired banksend model and nothing in this flow uses it."
    print ""
    print "Reference copy of the same facts:"
    print "  chain-id          $CHAIN"
    printf "  %-26s %s\n" "$APPSVR" "$(addr_of $APPSVR)"
    printf "  %-26s %s\n" "$USERS"  "$(addr_of $USERS)"
    print "  (also recorded in $COORD_HOME/$DEPLOY_STATE_FILE -- later steps read it"
    print "   from there, so you never need to retype these.)"
    print "==================================================================="
    ;;

approve)
    # DEPOSIT AND VOTE, ONE PROPOSAL AT A TIME.  Both come from the STAKE bucket: the deposit
    # needs liquid tokens and the vote needs bonded ones, and bucket 03 is the only one that has
    # both.  pubsec has stakes=no and could not carry the vote.
    [[ ${#PROPOSALS} -gt 0 ]] || { print -u2 -- "--stage approve needs at least one proposal id"; usage }
    print "==========================================================="
    print "FOUNDATION -> VERITAS sponsorship, APPROVE"
    print "==========================================================="
    print "  proposals: ${PROPOSALS[*]}"
    MEMBERS=$(ask_members "$STAKE_BUCKET" "$MEMBERS")

    # LOOK AT EACH PROPOSAL BEFORE PUTTING 10M QDN ON IT.
    #
    # The ids are typed by an operator from step_2's output -- nothing derives them -- so a
    # transposed digit deposits the foundation's money on somebody else's proposal and votes YES
    # on it.  Two checks, both cheap:
    #
    #   WHAT IT IS      MsgAddServiceProvider naming a SEC provider.  Anything else is refused,
    #                   because "deposit and vote yes" is not a safe default for an unknown
    #                   proposal.
    #   WHERE IT IS     already PASSED/REJECTED/FAILED means the work is done or moot; depositing
    #                   then is money spent for nothing.  Skipped, not failed -- re-running this
    #                   stage after a partial run is normal and must stay safe.
    _todo=()
    for pid in "${PROPOSALS[@]}"; do
        _pj=$(qq query gov proposal "$pid" --output json 2>/dev/null || true)
        if [[ -z "$_pj" ]]; then
            print -u2 "  proposal $pid: NOT FOUND on $CHAIN -- check the id step_2 printed"
            exit 1
        fi
        _pstatus=$(print -r -- "$_pj" | jq -r '.proposal.status // ""')
        _ptype=$(print -r -- "$_pj"   | jq -r '.proposal.messages[0].type // .proposal.messages[0]["@type"] // ""')
        _pnode=$(print -r -- "$_pj"   | jq -r '.proposal.messages[0].value.nodeID // ""')
        if [[ "$_ptype" != *MsgAddServiceProvider ]]; then
            print -u2 "  proposal $pid is NOT a service-provider proposal (it is ${_ptype:-unknown})."
            print -u2 "  Refusing: this stage deposits ${DEPOSIT_QDN:-10000000}qdn and votes YES."
            exit 1
        fi
        case "$_pstatus" in
            *DEPOSIT_PERIOD|*VOTING_PERIOD)
                print "  proposal $pid: $_pnode ($_pstatus) -- will deposit and vote"
                _todo+=("$pid") ;;
            *PASSED)
                print "  proposal $pid: $_pnode already PASSED -- skipping (nothing to do)" ;;
            *)
                print -u2 "  proposal $pid: $_pnode is $_pstatus -- cannot be helped by a vote"
                exit 1 ;;
        esac
    done
    if (( ${#_todo} == 0 )); then
        print ""
        print "Nothing to do -- every proposal given is already decided."
        exit 0
    fi
    PROPOSALS=("${_todo[@]}")

    for pid in "${PROPOSALS[@]}"; do
        for kind in deposit vote; do
            u="$WORKDIR/$kind-$pid.json"
            if [[ "$kind" == deposit ]]; then
                _SIGNERS=$(_count_members "$MEMBERS")
                step "depositing on proposal $pid"
                msig build-deposit --from "$STAKE_BUCKET" --proposal "$pid" \
                        --amount "10000000qdn" --chain-id "$CHAIN" "${ssh_args[@]}" --out "$u" > /dev/null || exit 1
            else
                _SIGNERS=$(_count_members "$MEMBERS")
                step "voting YES on proposal $pid"
                msig build-vote --from "$STAKE_BUCKET" --proposal "$pid" --vote yes \
                        --chain-id "$CHAIN" "${ssh_args[@]}" --out "$u" > /dev/null || exit 1
            fi
            print ""
            print "  proposal $pid: $kind  (sequence offset $n)"
            run_ceremony "$kind $pid" "$u" "$STAKE_BUCKET" "$MEMBERS"
        done
    done
    if (( ${#TXLOG} )); then
        print ""
        print -r -- "--- transactions this run sent"
        for t in "${TXLOG[@]}"; do print "  $t"; done
    fi

    print ""
    print "==================================================================="
    print "APPROVE DONE -- deposited and voted YES on ${#PROPOSALS[@]} proposal(s)."
    print ""
    print "1. WAIT for each to reach PASSED.  Each command blocks until it does:"
    for pid in "${PROPOSALS[@]}"; do
        print "     provider_scripts/query_service_provider_proposal.sh $pid --wait${QADENA_NODE:+ --node $QADENA_NODE}"
    done
    print ""
    print "   A vote is not a result: the provider is registered by the proposal EXECUTING,"
    print "   and step_3 creates wallets that need those providers to exist.  Started early,"
    print "   it fails partway through with wallets already on chain."
    print ""
    print "2. THEN TELL SEC TO RUN, exactly:"
    print ""
    print "     veritas_scripts/step_3.sh${QADENA_NODE:+ --node $QADENA_NODE}"
    print ""
    print "   No exports and no addresses: step_3 reads them from the run's own variables.json"
    print "   and verifies the delegation on chain before using it."
    print ""
    print "3. SEC returns a POOL BLOCK.  Save it to a file and finish with:"
    print ""
    print "     foundation_scripts/sec_veritas_after_step_3.sh --pool-addresses <that file> \\"
    print "         --coord-home $COORD_HOME${QADENA_NODE:+ --node $QADENA_NODE}"
    print ""
    print "4. VERIFY the whole deployment (read-only, no keyring, no passphrase):"
    print ""
    print "     foundation_scripts/sec_veritas_verify.sh --coord-home $COORD_HOME${QADENA_NODE:+ --node $QADENA_NODE}"
    print "==================================================================="
    ;;

*)  print -u2 "unknown --stage '$STAGE' (prepare | approve)"; usage ;;
esac
