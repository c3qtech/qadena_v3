#!/bin/zsh
#
# Move keys from an UNENCRYPTED `test` keyring into an encrypted `file` one, in place.
#
#   ./testscripts/migrate_keyring.sh --dir ~/sec-veritas/keyring
#
# WHY THIS EXISTS.  `test` is JWE-wrapped under a passphrase built into the SDK, so it opens with
# no prompt: read access to the directory is read access to every key.  On SEC's box those keys
# ARE the deployment -- secidentitysrvprv signs credential issuance as the identity provider, and
# sec-veritas-admin carries authz to issue fee grants as the foundation.  The steps now default to
# `file`, but changing a default does not move keys that already exist, and the chain already
# knows their addresses: they cannot simply be regenerated.
#
# THE ONLY MECHANISM THAT WORKS is `keys export` -> `keys import`.  There is no `import-hex` in
# this build, and copying the keyring files between backends does not work because the wrapping
# differs.  Export produces an ARMORED blob (argon2 + a passphrase this script generates fresh per
# run), import unwraps it into the target.
#
# NOTHING IS DELETED.  The source keyring is left exactly as it was, and the script says so at the
# end.  Removing it is a separate, deliberate act AFTER the deployment has been confirmed to work
# against the new one -- a half-migrated keyring that has already been deleted is unrecoverable,
# and the mnemonics are the only other copy.
#
# EVERY KEY IS VERIFIED BY ADDRESS.  An import that silently produced a different address would be
# the worst outcome here: the chain holds grants, wallets and provider registrations against the
# ORIGINAL addresses, so a mismatch means signing authority is gone for something already on
# chain.  Each key is compared before and after, and a single mismatch stops the run.
#
# MULTISIG KEYS CANNOT BE MIGRATED THIS WAY and are skipped with a note.  They hold no private
# material -- a multisig is derived from its members' pubkeys and a threshold -- so `keys export`
# has nothing to export.  Recreate them with `keys add --multisig` once the members are in the
# target keyring; the address is a pure function of those inputs and will come out identical.

set -e
set -u

SCRIPT_DIR="${0:A:h}"
_kb_caller="${QADENA_KEYRING_BACKEND:-}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1 || true
SCRIPT_DIR="${0:A:h}"

# THE BINARY, WHICH IS NOT ALWAYS AT $qadenabin YET.  buildscripts/init.sh calls this right after
# `ignite chain init`, and install.sh -- which puts qadenad in ~/qadena/bin -- runs 200 lines later.
# At that point the built binary is `qadena_v3d` on PATH, which init.sh itself uses a few lines on.
# --qadenad lets the caller say so; the default is for a normal, post-install run.
QBIN="${qadenabin:-$HOME/qadena/bin}/qadenad"
HOME_DIR="${QADENAHOME:-$HOME/qadena}"
DIR=""
FROM="test"
TO="file"
PASSFILE=""
ONLY=""
DRY=0
# Off by default: for a manual migration of a live deployment the source is the only other copy of
# every key, and the mnemonics may be sealed elsewhere or nowhere.  buildscripts/init.sh passes it,
# because there the home was created moments ago and nothing else holds those keys.
DELETE_SRC=0

usage() {
    print -r -- "Usage: migrate_keyring.sh --dir <keyring-dir> [options]"
    print -r -- ""
    print -r -- "  --dir <dir>        the keyring directory holding keyring-test (REQUIRED)"
    print -r -- "  --from <backend>   source backend (default test)"
    print -r -- "  --to <backend>     target backend (default file)"
    print -r -- "  --passfile <file>  first line is the TARGET keyring passphrase; prompted if omitted"
    print -r -- "  --qadenad <path>   the binary to use.  Default \$qadenabin/qadenad, which does not"
    print -r -- "                     exist yet during init.sh -- pass the built one there."
    print -r -- "  --only a,b,c       migrate just these keys (default: all in the source)"
    print -r -- "  --dry-run          list what would move, touch nothing"
    print -r -- "  --delete-source    remove keyring-<from> after EVERY key has migrated and had"
    print -r -- "                     its address verified.  Off by default."
    print -r -- ""
    print -r -- "  Nothing is deleted.  Every key is verified by address after import;"
    print -r -- "  one mismatch stops the run.  Multisig keys are skipped -- recreate"
    print -r -- "  them with 'keys add --multisig' once their members are migrated."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)      DIR="$2"; shift 2 ;;
        --from)     FROM="$2"; shift 2 ;;
        --to)       TO="$2"; shift 2 ;;
        --passfile) PASSFILE="$2"; shift 2 ;;
        --qadenad)  QBIN="$2"; shift 2 ;;
        --only)     ONLY="$2"; shift 2 ;;
        --dry-run)  DRY=1; shift ;;
        --delete-source) DELETE_SRC=1; shift ;;
        --help|-h)  usage; exit 0 ;;
        *) print -u2 -- "unknown option: $1"; usage >&2; exit 1 ;;
    esac
done

[[ -n "$DIR" ]] || { usage >&2; exit 1 }
[[ -d "$DIR" ]] || { print -u2 "no such directory: $DIR"; exit 1 }
[[ -d "$DIR/keyring-$FROM" ]] || { print -u2 "no keyring-$FROM in $DIR -- nothing to migrate"; exit 1 }

src() { "$QBIN" --home "$HOME_DIR" --keyring-dir "$DIR" --keyring-backend "$FROM" "$@" }
dst() { "$QBIN" --home "$HOME_DIR" --keyring-dir "$DIR" --keyring-backend "$TO" "$@" }

# THE ARMOR PASSPHRASE IS EPHEMERAL AND PER-RUN.  It protects the blob only between the export and
# the import a moment later; it is never stored and never reused.  A fixed one would sit in shell
# history and in this file, which is worse than useless for something wrapping every provider key.
ARMOR=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
[[ ${#ARMOR} -ge 8 ]] || { print -u2 "could not generate an armor passphrase"; exit 1 }

# The armored blobs land in a 700 directory that is removed on ANY exit, including a failure --
# they are unwrapped private keys and must not outlive the run.
WORK=$(mktemp -d)
chmod 700 "$WORK"
cleanup() { rm -rf "$WORK" }
trap cleanup EXIT INT TERM

print -r -- "migrating $DIR: keyring-$FROM -> keyring-$TO"

# The name list comes from the SOURCE, so this cannot miss a key someone added by hand.
# THE BINARY MUST EXIST BEFORE ITS OUTPUT MEANS ANYTHING.  Without this check a missing qadenad
# made `keys list` fail, 2>/dev/null swallowed "No such file or directory", and the empty result was
# reported as "no keys found in keyring-test" -- against a keyring that was full.  The message named
# the wrong thing entirely and sent the search to the keyring instead of the PATH.
[[ -x "$QBIN" ]] || {
    print -u2 "no qadenad at $QBIN"
    print -u2 "  Nothing can be read from the keyring without it.  Pass --qadenad <path> if the"
    print -u2 "  binary is not installed yet -- during init.sh the built one is \`which qadena_v3d\`."
    exit 1
}
_list_err=$(src keys list --output json 2>&1 >/dev/null)
_names=$(src keys list --output json 2>/dev/null | jq -r '.[].name' 2>/dev/null || true)
[[ -n "$_names" ]] || {
    print -u2 "no keys found in keyring-$FROM"
    # SHOW WHAT qadenad ACTUALLY SAID.  An empty list and a failed command are indistinguishable
    # from the caller's side, and they have completely different causes.
    [[ -n "$_list_err" ]] && print -u2 "  qadenad said: $(print -r -- "$_list_err" | tail -2)"
    print -u2 "  looked in: $DIR/keyring-$FROM  (using $QBIN)"
    ls "$DIR/keyring-$FROM"/*.info > /dev/null 2>&1 \
        && print -u2 "  NOTE: that directory DOES contain .info files, so this is a read failure,"
    exit 1
}
if [[ -n "$ONLY" ]]; then
    _want=(${(s:,:)ONLY})
    _filtered=""
    for _n in ${(f)_names}; do
        for _w in "${_want[@]}"; do [[ "$_n" == "$_w" ]] && _filtered="$_filtered$_n"$'\n' ; done
    done
    _names="${_filtered%$'\n'}"
    [[ -n "$_names" ]] || { print -u2 "none of --only matched a key in keyring-$FROM"; exit 1 }
fi
_total=$(print -r -- "$_names" | grep -c . || true)
print -r -- "  $_total key(s) to consider"

if (( DRY )); then
    for _n in ${(f)_names}; do
        _t=$(src keys show "$_n" --output json 2>/dev/null | jq -r '.type // "?"')
        print -r -- "    $_n  ($_t)"
    done
    print -r -- ""
    print -r -- "DRY RUN -- nothing was written."
    exit 0
fi

# The target passphrase is asked ONCE and reused for every import.  qadenad prompts twice when the
# keyring does not yet exist and once thereafter, which is why the feed below is length-aware.
if [[ -n "$PASSFILE" ]]; then
    [[ -r "$PASSFILE" ]] || { print -u2 "cannot read $PASSFILE"; exit 1 }
    KRPASS=$(head -1 "$PASSFILE")
else
    print -u2 -n "  passphrase for the NEW keyring-$TO (min 8 chars, will not echo): "
    read -s KRPASS; print -u2 ""
fi
[[ ${#KRPASS} -ge 8 ]] || { print -u2 "passphrase must be at least 8 characters"; exit 1 }

_new_keyring=1
[[ -d "$DIR/keyring-$TO" ]] && [[ -n "$(ls -A "$DIR/keyring-$TO" 2>/dev/null)" ]] && _new_keyring=0

_ok=0 _skipped=0 _msig=0 _failed=0
for _n in ${(f)_names}; do
    [[ -n "$_n" ]] || continue

    _type=$(src keys show "$_n" --output json 2>/dev/null | jq -r '.type // ""')
    _addr=$(src keys show "$_n" -a 2>/dev/null | tr -d '\r')
    if [[ -z "$_addr" ]]; then
        print -r -- "  SKIP  $_n -- cannot read its address in keyring-$FROM"
        _failed=$(( _failed + 1 )); continue
    fi

    # A multisig has no private key to export; see the header.
    if [[ "$_type" == "multi" ]]; then
        print -r -- "  msig  $_n -- multisig, recreate with 'keys add --multisig' after its members"
        _msig=$(( _msig + 1 )); continue
    fi

    # IDEMPOTENT, AND VERIFIED IDEMPOTENT.  A key already in the target is fine only if it is the
    # SAME key: a name collision with a different address would otherwise be reported as success.
    _existing=$({ print -r -- "$KRPASS" } | dst keys show "$_n" -a 2>/dev/null | tr -d '\r' || true)
    if [[ -n "$_existing" ]]; then
        if [[ "$_existing" == "$_addr" ]]; then
            _skipped=$(( _skipped + 1 )); continue
        fi
        print -u2 -- "  FAIL  $_n already exists in keyring-$TO with a DIFFERENT address"
        print -u2 -- "        keyring-$FROM: $_addr"
        print -u2 -- "        keyring-$TO:   $_existing"
        print -u2 -- "        Refusing to overwrite.  Rename or remove one before re-running."
        exit 1
    fi

    _asc="$WORK/$_n.asc"
    if ! { print -r -- "$ARMOR"; print -r -- "$ARMOR" } | src keys export "$_n" > "$_asc" 2>/dev/null; then
        print -u2 -- "  FAIL  $_n -- export failed"
        _failed=$(( _failed + 1 )); continue
    fi
    grep -q 'END TENDERMINT PRIVATE KEY' "$_asc" 2>/dev/null || {
        print -u2 -- "  FAIL  $_n -- exported blob is truncated, not importing it"
        _failed=$(( _failed + 1 )); continue
    }

    if (( _new_keyring )); then
        _feed=("$ARMOR" "$KRPASS" "$KRPASS")
    else
        _feed=("$ARMOR" "$KRPASS")
    fi
    if ! { for _l in "${_feed[@]}"; do print -r -- "$_l"; done } \
            | dst keys import "$_n" "$_asc" > /dev/null 2>&1; then
        print -u2 -- "  FAIL  $_n -- import failed"
        _failed=$(( _failed + 1 )); continue
    fi
    _new_keyring=0
    rm -f "$_asc"

    # THE CHECK THAT MATTERS.  The chain holds grants and registrations against the ORIGINAL
    # address; an import that produced a different one has silently lost signing authority for
    # something already deployed, so stop rather than continue and report a total at the end.
    _after=$({ print -r -- "$KRPASS" } | dst keys show "$_n" -a 2>/dev/null | tr -d '\r')
    if [[ "$_after" != "$_addr" ]]; then
        print -u2 -- "  FAIL  $_n ADDRESS CHANGED -- $_addr -> ${_after:-<none>}"
        print -u2 -- "        Stopping.  keyring-$FROM is untouched; nothing on chain is affected,"
        print -u2 -- "        but do not delete it and do not trust keyring-$TO for this key."
        exit 1
    fi
    print -r -- "  ok    $_n  $_addr"
    _ok=$(( _ok + 1 ))
done

print -r -- ""
print -r -- "  $_ok migrated, $_skipped already present, $_msig multisig (skipped), $_failed failed"
print -r -- ""
if (( _failed > 0 )); then
    print -u2 -- "SOME KEYS DID NOT MOVE.  keyring-$FROM is unchanged and remains the working one."
    exit 1
fi
if (( DELETE_SRC )); then
    # Only here: every key above migrated and had its address checked against the source, and a
    # single mismatch exits before this point.
    rm -rf "$DIR/keyring-$FROM"
    print -r -- "removed $DIR/keyring-$FROM (--delete-source)"
else
    print -r -- "keyring-$FROM was NOT deleted, deliberately.  Confirm the deployment works against"
    print -r -- "keyring-$TO first -- run a step, or read an address back -- and only then:"
    print -r -- "    rm -rf $DIR/keyring-$FROM"
fi
print -r -- ""
print -r -- "From now on the steps use keyring-$TO by default; export QADENA_KEYRING_BACKEND=$FROM"
print -r -- "only for an unattended harness run that cannot answer a passphrase prompt."
