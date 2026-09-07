#!/bin/zsh
#
# Put SEC's mnemonics under the same protection the foundation's already have.
#
#   veritas_scripts/seal_sec_mnemonics.sh --sec-home ~/sec-veritas
#
# THE ASYMMETRY THIS FIXES.  The foundation holds 62 mnemonics as individually sealed
# <name>.mnemonic.enc files -- AES-256-CBC, PBKDF2, one passphrase -- and zero plaintext.  SEC
# holds SIX in one plaintext file, mnemonics.json, protected by nothing but 600 on the file and 700
# on the directory.  Those six derive every SEC wallet on the chain: both service providers, the
# whole citizen-onboarding sponsor pool, the document counter-signer, and the delegation key.  One
# `cat` is the entire deployment.
#
# WHAT IT DOES.  Writes one sealed file per mnemonic beside the JSON, VERIFIES each one decrypts
# back to exactly the value it came from, and only then offers to remove the plaintext.  The
# verification is the point: sealing without checking the round-trip is how you discover at
# recovery time that the passphrase was mistyped, when the plaintext is already gone.
#
# WHAT IT DOES NOT DO.  Remove mnemonics.json unless you pass --remove-plaintext, and it will not
# do that until every mnemonic has round-tripped.  Steps 2 and 3 read mnemonics.json directly, so
# removing it means those steps can no longer run unattended -- which is correct once a deployment
# is established and wrong while you are still bringing it up.  Seal early, remove late.
#
# RECOVERY, after the plaintext is gone:
#
#   foundation_scripts/mnemonic.sh show <sec-home>/mnemonics signermnemonic
#
# and to rebuild mnemonics.json for a step that needs it, --restore does exactly that.

set -e
set -u

HERE="${0:A:h}"
MN="$HERE/../foundation_scripts/mnemonic.sh"
SEC_HOME="${VERITAS_SEC_HOME:-$HOME/sec-veritas}"
REMOVE=0
RESTORE=0

usage() {
    print -r -- "Usage: seal_sec_mnemonics.sh [--sec-home <dir>] [--remove-plaintext] [--restore]"
    print -r -- ""
    print -r -- "  --sec-home <dir>      default \$VERITAS_SEC_HOME or ~/sec-veritas"
    print -r -- "  --remove-plaintext    delete mnemonics.json AFTER every mnemonic round-trips."
    print -r -- "                        Steps 2 and 3 read that file, so only do this once the"
    print -r -- "                        deployment is established."
    print -r -- "  --restore             rebuild mnemonics.json from the sealed files (asks once"
    print -r -- "                        for the passphrase)."
    print -r -- ""
    print -r -- "  Sealing uses foundation_scripts/mnemonic.sh -- the same cipher, the same"
    print -r -- "  passphrase discipline, and the same layout as the foundation's mnemonics."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sec-home)        SEC_HOME="$2"; shift 2 ;;
        --remove-plaintext) REMOVE=1; shift ;;
        --restore)         RESTORE=1; shift ;;
        --help|-h)         usage; exit 0 ;;
        *) print -u2 -- "unknown option: $1"; usage >&2; exit 1 ;;
    esac
done

[[ -x "$MN" ]] || { print -u2 "cannot run $MN"; exit 1 }
JSON="$SEC_HOME/mnemonics.json"
DIR="$SEC_HOME/mnemonics"

# The six keys step_1 writes.  Read from the FILE rather than listed here: a seventh added later
# would otherwise be sealed by nobody and silently left in plaintext.
_keys_from_json() { jq -r 'keys[]' "$JSON" }

if (( RESTORE )); then
    [[ -d "$DIR" ]] || { print -u2 "no sealed mnemonics in $DIR"; exit 1 }
    [[ ! -e "$JSON" ]] || { print -u2 "$JSON already exists -- refusing to overwrite it"; exit 1 }
    print -r -- "rebuilding $JSON from $DIR"
    _args=(); _filter="{"
    for _f in "$DIR"/*.mnemonic.enc(N); do
        _n="${${_f:t}%.mnemonic.enc}"
        # mnemonic.sh show prompts once per call; that is a lot of prompts.  Read the passphrase
        # once here and feed each call, rather than making the operator type it six times.
        if [[ -z "${_pass:-}" ]]; then
            print -u2 -n "  sealing passphrase (hidden): "; read -s _pass; print -u2 ""
        fi
        _v=$(print -r -- "$_pass" | "$MN" show "$DIR" "$_n" 2>/dev/null) \
            || { print -u2 "  could not decrypt $_n -- wrong passphrase?"; exit 1 }
        _args+=(--arg "$_n" "$_v")
        [[ "$_filter" == "{" ]] && _filter="$_filter$_n:\$$_n" || _filter="$_filter,$_n:\$$_n"
    done
    _filter="$_filter}"
    umask 077
    jq -n "${_args[@]}" "$_filter" > "$JSON"
    chmod 600 "$JSON"
    print -r -- "  wrote $JSON ($(jq -r 'keys|length' "$JSON") mnemonics) -- PLAINTEXT, delete it again when done"
    exit 0
fi

[[ -r "$JSON" ]] || { print -u2 "no $JSON -- nothing to seal (already sealed?  use --restore)"; exit 1 }

mkdir -p "$DIR"; chmod 700 "$DIR"
umask 077

# WRITE PLAINTEXT ONLY INSIDE THE 700 DIRECTORY, and only for as long as sealing takes.  The
# alternative -- piping into openssl without a temp file -- is what mnemonic.sh already does for
# `show`, but `seal` operates on files, so the exposure is a few milliseconds in a directory only
# this user can enter.  They are removed below whether sealing succeeded or not.
_cleanup() { rm -f "$DIR"/*.mnemonic(N) }
trap _cleanup EXIT INT TERM

_n=0
for _k in $(_keys_from_json); do
    jq -r --arg k "$_k" '.[$k]' "$JSON" > "$DIR/$_k.mnemonic"
    _n=$(( _n + 1 ))
done
print -r -- "sealing $_n mnemonic(s) from $JSON"

"$MN" seal "$DIR"

# VERIFY EVERY ONE BEFORE ANYTHING IS DELETED.  A sealed file that does not decrypt is worse than
# no sealed file: it looks like a backup.
print -u2 -n "  passphrase again, to verify the seals: "; read -s _vp; print -u2 ""
_bad=0
for _k in $(_keys_from_json); do
    _want=$(jq -r --arg k "$_k" '.[$k]' "$JSON")
    _got=$(print -r -- "$_vp" | "$MN" show "$DIR" "$_k" 2>/dev/null || true)
    if [[ "$_want" == "$_got" && -n "$_got" ]]; then
        print -r -- "  ok    $_k  ($(print -r -- "$_got" | wc -w | tr -d ' ') words)"
    else
        print -u2 -- "  FAIL  $_k does not round-trip"
        _bad=$(( _bad + 1 ))
    fi
done
(( _bad == 0 )) || { print -u2 ""; print -u2 "$_bad seal(s) failed -- $JSON left in place"; exit 1 }

print -r -- ""
print -r -- "all $_n mnemonic(s) sealed and verified in $DIR"
if (( REMOVE )); then
    rm -f "$JSON"
    print -r -- "removed $JSON"
    print -r -- ""
    print -r -- "STEPS 2 AND 3 READ THAT FILE.  To run them again:"
    print -r -- "    veritas_scripts/seal_sec_mnemonics.sh --restore"
    print -r -- "then delete the plaintext again when the run finishes."
else
    print -r -- ""
    print -r -- "$JSON is STILL PLAINTEXT.  Once the deployment is established:"
    print -r -- "    veritas_scripts/seal_sec_mnemonics.sh --remove-plaintext"
fi
