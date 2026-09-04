#!/bin/zsh
#
# Reassemble a mnemonics backup from Shamir shares.
#
#   foundation_scripts/restore_mnemonics.sh --shares ~/launch/backup --out-dir ~/restored
#   foundation_scripts/restore_mnemonics.sh --out-dir ~/restored share-01*.txt share-03*.txt ...
#   foundation_scripts/restore_mnemonics.sh --shares a.txt --shares b.txt --shares c.txt --out-dir ...
#
# --shares takes a DIRECTORY or a FILE and may be repeated; bare arguments are share files too.  It needs the threshold recorded in
# them; fewer and it stops rather than producing nonsense.
#
# WHY IT CHECKS SO MUCH.  hashicorp's shamir.Combine returns GARBAGE and no error when given too
# few shares (measured, not assumed).  So there are three gates, and a real backup passes all three:
#   1. shamirtool refuses fewer shares than the threshold recorded in them
#   2. shamirtool checks the reassembled bytes against the SHA-256 taken at split time
#   3. tar/gzip fail on anything that is not the original archive
#
# TEST A BACKUP THE DAY YOU MAKE IT.  A backup nobody has restored is a hypothesis.
#
set -u
HERE="${0:A:h}"
ITER=200000

OUTDIR="" FILES=() SHARE_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        # A DIRECTORY *OR* A FILE, and repeatable.  Requiring a directory here made
        # `--shares a.txt b.txt c.txt` -- the obvious thing to type -- fail with "does not exist"
        # about a file that existed perfectly well, because it was being tested with -d.
        --shares)  SHARE_ARGS+=("$2"); shift 2 ;;
        --out-dir) OUTDIR="$2"; shift 2 ;;
        -h|--help) sed -n '3,22p' "$0"; exit 0 ;;
        -*) print -u2 "unknown option: $1"; exit 1 ;;
        *) FILES+=("$1"); shift ;;
    esac
done
[[ -n "$OUTDIR" ]] || { print -u2 "need --out-dir; see --help"; exit 1 }
for a in "${SHARE_ARGS[@]}"; do
    if [[ -d "$a" ]]; then
        got=("$a"/share-*.txt(N))
        (( ${#got} )) || { print -u2 "$a contains no share-*.txt files"; exit 1 }
        FILES+=("${got[@]}")
    elif [[ -f "$a" ]]; then
        FILES+=("$a")
    else
        print -u2 "$a is neither a file nor a directory"
        exit 1
    fi
done
# Duplicates are not extra shares -- shamir would combine the same point twice and silently
# reassemble the wrong secret, which the sha256 check would then report as corruption.
FILES=("${(@u)FILES}")
(( ${#FILES} )) || { print -u2 "no share files given"; exit 1 }
command -v go > /dev/null || { print -u2 "go is required (to run shamirtool)"; exit 1 }

[[ -e "$OUTDIR" ]] && [[ -n "$(ls -A "$OUTDIR" 2>/dev/null)" ]] && {
    print -u2 "$OUTDIR is not empty -- refusing to unpack over existing files"; exit 1 }
mkdir -p "$OUTDIR" || exit 1
chmod 700 "$OUTDIR" 2>/dev/null

print "restoring from ${#FILES} share(s)"
WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

( cd "$HERE/.." && go run -mod=vendor ./foundation_scripts/shamirtool combine \
     --out "$WORK/mnemonics.tar.gz" "${FILES[@]}" ) || exit 1

# The archive is not encrypted: what protects the mnemonics is the seal on each file inside.
tar xzf "$WORK/mnemonics.tar.gz" -C "$OUTDIR" \
    || { print -u2 "the archive did not unpack -- the reassembled data is not the original"; exit 1 }

n=$(ls -1 "$OUTDIR" 2>/dev/null | wc -l | tr -d ' ')
print "  restored $n file(s) -> $OUTDIR"
print ""
# Same trap as in backup_mnemonics.sh: an unmatched (N) glob leaves a bare `ls`, which succeeds.
sealed=("$OUTDIR"/*.mnemonic.enc(N))
if (( ${#sealed} )); then
    print "These are still SEALED (*.mnemonic.enc).  Read one with the SEALING passphrase:"
    print "    foundation_scripts/mnemonic.sh show $OUTDIR <name>"
else
    print "These are PLAINTEXT secrets.  Remove $OUTDIR as soon as you are done with it."
fi
