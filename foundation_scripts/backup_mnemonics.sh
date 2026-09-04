#!/bin/zsh
#
# Back up the whole mnemonics directory as Shamir shares.
#
#   foundation_scripts/backup_mnemonics.sh --dir ~/launch/mnemonics \
#       --out-dir ~/launch/backup --parts 5 --threshold 3
#
# WHAT IT PRODUCES.  One tar.gz of the directory, split into N shares of which any K reassemble it.
# Store the shares in K-separated places: no single location can reconstruct anything, and losing
# (N-K) of them costs nothing.
#
# THE ARCHIVE IS NOT SEPARATELY ENCRYPTED, and that is deliberate.
#
# The files inside are ALREADY *.mnemonic.enc, sealed at mint time under the keyring passphrase.
# An encryption layer over the tarball would have protected only the FILE NAMES -- which buckets
# exist and how many members each has -- and that is not secret: it is in tokenomics/allocations.csv
# and in fill_launch_config.py's ACCOUNTS table, both in the repo.
#
# It would have cost a SECOND passphrase that must survive for decades, and an ambiguous prompt at
# exactly the worst moment: a recovery years from now, by someone who was not here, reading
# "passphrase" and not knowing which. One secret is easier to protect and harder to lose.
#
# So there is ONE secret in this whole chain -- the sealing/keyring passphrase -- and the shares
# are the second factor:
#
#     K shares  ->  untar  ->  sealing passphrase  ->  the words
#
# NOTE WHAT THE SHARES DO AND DO NOT DO.  They ensure no single share holder can reconstruct the
# archive.  They do NOT protect the mnemonics themselves -- that is the seal.  Losing the sealing
# passphrase makes every mnemonic unreadable from a perfect set of shares, so that secret needs its
# own survival plan.
#
# COMBINE DOES NOT VERIFY THE THRESHOLD -- hashicorp's shamir returns GARBAGE, not an error, when
# given too few shares (measured).  shamirtool records a SHA-256 at split time and refuses a
# mismatch, and gzip/tar above it fail loudly on nonsense too.
#
# RESTORE:  foundation_scripts/restore_mnemonics.sh --shares <dir> --out-dir <dir>
#
set -u
HERE="${0:A:h}"
ITER=200000

DIR="" OUTDIR="" PARTS=5 THRESHOLD=3 LABEL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)       DIR="$2"; shift 2 ;;
        --out-dir)   OUTDIR="$2"; shift 2 ;;
        --parts)     PARTS="$2"; shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --label)     LABEL="$2"; shift 2 ;;
        -h|--help)   sed -n '3,24p' "$0"; exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$DIR" && -n "$OUTDIR" ]] || { print -u2 "need --dir and --out-dir; see --help"; exit 1 }
[[ -d "$DIR" ]] || { print -u2 "$DIR does not exist"; exit 1 }
command -v go > /dev/null || { print -u2 "go is required (to run shamirtool)"; exit 1 }

n=$(ls -1 "$DIR" 2>/dev/null | wc -l | tr -d ' ')
(( n > 0 )) || { print -u2 "$DIR is empty -- refusing to back up nothing"; exit 1 }
[[ -d "$OUTDIR" ]] && [[ -n "$(ls -A "$OUTDIR" 2>/dev/null)" ]] && {
    print -u2 "$OUTDIR is not empty -- refusing to mix share sets."
    print -u2 "Shares from different splits look alike and cannot be combined; use a fresh directory."
    exit 1 }
mkdir -p "$OUTDIR" || exit 1
chmod 700 "$OUTDIR" 2>/dev/null

print "backing up $n file(s) from $DIR"
print "  scheme : ${THRESHOLD}-of-${PARTS} Shamir over the tar (contents already sealed)"
print ""

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

# -C so the archive holds bare filenames, not the absolute path of whoever's machine made it.
# -C so the archive holds bare filenames, not the absolute path of whoever's machine made it.
tar czf "$WORK/mnemonics.tar.gz" -C "$DIR" . || { print -u2 "tar failed"; exit 1 }

# REFUSE TO SPLIT PLAINTEXT.  If the directory still holds unsealed *.mnemonic files, the shares
# would carry readable secrets and K of them would be a full compromise -- the seal is the only
# thing protecting the words, since the archive itself is not encrypted.
# AN ARRAY, NOT `ls ... > /dev/null`.  With the (N) qualifier an unmatched glob expands to
# NOTHING, so `ls "$DIR"/*.mnemonic(N)` becomes a bare `ls` -- which lists the current directory
# and SUCCEEDS.  The guard was therefore always true, and refused every sealed directory.
plaintext=("$DIR"/*.mnemonic(N))
if (( ${#plaintext} )); then
    print -u2 ""
    print -u2 "REFUSING: $DIR still contains PLAINTEXT *.mnemonic files."
    print -u2 "  The archive is not encrypted -- the seal on each file is what protects it, so"
    print -u2 "  splitting plaintext would put readable mnemonics into the shares."
    print -u2 "  Seal them first:  foundation_scripts/mnemonic.sh seal $DIR"
    exit 1
fi
print "  archived ($(du -h "$WORK/mnemonics.tar.gz" | cut -f1), contents already sealed)"

( cd "$HERE/.." && go run -mod=vendor ./foundation_scripts/shamirtool split \
     --in "$WORK/mnemonics.tar.gz" --out-dir "$OUTDIR" \
     --parts "$PARTS" --threshold "$THRESHOLD" \
     --label "${LABEL:-qadena mnemonics $(date +%Y-%m-%d)}" ) || exit 1

print ""
print "NEXT -- and this is the part that matters:"
print "  * Move the $PARTS shares to $PARTS SEPARATE places.  Any $THRESHOLD reconstruct;"
print "    fewer are useless.  Shares kept together are worth no more than one file."
print "  * The shares protect the ARCHIVE.  The SEALING passphrase protects the mnemonics."
print "    A recovery needs BOTH: $THRESHOLD shares to rebuild the tar, then that passphrase to"
print "    read any mnemonic in it.  It is the only secret here -- make sure it survives."
print "  * Verify now, not later:"
print "      foundation_scripts/restore_mnemonics.sh --shares <k-of-them> --out-dir /tmp/verify
      diff -r $DIR /tmp/verify && print \"BACKUP VERIFIED\" || print \"BACKUP IS BAD\"
      rm -rf /tmp/verify
    A restore that ran is not a restore that is correct.  diff -r exits non-zero and
    names the file on a flipped byte or a missing one; without it you have only shown
    that the shares reassembled into something tar was willing to unpack."
