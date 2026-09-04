#!/bin/zsh
#
# Mint the launch chain's keys into an ENCRYPTED keyring and emit the CSV that
# foundation_scripts/fill_launch_config.py --apply consumes.
#
#   foundation_scripts/derive_launch_keys.sh --home ~/launch/coord \
#       --mnemonics-dir ~/launch/mnemonics --out ~/launch/addresses.csv
#
# WHY THIS EXISTS.  fill_launch_config.py --dev-keys does the same shape, but mints into
# `--keyring-backend test` -- an UNENCRYPTED keyring on disk -- and stamps every row
# "DEV THROWAWAY KEY -- never for mainnet".  That is correct for a fleet you purge.  It is not
# what you want for a chain whose genesis freezes these addresses forever.
#
# The topology is the same either way, and that is deliberate: at genesis "almost nobody's address
# is known" (the brief's LATE ARRIVAL section), so the FOUNDER holds every member key until real
# members arrive.  What separates a launch from a test is not the shape, it is HOW THE KEYS ARE
# MINTED -- encrypted keyring, and every mnemonic captured as it is created.
#
# THE ACCOUNT LIST IS NOT DUPLICATED HERE.  It is read from
# `fill_launch_config.py --template`, which is the single source of names and thresholds.  A second
# copy in this file would drift, and the failure would be a bucket missing from genesis.
#
# IF THERE IS NO qadenad it builds a throwaway one into a temp dir and deletes it on exit
# (--no-build to refuse instead).  See the note at the build site for why that is safe HERE and
# would not be elsewhere.
#
# WHAT IT WRITES
#   <out>              name,address,threshold,... -- feed straight to --apply
#   <mnemonics-dir>/   one 0600 <name>.mnemonic.enc per signing key -- AES-256-CBC/PBKDF2 under
#                      the same passphrase as the keyring.  THE ONLY RECOVERY THAT EXISTS.
#                      Never written in the clear: the mnemonic goes from qadenad's stdout through
#                      a variable into openssl's stdin, and each file is decrypted and compared
#                      before the run moves on.  Read one back with
#                      foundation_scripts/mnemonic.sh show <dir> <name>.
#
# THE MNEMONICS ARE THE POINT.  A multisig has no private material of its own -- it is derived
# from its members -- so losing a member mnemonic degrades the threshold, and losing enough of
# them makes the bucket unspendable while genesis still says it holds billions.  This script
# refuses to run without somewhere to put them, and refuses to overwrite one it finds.
#
set -u
HERE="${0:A:h}"

HOME_DIR="" OUT="" MNEM_DIR="" PASSFILE="" QBIN="" FORCE=0 NO_BUILD=0
ENC_ITER=200000          # PBKDF2 rounds; matches foundation_scripts/mnemonic.sh
BUILT_TMP=""
cleanup_built() { [[ -n "$BUILT_TMP" ]] && rm -rf "$BUILT_TMP" }
trap cleanup_built EXIT
while [[ $# -gt 0 ]]; do
    case "$1" in
        --home)           HOME_DIR="$2"; shift 2 ;;
        --out)            OUT="$2"; shift 2 ;;
        --mnemonics-dir)  MNEM_DIR="$2"; shift 2 ;;
        --passphrase-file) PASSFILE="$2"; shift 2 ;;
        --qadenad)        QBIN="$2"; shift 2 ;;
        --no-build)       NO_BUILD=1; shift ;;
        --force)          FORCE=1; shift ;;
        -h|--help)        sed -n '3,32p' "$0"; exit 0 ;;
        *) print -u2 "unknown option: $1"; exit 1 ;;
    esac
done
[[ -n "$HOME_DIR" && -n "$OUT" && -n "$MNEM_DIR" ]] \
    || { print -u2 "need --home, --out and --mnemonics-dir; see --help"; exit 1 }

# NEVER $QADENAHOME.  buildscripts/init.sh does `rm -rf $QADENAHOME`, so a keyring placed there is
# destroyed by the very build these keys exist for -- which is exactly how a Mac lost 72 bucket
# keys on 2026-09-03.  Refuse rather than warn.
real_home="${QADENAHOME:-$HOME/qadena}"
if [[ "${HOME_DIR:A}" == "${real_home:A}" ]]; then
    print -u2 -- "--home must NOT be \$QADENAHOME ($real_home): init.sh does 'rm -rf' on it."
    print -u2 "Use a dedicated directory, e.g. ~/launch/coord"
    exit 1
fi

# Prefer an installed binary, fall back to the build tree.  install.sh need not have run: deriving
# addresses is a build-time act and the node may not exist yet.
if [[ -z "$QBIN" ]]; then
    for c in "$real_home/bin/qadenad" "$HERE/../cmd/qadenad/qadenad"; do
        [[ -x "$c" ]] && { QBIN="$c"; break }
    done
fi
# BUILD ONE IF THERE IS NONE -- INTO A TEMP DIR, AND ONLY BECAUSE OF WHAT WE USE IT FOR.
#
# This script runs `keys add` and `keys show` and nothing else: local keyring operations that never
# verify a remote report, never talk to a chain, and are identical in a debug and an SGX build.  So
# a plain `go build` is sufficient here even though it omits `-tags realenclave`.
#
# THE TEMP DIR IS THE SAFETY.  A binary built without that tag uses the DEBUG verifier -- it accepts
# forged attestation while believing it has attestation (see buildscripts/build.sh).  Left in
# cmd/qadenad/, it is indistinguishable from a real build and the next install.sh would happily ship
# it to a node.  Building somewhere temporary and deleting it on exit means this convenience cannot
# leak into a deployment.  Use buildscripts/build.sh for anything a node will run.
if [[ -z "$QBIN" || ! -x "$QBIN" ]]; then
    if (( NO_BUILD )); then
        print -u2 "no qadenad found and --no-build was given.  Looked in:"
        print -u2 "    $real_home/bin/qadenad       (installed)"
        print -u2 "    $HERE/../cmd/qadenad/qadenad (built)"
        exit 1
    fi
    command -v go > /dev/null || {
        print -u2 "no qadenad found and no go toolchain to build one."
        print -u2 "    looked in $real_home/bin/qadenad and $HERE/../cmd/qadenad/qadenad"
        print -u2 "    build with buildscripts/build.sh, or pass --qadenad <path>"
        exit 1 }
    BUILT_TMP=$(mktemp -d)
    print "no qadenad found -- building a throwaway one (keys operations only, deleted on exit)"
    if ! ( cd "$HERE/.." && go build -mod=vendor -o "$BUILT_TMP/qadenad" ./cmd/qadenad ) 2>&1 | tail -5; then
        print -u2 "build failed -- run buildscripts/build.sh to see it properly"
        exit 1
    fi
    [[ -x "$BUILT_TMP/qadenad" ]] || { print -u2 "build produced no binary"; exit 1 }
    QBIN="$BUILT_TMP/qadenad"
    print "  built $QBIN"
fi

PY="$HERE/fill_launch_config.py"
[[ -x "$PY" || -f "$PY" ]] || { print -u2 "cannot find $PY"; exit 1 }

command -v openssl > /dev/null || {
    print -u2 "openssl is required: mnemonics are sealed as they are minted, never written in the clear."
    exit 1 }

mkdir -p "$MNEM_DIR" || exit 1
chmod 700 "$MNEM_DIR" 2>/dev/null
mkdir -p "$HOME_DIR" || exit 1

# ASKED ONCE, HELD IN MEMORY, FED TO EVERY INVOCATION.
#
# `--keyring-backend file` prompts on EVERY call and this script makes over a hundred, so
# per-command prompting was never viable.  Worse, `mint()` captures stdout with $(...) to read the
# mnemonic back -- which swallows the prompt, so the operator types blind into an invisible
# confirmation and gets "passphrase do not match" with nothing on screen explaining why.
#
# The passphrase never reaches disk and never reaches a command line: it is written into the pipe
# by a shell builtin, so it cannot appear in `ps`.
kr=(--keyring-backend file --home "$HOME_DIR")
KRPASS=""
if [[ -n "$PASSFILE" ]]; then
    [[ -r "$PASSFILE" ]] || { print -u2 "cannot read $PASSFILE"; exit 1 }
    KRPASS=$(head -1 "$PASSFILE")
    [[ -n "$KRPASS" ]] || { print -u2 "$PASSFILE is empty"; exit 1 }
else
    print "The keyring at $HOME_DIR is encrypted and needs a passphrase."
    print "It is asked once here and reused for every key -- it is never written to disk."
    read -s "KRPASS?  passphrase: "; print ""
    if [[ ! -d "$HOME_DIR/keyring-file" ]]; then
        read -s "KRPASS2?  confirm:    "; print ""
        [[ "$KRPASS" == "$KRPASS2" ]] || { print -u2 "passphrases do not match"; exit 1 }
        unset KRPASS2
    fi
    [[ -n "$KRPASS" ]] || { print -u2 "empty passphrase"; exit 1 }
fi

q() {
    # twice: the backend asks for confirmation the first time it creates the keyring, and ignores
    # the surplus line on every call after that.
    { print -r -- "$KRPASS"; print -r -- "$KRPASS" } | "$QBIN" "${kr[@]}" "$@" 2>/dev/null
}

print "deriving launch keys"
print "  qadenad     : $QBIN"
print "  keyring     : $HOME_DIR  (backend: file, ENCRYPTED)"
print "  mnemonics   : $MNEM_DIR  (0600 per key -- the only recovery)"
print "  out         : $OUT"
print ""

tmpl=$(mktemp)
python3 "$PY" --template "$tmpl" > /dev/null || { print -u2 "could not read the account list from $PY"; rm -f "$tmpl"; exit 1 }

# Capture the mnemonic AS THE KEY IS CREATED.  `keys add --output json` carries it; there is no
# second chance to ask for it afterwards.
mint() {   # $1 = key name
    # SEPARATE STATEMENTS, NOT one `local a=.. b=$a`.  In zsh the right-hand sides of a single
    # `local` are expanded against the OUTER scope, so `mf=...$n...` picked up the caller's $n --
    # the member COUNT (5) -- and every key's mnemonic was written to `5.mnemonic`, each
    # overwriting the last.  Keys existed with no recoverable mnemonic, which is precisely what
    # this script exists to prevent.
    local n="$1"
    local mf="$MNEM_DIR/$n.mnemonic.enc"
    local out mn back

    if q keys show "$n" -a > /dev/null 2>&1; then
        # A KEY WITH NO MNEMONIC IS UNRECOVERABLE, and this used to print "skipping" as though it
        # were fine.  The keyring can sign with it today and nothing can ever restore it elsewhere,
        # so say so rather than let a resumed run paper over it.
        if [[ -e "$mf" ]]; then
            print "    $n: already minted and sealed, skipping"
            return 0
        fi
        print -u2 "    $n: IN THE KEYRING BUT HAS NO SEALED MNEMONIC ($mf)."
        print -u2 "      That key cannot be recovered anywhere else.  Delete it from the keyring"
        print -u2 "      and re-run to mint a recoverable one, or --force to carry on regardless."
        (( FORCE )) || return 1
        return 0
    fi
    if [[ -e "$mf" && $FORCE -eq 0 ]]; then
        print -u2 "    $n: $mf exists but the key does not -- refusing to overwrite a mnemonic."
        print -u2 "      That file may be the only copy of a key this keyring has lost."
        return 1
    fi

    out=$(q keys add "$n" --output json 2>&1) || { print -u2 "    $n: keys add failed: $out"; return 1 }
    mn=$(print -- "$out" | sed -n 's/.*"mnemonic":"\([^"]*\)".*/\1/p')
    if [[ -z "$mn" ]]; then
        print -u2 "    $n: created but NO MNEMONIC was returned -- refusing to continue."
        print -u2 "      An unrecoverable key is worse than no key.  Output: $(print -- "$out" | tail -2)"
        return 1
    fi

    # SEALED WITHOUT EVER TOUCHING DISK IN THE CLEAR.  The mnemonic goes qadenad stdout -> this
    # variable -> openssl stdin -> ciphertext.  Writing it plaintext first and encrypting after
    # would leave ~60 readable secrets lying around for the length of the run, and any crash in
    # between leaves them there.
    # THE PASSPHRASE GETS ITS OWN DESCRIPTOR.  Sending both the passphrase and the data through
    # stdin does not work -- openssl takes the first line as the passphrase and then mis-reads the
    # rest as ciphertext input, producing a file that encrypts "successfully" and never decrypts
    # back.  The verify below caught exactly that.  Data on stdin, passphrase on fd 3.
    if ! print -r -- "$mn" | \
         openssl enc -aes-256-cbc -pbkdf2 -iter "$ENC_ITER" -salt -out "$mf" \
                 -pass fd:3 3< <(print -r -- "$KRPASS") 2>/dev/null; then
        print -u2 "    $n: could not seal the mnemonic -- the key exists but is UNRECOVERABLE."
        print -u2 "      Delete '$n' from $HOME_DIR and re-run."
        rm -f "$mf"
        return 1
    fi
    chmod 600 "$mf" 2>/dev/null

    # VERIFY BEFORE MOVING ON.  A cipher that wrote rubbish and one that worked look identical
    # until the day you need it, and by then the plaintext is long gone.
    back=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter "$ENC_ITER" \
             -in "$mf" -pass fd:3 3< <(print -r -- "$KRPASS") 2>/dev/null)
    if [[ "$back" != "$mn" ]]; then
        print -u2 "    $n: SEALED FILE DOES NOT DECRYPT BACK -- refusing to continue."
        rm -f "$mf"
        return 1
    fi
    print "    $n: minted, sealed -> $(basename "$mf")"
}

rows=()
fail=0
while IFS=, read -r name address threshold rest; do
    [[ "$name" == "name" || -z "$name" ]] && continue
    print "  $name  ($threshold)"
    if [[ "$threshold" == "single" ]]; then
        mint "$name" || { fail=1; continue }
    else
        nmem=${threshold##*of}; thr=${threshold%%of*}
        members=()
        for i in $(seq 1 "$nmem"); do
            mint "${name}-m${i}" || { fail=1; break }
            members+=("${name}-m${i}")
        done
        (( fail )) && continue
        if ! q keys show "$name" -a > /dev/null 2>&1; then
            # A multisig holds NO private material -- it is a pure function of its members'
            # pubkeys, the threshold and their ORDER.  Nothing to back up here, and any member
            # can re-derive the same address to check it.
            q keys add "$name" --multisig "${(j:,:)members}" --multisig-threshold "$thr" > /dev/null 2>&1 \
                || { print -u2 "    $name: could not derive the multisig"; fail=1; continue }
            print "    $name: derived ${thr}-of-${nmem} from ${(j:,:)members}"
        else
            print "    $name: multisig already present"
        fi
    fi
    addr=$(q keys show "$name" -a 2>/dev/null | tr -d '\r')
    [[ "$addr" == qadena1* ]] || { print -u2 "    $name: no address derived"; fail=1; continue }
    print "    $name = $addr"
    rows+=("$name,$addr,$threshold,$rest")
done < "$tmpl"
rm -f "$tmpl"

(( fail )) && { print -u2 ""; print -u2 "one or more keys failed -- $OUT NOT written"; exit 1 }

{ print "name,address,threshold,what_it_is,how_to_derive"
  for r in "${rows[@]}"; do print -- "$r"; done } > "$OUT" || exit 1

print ""
print "wrote $OUT"
print ""
print "NEXT:"
print "  1. BACK UP $MNEM_DIR -- offline, off this machine.  It is the only recovery."
print "     foundation_scripts/backup_mnemonics.sh --dir $MNEM_DIR --out-dir <shares> --parts 5 --threshold 3"
print "  2. Copy the addresses into tokenomics/allocations.csv BY HAND (it is human-owned)."
print "  3. foundation_scripts/fill_launch_config.py --apply $OUT \\"
print "         --out ~/launch/<chain>-launch-config.yml"
print "  4. buildscripts/init.sh --mainnet-source ~/launch/<chain>-launch-config.yml"
print "     (it will prompt, hidden, for the validator's mnemonic from $MNEM_DIR)"
