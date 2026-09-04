#!/bin/zsh
#
# Seal and reveal a mnemonic with symmetric encryption -- never plaintext at rest.
#
#   foundation_scripts/mnemonic.sh seal <dir>            encrypt every *.mnemonic in <dir>
#   foundation_scripts/mnemonic.sh show <dir> <name>     decrypt ONE to stdout
#
# WHY STDOUT, AND WHY THAT MATTERS.  buildscripts/init.sh asks for the genesis validator's mnemonic
# with `read -s`, which reads STDIN -- so the reveal can be piped straight into it:
#
#   foundation_scripts/mnemonic.sh show ~/launch/mnemonics qfi-pioneer1 \
#     | buildscripts/init.sh --mainnet-source ~/launch/x.yml --advertise-ip-address <ip>
#
# Nothing touches disk and nothing reaches `ps`.  Pass --advertise-ip-address so the IP prompt does
# not consume the piped line first.
#
# DO NOT use `--pioneer-mnemonic "$(... show ...)"`: that puts the mnemonic in ARGV, where any user
# on the machine can read it out of `ps`.  init.sh's own header says the prompt exists so a mnemonic
# "need never appear in shell history or ps" -- a command substitution throws that away.
#
# THE CIPHER is AES-256-CBC with PBKDF2 (200k iterations) and a random salt, via openssl, which is
# present on macOS and on the Ubuntu nodes.  Symmetric, one passphrase, no key material to manage
# beyond the passphrase that already unlocks the keyring.
#
set -u
HERE="${0:A:h}"
# CAPTURED AT TOP LEVEL.  In zsh $0 inside a function is the FUNCTION'S name (FUNCTION_ARGZERO is
# on by default), so `sed -n '3,26p' "$0"` in usage() ran as `sed ... usage` and reported
# "sed: usage: No such file or directory".  Only scripts that read their own header from inside a
# function hit this; the others do it at top level in the arg loop and are unaffected.
SELF="${0:A}"
ITER=200000

command -v openssl > /dev/null || { print -u2 "openssl is required"; exit 1 }

usage() { sed -n '3,26p' "$SELF"; exit ${1:-1} }
[[ $# -ge 1 ]] || usage
CMD="$1"; shift
[[ "$CMD" == "--help" || "$CMD" == "-h" ]] && usage 0

# Asked once, never echoed, never written down.  -s so it does not reach the terminal or scrollback.
ask_pass() {
    local p
    read -s "p?  passphrase: "; print -u2 ""
    [[ -n "$p" ]] || { print -u2 "empty passphrase"; exit 1 }
    print -r -- "$p"
}

case "$CMD" in
seal)
    DIR="${1:-}"; [[ -n "$DIR" && -d "$DIR" ]] || { print -u2 "seal needs a directory"; exit 1 }
    files=("$DIR"/*.mnemonic(N))
    (( ${#files} )) || { print -u2 "no *.mnemonic files in $DIR -- nothing to seal"; exit 1 }
    print -u2 "sealing ${#files} mnemonic(s) in $DIR"
    PASS=$(ask_pass)
    read -s "P2?  confirm:    "; print -u2 ""
    [[ "$PASS" == "$P2" ]] || { print -u2 "passphrases do not match"; exit 1 }
    unset P2
    for f in "${files[@]}"; do
        enc="${f}.enc"
        [[ -e "$enc" ]] && { print -u2 "  $(basename $enc) exists, skipping"; continue }
        if ! print -r -- "$PASS" | openssl enc -aes-256-cbc -pbkdf2 -iter $ITER -salt \
                -in "$f" -out "$enc" -pass stdin 2>/dev/null; then
            print -u2 "  FAILED to seal $(basename $f)"; rm -f "$enc"; exit 1
        fi
        chmod 600 "$enc"
        # VERIFY BEFORE DELETING THE ONLY COPY.  A cipher that wrote garbage and a cipher that
        # worked look identical until the day you need it, and by then the plaintext is gone.
        back=$(print -r -- "$PASS" | openssl enc -d -aes-256-cbc -pbkdf2 -iter $ITER \
                 -in "$enc" -pass stdin 2>/dev/null)
        if [[ "$back" != "$(cat "$f")" ]]; then
            print -u2 "  ROUND-TRIP FAILED for $(basename $f) -- keeping the plaintext"; rm -f "$enc"; exit 1
        fi
        rm -f "$f"
        print -u2 "  sealed $(basename $enc)"
    done
    print -u2 ""
    print -u2 "done.  Plaintext removed; only *.mnemonic.enc remain."
    ;;
show)
    DIR="${1:-}"; NAME="${2:-}"
    [[ -n "$DIR" && -n "$NAME" ]] || { print -u2 "show needs <dir> <name>"; exit 1 }
    enc="$DIR/$NAME.mnemonic.enc"
    [[ -r "$enc" ]] || { print -u2 "no $enc"; exit 1 }
    PASS=$(ask_pass)
    # BUFFERED, NOT STREAMED.  openssl writes partial plaintext as it decrypts and only reports
    # failure at the end -- so a wrong passphrase emits BINARY GARBAGE to stdout and *then* errors.
    # This command is meant to be piped into init.sh's mnemonic prompt, where that garbage would be
    # accepted as the mnemonic.  Capture it, check it, and only then let anything reach stdout.
    local plain
    plain=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter $ITER \
              -in "$enc" -pass fd:3 3< <(print -r -- "$PASS") 2>/dev/null) || {
        print -u2 "could not decrypt $enc -- wrong passphrase, or the file is damaged"
        exit 1 }

    # A BIP39 mnemonic is 12 or 24 words.  Anything else is not a mnemonic, however cleanly it
    # decrypted -- and feeding it onward is worse than failing here.
    local wc=$(print -r -- "$plain" | wc -w | tr -d ' ')
    if [[ "$wc" != "12" && "$wc" != "24" ]]; then
        print -u2 "decrypted $wc word(s) -- not a 12 or 24 word mnemonic.  Refusing to emit it."
        exit 1
    fi
    print -r -- "$plain"
    ;;
*) print -u2 "unknown subcommand: $CMD"; usage ;;
esac
