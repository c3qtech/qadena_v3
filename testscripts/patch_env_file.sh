#!/usr/bin/env bash
#
# Patch a deployment's env file with the wallet keys a VERITAS bring-up produced.
#
#   ./testscripts/patch_env_file.sh sec stacks/veritas/env-sponsored-test
#
# gen_key_env_vars.sh turns the *.base64 files into a block of SEC_* assignments; this puts that
# block INTO an env file that already exists, replacing the ten variables in place and leaving
# every other line -- API keys, URLs, database settings, comments -- exactly as it found them.
# Doing that by hand means ten copy-pastes of 3KB base64 blobs into a file where a truncated paste
# is invisible and produces a key that decodes to nothing.
#
# WHAT IT WILL NOT DO
#
#   * It never prints a key.  The values are ARMORED PRIVATE KEYS: whoever holds
#     SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY can sign as every pooled sponsor wallet.  Progress
#     names variables and byte counts, never contents, so a terminal log or a CI transcript of
#     this run is not a key disclosure.
#   * It never creates the env file.  Patching a file that does not exist would produce something
#     that looks like a deployment config while missing everything else the stack needs.
#   * It never commits.  The result contains private keys; `git add` on it is the accident this
#     exists to make less likely, so the backup it writes is named to be caught by .gitignore
#     patterns and the script says so at the end.
#
# THE VARIABLE NAMES DO NOT FOLLOW THE PREFIX -- see gen_key_env_vars.sh.  `sec` and `ekycph`
# deployments both write SEC_*, because config.go binds those names unconditionally.  Only the
# FILENAMES carry the prefix.  This script inherits that and must not "fix" it.
#
# ORDER MATTERS ON A SPLIT KEYRING.  The .base64 files are produced on the machine that ran
# step_2/step_3 (SEC's box).  If you are patching an env file on a different machine, copy the
# whole key directory across first -- a partial copy fails the length check in gen_key_env_vars.sh
# rather than writing half a deployment.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GEN="$SCRIPT_DIR/gen_key_env_vars.sh"

PREFIX=""
ENV_FILE=""
KEY_DIR="."
SPONSORS=""
ARMOR_PASSFILE=""
OUT=""
IN_PLACE=0
NODE_HOST=""
GRPC_PORT=""
DRY_RUN=0

usage() {
	cat <<'EOF'
Usage: patch_env_file.sh <prefix> <env-file> [options]

  <prefix>      the leading component of the .base64 FILENAMES: sec, ekycph, ...
                (the VARIABLE names are always SEC_*; see gen_key_env_vars.sh)
  <env-file>    an EXISTING env file; it is READ, never written (see --out)

Options:
  --key-dir <dir>    where the *.base64 files are (default: the current directory)
  --sponsors <file>  also set QADENA_FOUNDATION_USERS_ADDRESS and
                     QADENA_FOUNDATION_APPSVR_ADDRESS from a veritas-sponsors.json
                     (written by sec_veritas_before_step_1.sh --stage prepare)
  --armor-passfile <file>
                     also set ARMOR_PASS_PHRASE from this file's first line.  The
                     app-server needs the passphrase the KEYS WERE EXPORTED WITH,
                     which is the keyring passphrase -- pass the same file you gave
                     the bring-up.  Without it the app dies at startup with
                     "Failed to import private key" and no further detail.
  --node-host <host> set QADENA_PIONEER_IP and QADENA_PUBLIC_HOST to this host or
                     IP -- the chain THIS deployment's keys belong to.  Without it
                     both keep whatever the env file already carried, which is a
                     DIFFERENT chain's endpoint: the app then authenticates with
                     the new keys against the old chain and fails at runtime, with
                     nothing in the config naming the cause.
  --grpc-port <n>    set QADENA_GRPC_PORT too (default: leave it alone)
  --out <file>       where to write the populated copy
                     (default: <key-dir>/<source basename>, i.e. the deployment home,
                     the same place patch_cloud_formation_template.sh puts its copy)
  --in-place         patch the SOURCE instead, keeping a timestamped backup beside
                     it.  This was the only behaviour once; it is now opt-in.
  --dry-run          report what would change; write nothing

  THE SOURCE IS NOT MODIFIED unless --in-place is given.  The output holds ARMORED
  PRIVATE KEYS and belongs with the rest of the deployment's secrets, not in a
  stack directory that is edited by hand and easy to commit.  --in-place still
  writes the timestamped backup it always did.
  Keys are never printed -- progress names variables and sizes only.

  ./testscripts/patch_env_file.sh sec stacks/veritas/env-sponsored-test \
      --key-dir ~/sec-veritas/keys \
      --sponsors ~/fleet-launch/coord/veritas-sponsors.json
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--key-dir)  KEY_DIR="$2"; shift 2 ;;
	--sponsors) SPONSORS="$2"; shift 2 ;;
	--armor-passfile) ARMOR_PASSFILE="$2"; shift 2 ;;
	--node-host) NODE_HOST="$2"; shift 2 ;;
	--grpc-port) GRPC_PORT="$2"; shift 2 ;;
	--out)      OUT="$2"; shift 2 ;;
	--in-place) IN_PLACE=1; shift ;;
	--dry-run)  DRY_RUN=1; shift ;;
	--help|-h)  usage; exit 0 ;;
	--*)        echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
	*)
		if [ -z "$PREFIX" ]; then PREFIX="$1"
		elif [ -z "$ENV_FILE" ]; then ENV_FILE="$1"
		else echo "unexpected argument: $1" >&2; exit 1
		fi
		shift ;;
	esac
done

[ -n "$PREFIX" ] && [ -n "$ENV_FILE" ] || { usage >&2; exit 1; }
[ -x "$GEN" ] || { echo "error: cannot run $GEN" >&2; exit 1; }

# REFUSE TO CREATE.  An env file is a deployment's whole configuration; one containing only these
# ten variables would start and then fail on everything else, which is a worse outcome than a
# clear refusal here.
if [ ! -f "$ENV_FILE" ]; then
	echo "error: $ENV_FILE does not exist." >&2
	echo "  This patches an EXISTING env file; it does not create one.  Copy the stack's" >&2
	echo "  template first (e.g. stacks/veritas/env.template) and patch that." >&2
	exit 1
fi

# WHERE THE POPULATED COPY GOES.  Defaulted beside the keys, exactly as
# patch_cloud_formation_template.sh does: --key-dir is the deployment home, which already varies
# per deployment AND per site, so one deployment's rendered env cannot be mistaken for another's.
if [ "$IN_PLACE" -eq 1 ]; then
	[ -z "$OUT" ] || { echo "error: --out and --in-place are mutually exclusive." >&2; exit 1; }
	OUT="$ENV_FILE"
else
	[ -n "$OUT" ] || OUT="${KEY_DIR%/}/$(basename "$ENV_FILE")"
	# SAME FILE BY A DIFFERENT PATH IS STILL THE SAME FILE.  --key-dir pointed at the stack
	# directory would resolve to the source and patch it in place while reporting a copy.
	if [ "$(cd "$(dirname "$OUT")" 2>/dev/null && pwd)/$(basename "$OUT")" = \
	     "$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")" ]; then
		echo "error: --out resolves to the source env file." >&2
		echo "  Use --in-place if patching it is what you meant; it keeps a backup." >&2
		exit 1
	fi
fi

# GENERATE FIRST, WRITE NOTHING YET.  gen_key_env_vars.sh validates every file -- base64, JSON
# array, and name/key array lengths matching -- and exits non-zero if any of it is wrong.  Running
# it before touching the env file means a bad key directory cannot leave a half-patched config.
BLOCK="$(mktemp)"
trap 'rm -f "$BLOCK"' EXIT
echo "reading keys from $KEY_DIR (prefix: $PREFIX)"
if ! "$GEN" "$KEY_DIR" "$PREFIX" > "$BLOCK"; then
	echo "error: key generation failed -- $ENV_FILE is untouched" >&2
	exit 1
fi

# The sponsor addresses are PUBLIC, unlike everything else here, so they may be printed.
FOUNDATION_USERS=""
FOUNDATION_APPSVR=""
if [ -n "$SPONSORS" ]; then
	[ -f "$SPONSORS" ] || { echo "error: no such file: $SPONSORS" >&2; exit 1; }
	command -v jq >/dev/null 2>&1 || { echo "error: --sponsors needs jq" >&2; exit 1; }
	# TWO FILE SHAPES, ONE PAIR OF FACTS -- see the same note in patch_cloud_formation_template.sh.
	# The foundation holds <deployment>-sponsors.json (.appsvr/.users) in its coordinator home; the
	# DEPLOYMENT side has no coordinator home and holds variables.json (.appsvraddr/.usersaddr),
	# which step_1 wrote.  Accept either, so whoever patches does not need the other side's file.
	FOUNDATION_USERS=$(jq -r '.users  // .usersaddr  // empty' "$SPONSORS")
	FOUNDATION_APPSVR=$(jq -r '.appsvr // .appsvraddr // empty' "$SPONSORS")
	[ -n "$FOUNDATION_USERS" ] && [ -n "$FOUNDATION_APPSVR" ] || {
		echo "error: $SPONSORS names neither .users/.appsvr nor .usersaddr/.appsvraddr." >&2
		echo "  Point --sponsors at either:" >&2
		echo "    <coord>/<deployment>-sponsors.json   (foundation side, from --stage prepare)" >&2
		echo "    <deployment home>/variables.json     (deployment side, written by step_1)" >&2
		exit 1
	}
	echo "foundation from $SPONSORS:"
	echo "  users  $FOUNDATION_USERS"
	echo "  appsvr $FOUNDATION_APPSVR"
fi

# THE ARMOR PASSPHRASE IS THE KEYRING PASSPHRASE, and that is not a choice anyone made -- it is a
# consequence.  extract_ephem_keys.sh pipes `echo "dummy-passphrase"` into `keys export`, but the
# export runs through qadenad_alias, which supplies its OWN stdin (the keyring passphrase, fed
# repeatedly for however many prompts a command has).  That overrides the echo, so the armor ends
# up encrypted with the keyring passphrase whatever the script intended.
#
# The app-server then imports with ARMOR_PASS_PHRASE and dies at startup on a mismatch --
# "Failed to import private key for <name>:" with an EMPTY reason, which points nowhere near the
# cause.  Measured 2026-09-07: the env shipped dummy-passphrase, the keys were encrypted with the
# keyring passphrase, and the api container exited 1 in a restart loop.
# THE ENDPOINT, SET FOR THE SAME REASON AS IN THE CFN PATCHER -- an option present in one patcher
# and absent in the other is how the two drift.
#
# NOT THROUGH $BLOCK, THOUGH.  The block is `VAR='value'` and the python carries those lines over
# verbatim, so routing the endpoint through it writes QADENA_PIONEER_IP='103.56.5.229' -- quoted,
# where this file writes the host UNQUOTED, and every consumer that does not strip quotes then
# resolves a hostname with apostrophes in it.  The file already carries both conventions: the
# base64 blobs are quoted, the addresses and the endpoint are not.  So these go the way the
# addresses go, as plain values handed to the editor.
if [ -n "$NODE_HOST" ]; then
	echo "  endpoint: QADENA_PIONEER_IP / QADENA_PUBLIC_HOST -> $NODE_HOST"
fi
if [ -n "$GRPC_PORT" ]; then
	echo "  endpoint: QADENA_GRPC_PORT -> $GRPC_PORT"
fi

ARMOR_PASS=""
if [ -n "$ARMOR_PASSFILE" ]; then
	[ -r "$ARMOR_PASSFILE" ] || { echo "error: cannot read $ARMOR_PASSFILE" >&2; exit 1; }
	ARMOR_PASS=$(head -1 "$ARMOR_PASSFILE")
	[ -n "$ARMOR_PASS" ] || { echo "error: $ARMOR_PASSFILE is empty" >&2; exit 1; }
	echo "armor passphrase: taken from $ARMOR_PASSFILE (${#ARMOR_PASS} chars, not shown)"
fi

# .bak LAST, so the plain `*.bak` rule that nearly every .gitignore already carries
# actually matches it. This used to be "${ENV_FILE}.bak.<stamp>", where .bak is an
# infix and `*.bak` matches nothing -- so the header's promise that the backup "is
# named to be caught by .gitignore patterns" was false, and a file holding the ARMORED
# PRIVATE KEYS this script just replaced sat untracked-but-visible in `git status`,
# one `git add -A` from being committed. (Caught 2026-09-14 in follow-the-money.)
BACKUP="${OUT}.$(date -u '+%Y%m%dT%H%M%SZ').bak"
if [ "$DRY_RUN" -eq 0 ]; then
	if [ "$IN_PLACE" -eq 1 ]; then
		cp -p "$ENV_FILE" "$BACKUP"
		chmod 600 "$BACKUP" 2>/dev/null || true
	else
		# The copy IS the output; the source stays as it was, so there is nothing to back up.
		BACKUP=""
		mkdir -p "$(dirname "$OUT")"
		cp -p "$ENV_FILE" "$OUT"
		chmod 600 "$OUT" 2>/dev/null || true
	fi
fi

DRY_RUN="$DRY_RUN" \
ENV_FILE="$OUT" \
BLOCK="$BLOCK" \
FOUNDATION_USERS="$FOUNDATION_USERS" \
FOUNDATION_APPSVR="$FOUNDATION_APPSVR" \
ARMOR_PASS="$ARMOR_PASS" \
NODE_HOST="$NODE_HOST" \
GRPC_PORT="$GRPC_PORT" \
python3 - <<'PY'
import os, re, sys

env_path = os.environ["ENV_FILE"]
dry      = os.environ["DRY_RUN"] == "1"

# Parse the generated block into VAR -> raw assignment line.  Only lines of the form
# VAR='...' count; the block's comments and headers are not carried into the env file, which has
# its own section structure that must survive.
pairs = {}
for line in open(os.environ["BLOCK"], encoding="utf-8"):
    m = re.match(r"^([A-Z][A-Z0-9_]*)='([^']*)'\s*$", line)
    if m:
        pairs[m.group(1)] = line.rstrip("\n")

for var in ("QADENA_FOUNDATION_USERS_ADDRESS", "QADENA_FOUNDATION_APPSVR_ADDRESS"):
    val = os.environ.get(var.replace("QADENA_FOUNDATION_", "FOUNDATION_").replace("_ADDRESS", ""), "")
    if val:
        pairs[var] = f"{var}={val}"

# Not base64 and not a key, but it is the thing that DECRYPTS the keys above -- so it belongs in
# the same atomic edit as they do: a run that updated the keys and left the old passphrase would
# produce an app that cannot start.
_armor = os.environ.get("ARMOR_PASS", "")
if _armor:
    pairs["ARMOR_PASS_PHRASE"] = f"ARMOR_PASS_PHRASE={_armor}"

# UNQUOTED, matching how this file already writes the host and the addresses.  Both names take the
# same value: PIONEER_IP is what the app dials, PUBLIC_HOST what it advertises, and a deployment
# where those disagree works until something follows the advertised address.
_host = os.environ.get("NODE_HOST", "")
if _host:
    pairs["QADENA_PIONEER_IP"]  = f"QADENA_PIONEER_IP={_host}"
    pairs["QADENA_PUBLIC_HOST"] = f"QADENA_PUBLIC_HOST={_host}"
_grpc = os.environ.get("GRPC_PORT", "")
if _grpc:
    pairs["QADENA_GRPC_PORT"] = f"QADENA_GRPC_PORT={_grpc}"

if not pairs:
    sys.exit("error: the generated block contained no assignments")

lines = open(env_path, encoding="utf-8").read().split("\n")

# REPLACE IN PLACE, PRESERVING POSITION.  An env file's ordering is meaningful to the humans who
# read it (sections, comments explaining a value), and appending a second definition of a variable
# that already exists is worse than useless: the LAST assignment wins in most loaders, so a
# stale-looking line above the real one is a permanent trap for the next reader.
seen, changed, added = set(), [], []
for i, line in enumerate(lines):
    m = re.match(r"^\s*([A-Z][A-Z0-9_]*)=", line)
    if not m:
        continue
    var = m.group(1)
    if var not in pairs:
        continue
    if var in seen:
        # A DUPLICATE ALREADY EXISTED.  Comment it rather than delete it: something put it there,
        # and silently dropping a line from a deployment config is not this script's call.
        lines[i] = "# patch_env_file: superseded duplicate -- " + line
        continue
    seen.add(var)
    if lines[i] != pairs[var]:
        lines[i] = pairs[var]
        changed.append(var)

for var, line in pairs.items():
    if var not in seen:
        added.append(var)

if added:
    # Appended together with a header, so a later reader can see these arrived as a group and
    # were not hand-edited one at a time.
    lines.append("")
    lines.append("# --- added by patch_env_file.sh ---")
    for var in added:
        lines.append(pairs[var])

if not dry:
    with open(env_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

# NEVER PRINT A VALUE.  Byte counts are enough to tell a real key from a truncated paste, and are
# safe in a terminal log.
def size(v):
    return len(pairs[v].split("=", 1)[1].strip("'"))

for var in sorted(changed):
    print(f"  updated  {var}  ({size(var)} bytes)")
for var in sorted(added):
    print(f"  ADDED    {var}  ({size(var)} bytes)")
unchanged = sorted(set(pairs) - set(changed) - set(added))
for var in unchanged:
    print(f"  same     {var}")
print(f"\n  {len(changed)} updated, {len(added)} added, {len(unchanged)} already correct")
PY

if [ "$DRY_RUN" -eq 1 ]; then
	echo ""
	echo "DRY RUN -- nothing written (source $ENV_FILE only read; would write $OUT)."
	exit 0
fi

chmod 600 "$OUT" 2>/dev/null || true
echo ""
if [ "$IN_PLACE" -eq 1 ]; then
	echo "  patched:  $OUT  (mode 600, IN PLACE)"
	echo "  backup:   $BACKUP"
else
	# NAME BOTH. The source is the record of what was deployed FROM; the output is the thing
	# with the keys in it. Printing only one leaves an operator guessing which to copy.
	echo "  source:   $ENV_FILE  (unmodified)"
	echo "  written:  $OUT  (mode 600)"
fi
echo ""
echo "THIS FILE NOW CONTAINS ARMORED PRIVATE KEYS.  Whoever holds"
echo "SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY can sign as every pooled sponsor wallet."
if [ -n "$BACKUP" ]; then
	echo "Do not commit it, and delete the backup once the deployment is confirmed:"
	echo "    rm -f $BACKUP"
else
	echo "Do not commit it.  It lives in the deployment home beside mnemonics.json and"
	echo "the rendered CloudFormation copy, which is where this deployment's secrets belong."
fi
