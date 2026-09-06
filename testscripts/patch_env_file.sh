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
DRY_RUN=0

usage() {
	cat <<'EOF'
Usage: patch_env_file.sh <prefix> <env-file> [options]

  <prefix>      the leading component of the .base64 FILENAMES: sec, ekycph, ...
                (the VARIABLE names are always SEC_*; see gen_key_env_vars.sh)
  <env-file>    an EXISTING env file to patch in place

Options:
  --key-dir <dir>    where the *.base64 files are (default: the current directory)
  --sponsors <file>  also set QADENA_FOUNDATION_USERS_ADDRESS and
                     QADENA_FOUNDATION_APPSVR_ADDRESS from a veritas-sponsors.json
                     (written by sec_veritas_before_step_1.sh --stage prepare)
  --dry-run          report what would change; write nothing

  A timestamped backup is written beside the env file before anything is modified.
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
	FOUNDATION_USERS=$(jq -r '.users  // empty' "$SPONSORS")
	FOUNDATION_APPSVR=$(jq -r '.appsvr // empty' "$SPONSORS")
	[ -n "$FOUNDATION_USERS" ] && [ -n "$FOUNDATION_APPSVR" ] || {
		echo "error: $SPONSORS has no .users/.appsvr -- is it a veritas-sponsors.json?" >&2
		exit 1
	}
	echo "foundation from $SPONSORS:"
	echo "  users  $FOUNDATION_USERS"
	echo "  appsvr $FOUNDATION_APPSVR"
fi

BACKUP="${ENV_FILE}.bak.$(date -u '+%Y%m%dT%H%M%SZ')"
if [ "$DRY_RUN" -eq 0 ]; then
	cp -p "$ENV_FILE" "$BACKUP"
	chmod 600 "$BACKUP" 2>/dev/null || true
fi

DRY_RUN="$DRY_RUN" \
ENV_FILE="$ENV_FILE" \
BLOCK="$BLOCK" \
FOUNDATION_USERS="$FOUNDATION_USERS" \
FOUNDATION_APPSVR="$FOUNDATION_APPSVR" \
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
	echo "DRY RUN -- $ENV_FILE was not modified."
	exit 0
fi

chmod 600 "$ENV_FILE" 2>/dev/null || true
echo ""
echo "  patched:  $ENV_FILE  (mode 600)"
echo "  backup:   $BACKUP"
echo ""
echo "THIS FILE NOW CONTAINS ARMORED PRIVATE KEYS.  Whoever holds"
echo "SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY can sign as every pooled sponsor wallet."
echo "Do not commit it, and delete the backup once the deployment is confirmed:"
echo "    rm -f $BACKUP"
