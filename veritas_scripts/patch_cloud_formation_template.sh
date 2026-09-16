#!/usr/bin/env bash
#
# Render a CloudFormation template with the wallet keys a bring-up produced, as a NEW FILE.
#
#   ./veritas_scripts/patch_cloud_formation_template.sh sec \
#       veritas_deployment/v2-cloud-formation-ssm-parameters.yaml \
#       --key-dir ~/sec-veritas --out ~/sec-veritas/v2-cloud-formation-ssm-parameters.yaml
#
# THE SOURCE IS NEVER MODIFIED.  It is a tracked file in the app-server repo and belongs to whoever
# maintains it; a populated one is a per-run, per-site artefact holding private keys, which is the
# opposite kind of thing.  Editing in place would also make `git diff` in that repo show a wall of
# key material, and the natural reaction -- checking it out again -- would silently discard the
# populated copy.  So: read the source, write the copy, and hand the copy to `aws cloudformation`.
#
# The env-file twin of this is patch_env_file.sh, and the two share a generator: gen_key_env_vars.sh
# turns the *.base64 files into a block of SEC_* assignments.  patch_env_file.sh writes that block
# into an env file; this writes the same values into the `Value:` of each SSM parameter resource
# whose `Name:` matches, leaving every other line of the template exactly as it found it.
#
# WHY NOT veritas_scripts/generate_aws_template.sh
#
# That script does a related job and is kept, but it is not this one:
#   * it RE-EXTRACTS from the keyring instead of reading the .base64 files, so it needs the keyring
#     and its passphrase on whatever machine renders the template, and can disagree with the files
#     step_3 actually produced;
#   * its provider names are hardcoded `sec*`, so it cannot render ekycph or enf;
#   * it writes a NEW file (veritas-keys-<env>-updated.yaml) rather than patching in place;
#   * its debug block echoes decoded PRIVATE KEYS to stderr.
# This one reads the files, takes the prefix, patches in place, and never prints a key.
#
# WHAT IT WILL NOT DO -- the same three rules patch_env_file.sh follows
#
#   * It never prints a key.  These are ARMORED PRIVATE KEYS: whoever holds
#     SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY can sign as every pooled sponsor wallet.  Progress
#     names parameters and byte counts, never contents.
#   * It never creates the SOURCE, and never edits it.  The output is a separate file.
#   * It never commits.  The OUTPUT contains private keys; the source stays clean.
#
# THE VARIABLE NAMES DO NOT FOLLOW THE PREFIX -- see gen_key_env_vars.sh.  `sec` and `ekycph`
# deployments both write SEC_*, because config.go binds those names unconditionally.  Only the
# FILENAMES carry the prefix.  This script inherits that and must not "fix" it.
#
# WHERE THE .base64 FILES ARE.  step_3 writes them into the DEPLOYMENT'S HOME (--out-dir), so
# --key-dir is normally ~/sec-veritas, ~/ekyc-ph, ~/qadena-enf, plus the site suffix.  They used to
# land in the repo root; that still works if you point --key-dir at it.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# LOOK BESIDE, THEN IN testscripts/.  This script moved from testscripts/ to veritas_scripts/ and
# its generator did not; a bare $SCRIPT_DIR sibling reference then resolved to a path that does not
# exist, and the only symptom was "cannot run .../veritas_scripts/gen_key_env_vars.sh".  Search
# both so either layout works and a future move does not silently break it again.
GEN="$SCRIPT_DIR/gen_key_env_vars.sh"
[ -x "$GEN" ] || GEN="$SCRIPT_DIR/../testscripts/gen_key_env_vars.sh"
[ -x "$GEN" ] || GEN="$SCRIPT_DIR/../scripts/gen_key_env_vars.sh"

PREFIX=""
TEMPLATE=""
KEY_DIR="."
SPONSORS=""
ARMOR_PASSFILE=""
ARMOR_PROMPT=0
OUT=""
BOTH=0
DRY_RUN=0

usage() {
	cat <<'EOF'
Usage: patch_cloud_formation_template.sh <prefix> <template.yaml> [options]

  <prefix>        the leading component of the .base64 FILENAMES: sec, ekycph, enf
                  (the PARAMETER names are always SEC_*; see gen_key_env_vars.sh)
  <template.yaml> the SOURCE CloudFormation template; it is read, never written

Options:
  --key-dir <dir>    where the *.base64 files are (default: the current directory).
                     step_3 writes them into the deployment home, e.g. ~/sec-veritas
  --sponsors <file>  also set QADENA_FOUNDATION_USERS_ADDRESS and
                     QADENA_FOUNDATION_APPSVR_ADDRESS from a <deployment>-sponsors.json
  --armor-passfile <file>
                     also set ARMOR_PASS_PHRASE from this file's first line
  --armor-prompt     ask for it on the terminal instead (hidden, asked twice).
                     Use this rather than writing the deployment's passphrase to
                     a file just to render one template
  --out <file>       where to write the populated copy
                     (default: <key-dir>/<source basename>)
  --both-branches    also write the PRODUCTION branch of each !If.  Default is the
                     non-prod branch only -- the template's own comments warn that its
                     prod values are unreconciled, and rewriting them from a testnet
                     bring-up would point production at testnet wallets.
  --dry-run          report what would change; write nothing
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--key-dir)        KEY_DIR="$2"; shift 2 ;;
	--sponsors)       SPONSORS="$2"; shift 2 ;;
	--armor-passfile) ARMOR_PASSFILE="$2"; shift 2 ;;
	--armor-prompt)   ARMOR_PROMPT=1; shift ;;
	--out)            OUT="$2"; shift 2 ;;
	--both-branches)  BOTH=1; shift ;;
	--dry-run)        DRY_RUN=1; shift ;;
	-h|--help)        usage; exit 0 ;;
	-*)               echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
	*)
		if   [ -z "$PREFIX" ];   then PREFIX="$1"
		elif [ -z "$TEMPLATE" ]; then TEMPLATE="$1"
		else echo "unexpected argument: $1" >&2; usage >&2; exit 1
		fi
		shift ;;
	esac
done

[ -n "$PREFIX" ] && [ -n "$TEMPLATE" ] || { usage >&2; exit 1; }
[ -x "$GEN" ] || { echo "error: cannot run $GEN" >&2; exit 1; }

if [ ! -f "$TEMPLATE" ]; then
	echo "error: $TEMPLATE does not exist." >&2
	echo "  This renders an EXISTING template; it will not invent one." >&2
	exit 1
fi

# DEFAULT THE OUTPUT BESIDE THE KEYS.  --key-dir is the deployment home, which already varies per
# deployment AND per site, so a populated template cannot be confused with another fleet's.
[ -n "$OUT" ] || OUT="${KEY_DIR%/}/$(basename "$TEMPLATE")"
if [ "$(cd "$(dirname "$OUT")" 2>/dev/null && pwd)/$(basename "$OUT")" = \
     "$(cd "$(dirname "$TEMPLATE")" && pwd)/$(basename "$TEMPLATE")" ]; then
	echo "error: --out is the source template; refusing to overwrite it." >&2
	exit 1
fi

BLOCK="$(mktemp)"
trap 'rm -f "$BLOCK"' EXIT
chmod 600 "$BLOCK"

# GENERATE FIRST, PATCH SECOND.  gen_key_env_vars.sh validates that each .base64 decodes to a JSON
# array and that the name and key arrays are the same length; a truncated file fails here, with the
# template still untouched, rather than halfway through the edit.
if ! "$GEN" "$KEY_DIR" "$PREFIX" > "$BLOCK"; then
	echo "error: key generation failed -- $TEMPLATE is untouched" >&2
	exit 1
fi

# The sponsor addresses are PUBLIC, unlike everything else here, so they may be printed.
if [ -n "$SPONSORS" ]; then
	[ -f "$SPONSORS" ] || { echo "error: $SPONSORS does not exist" >&2; exit 1; }
	# TWO FILE SHAPES, ONE PAIR OF FACTS.  The foundation has <deployment>-sponsors.json, written
	# by before_step_1.sh --stage prepare into its COORDINATOR home, with .appsvr/.users.  SEC has
	# no coordinator home at all -- it has variables.json in the deployment home, where step_1
	# recorded the same two addresses as .appsvraddr/.usersaddr.  Whoever renders the template
	# should not have to obtain the other side's file to name addresses they already hold.
	_u=$(jq -r '.users  // .usersaddr  // empty' "$SPONSORS")
	_a=$(jq -r '.appsvr // .appsvraddr // empty' "$SPONSORS")
	[ -n "$_u" ] && [ -n "$_a" ] || {
		echo "error: $SPONSORS names neither .users/.appsvr nor .usersaddr/.appsvraddr." >&2
		echo "  Point --sponsors at either:" >&2
		echo "    <coord>/<deployment>-sponsors.json   (foundation side, from --stage prepare)" >&2
		echo "    <deployment home>/variables.json     (deployment side, written by step_1)" >&2
		exit 1; }
	printf 'QADENA_FOUNDATION_USERS_ADDRESS=%s\n'  "$_u" >> "$BLOCK"
	printf 'QADENA_FOUNDATION_APPSVR_ADDRESS=%s\n' "$_a" >> "$BLOCK"
	echo "  sponsors: users=$_u appsvr=$_a"
fi

if [ -n "$ARMOR_PASSFILE" ] && [ "$ARMOR_PROMPT" -eq 1 ]; then
	echo "error: --armor-passfile and --armor-prompt are alternatives; pass one" >&2
	exit 1
fi
if [ -n "$ARMOR_PASSFILE" ]; then
	[ -r "$ARMOR_PASSFILE" ] || { echo "error: cannot read $ARMOR_PASSFILE" >&2; exit 1; }
	printf 'ARMOR_PASS_PHRASE=%s\n' "$(head -1 "$ARMOR_PASSFILE")" >> "$BLOCK"
elif [ "$ARMOR_PROMPT" -eq 1 ]; then
	# ASKED, NOT FILED.  This passphrase belongs to the DEPLOYMENT's keyring -- whoever ran step_3
	# typed it there -- and requiring a file means writing it to disk on a second machine purely to
	# render a template.  Ask instead; nothing is persisted but the rendered copy.
	#
	# ASKED TWICE, because a typo here is silent and expensive: the template renders fully, every
	# key lands, and the app-server then imports NONE of them and restart-loops reporting an empty
	# reason.  There is no later check that would catch it -- the keys and the passphrase are only
	# tested together at app-server start.
	if [ ! -t 0 ]; then
		echo "error: --armor-prompt needs a terminal.  For an unattended run use" >&2
		echo "       --armor-passfile <file> instead." >&2
		exit 1
	fi
	printf "The DEPLOYMENT's keyring passphrase -- the one typed when step_3 exported these\n" >&2
	printf "keys, NOT the foundation's coordinator passphrase.\n" >&2
	printf "  passphrase (hidden, will not echo): " >&2
	IFS= read -rs _ap; echo "" >&2
	printf "  confirm: " >&2
	IFS= read -rs _ap2; echo "" >&2
	[ "$_ap" = "$_ap2" ] || { echo "error: passphrases do not match" >&2; exit 1; }
	[ -n "$_ap" ] || { echo "error: empty passphrase" >&2; exit 1; }
	printf 'ARMOR_PASS_PHRASE=%s\n' "$_ap" >> "$BLOCK"
	unset _ap _ap2
fi

# The python below edits the file named in TEMPLATE, so point it at the COPY.  On a dry run there
# is no copy and it reads the source without writing.
if [ "$DRY_RUN" -eq 0 ]; then
	mkdir -p "$(dirname "$OUT")"
	cp "$TEMPLATE" "$OUT"
	chmod 600 "$OUT"
	TARGET="$OUT"
else
	TARGET="$TEMPLATE"
fi

BLOCK="$BLOCK" TEMPLATE="$TARGET" DRY_RUN="$DRY_RUN" BOTH_BRANCHES="$BOTH" python3 - <<'PY'
import os, re, sys

block, template = os.environ["BLOCK"], os.environ["TEMPLATE"]
dry  = os.environ["DRY_RUN"] == "1"
both = os.environ.get("BOTH_BRANCHES", "0") == "1"

vals = {}
for line in open(block):
    line = line.rstrip("\n")
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    # STRIP THE ENV-FILE QUOTING.  gen_key_env_vars.sh emits shell assignments -- NAME='<base64>' --
    # because its other consumer is an env file.  YAML needs the bare value: left quoted, it became
    # "'WyJ...=='" in the template, which is a string whose first character is an apostrophe, so
    # base64 decoding fails and the app-server falls back to one garbage key.
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
    vals[k.strip()] = v

lines = open(template).read().split("\n")

# NOT A YAML PARSE.  The template is full of short-form intrinsics -- !Sub, !If, !Join, !Ref -- which
# a plain loader rejects, and a loader that accepts them reorders keys and strips every comment.
# The comments in this template are load-bearing (they record which branch is reconciled), so this
# is a targeted line edit instead.
#
# THE TWO SHAPES THIS FILE ACTUALLY USES -- api/aws/v2-cloud-formation-ssm-parameters.yaml:
#
#   AWS::SSM::Parameter                       AWS::SecretsManager::Secret
#     Name: !Sub ".../SEC_X_USERNAME"           Name: !Sub ".../SEC_X_PRIVATE_KEY"
#     Value: !If                                SecretString: !If
#       - CreateProdResources                     - CreateProdResources
#       - "<base64>"        <- prod               - '{"SEC_X_PRIVATE_KEY": "<base64>"}'
#       - "<base64>"        <- non-prod           - '{"SEC_X_PRIVATE_KEY": "<base64>"}'
#
# The private keys moved OUT of Parameter Store because an SSM value caps at 8192 bytes and the key
# array is ~9.7KB; Secrets Manager allows 65536.  Its SecretString must be exactly one JSON object,
# {"<NAME>": "<base64>"} -- the app takes that field and base64-decodes it.  Wrapping it twice is a
# SILENT failure: the decode error path returns a one-element array holding the raw string, so the
# app boots and runs with a single garbage key instead of thirty.
name_re   = re.compile(r'^(\s*)Name:\s*(?:!Sub\s+)?(?:"([^"]*)"|\'([^\']*)\'|(\S+))\s*$')
holder_re = re.compile(r'^(\s*)(Value|SecretString):\s*(.*)$')
item_re   = re.compile(r'^(\s*)-\s*(.*)$')

def if_branches(start):
    """Indices of the list items under a block-form `!If` whose header is line `start`."""
    base = len(lines[start]) - len(lines[start].lstrip())
    out, j = [], start + 1
    while j < len(lines):
        cur = lines[j]
        if not cur.strip():
            j += 1
            continue
        ind = len(cur) - len(cur.lstrip())
        if ind <= base:
            break
        m = item_re.match(cur)
        if m and ind == (len(item_re.match(lines[start + 1]).group(1))
                         if item_re.match(lines[start + 1]) else ind):
            out.append(j)
        j += 1
    return out

def join_end(idx):
    depth, j = 0, idx
    while j < len(lines):
        depth += lines[j].count("[") - lines[j].count("]")
        if depth <= 0:
            return j
        j += 1
    return idx

updated, skipped, novalue = [], [], []
i = 0
while i < len(lines):
    m = name_re.match(lines[i])
    if not m:
        i += 1
        continue
    indent = len(m.group(1))
    raw = m.group(2) or m.group(3) or m.group(4) or ""
    key = raw.rsplit("/", 1)[-1]
    if key not in vals:
        i += 1
        continue

    j, done = i + 1, False
    while j < len(lines):
        cur = lines[j]
        if cur.strip() and (len(cur) - len(cur.lstrip())) < indent:
            break
        hm = holder_re.match(cur)
        if hm and len(hm.group(1)) == indent:
            holder, rest = hm.group(2), hm.group(3).strip()
            # SecretString wants the JSON-object wrapper; Value wants the bare base64.
            payload = ('\'{"%s": "%s"}\'' % (key, vals[key])) if holder == "SecretString" \
                      else '"%s"' % vals[key]
            if rest == "!If":
                br = if_branches(j)
                # br[0] is the CONDITION NAME, never a value.  br[1] is the true branch
                # (production), br[2] the false branch.
                targets = br[1:] if both else br[2:]
                if not targets:
                    skipped.append((key, j + 1, "!If with no branch to write"))
                else:
                    for t in targets:
                        ind = item_re.match(lines[t]).group(1)
                        lines[t] = "%s- %s" % (ind, payload)
                    updated.append(key)
            elif rest.startswith("!Join"):
                lines[j:join_end(j) + 1] = ['%s%s: !Join [ "", [ %s ] ]'
                                            % (hm.group(1), holder, payload)]
                updated.append(key)
            elif rest.startswith(("|", ">")) or rest == "":
                skipped.append((key, j + 1, rest or "(empty/block)"))
            elif rest.startswith("!"):
                # !Ref / !GetAtt / !ImportValue -- a link to something else, not a literal we own.
                skipped.append((key, j + 1, rest))
            else:
                lines[j] = "%s%s: %s" % (hm.group(1), holder, payload)
                updated.append(key)
            done = True
            break
        j += 1
    if not done:
        novalue.append(key)
    i = j + 1

# THE ARMOR PASSPHRASE IS NEITHER NAMED NOR SHAPED LIKE THE OTHERS.
#
# gen_key_env_vars.sh calls it ARMOR_PASS_PHRASE; the template calls it
#     Name: !Sub /veritas/${EnvType}/Common/qadena-armor-passphrase
# so the last-segment match above never fires.  Its value is also a JSON FIELD inside a `!Sub |`
# block scalar, which the loop skips as an intrinsic.  Both together meant the passphrase was left
# at the template's literal "dummy-passphrase" while every KEY around it was replaced -- and the
# keys are armored WITH that passphrase, so the app-server imports none of them and restart-loops
# reporting an empty reason.  Silent, and caused by patching rather than by not patching.
if "ARMOR_PASS_PHRASE" in vals:
    _ap = vals["ARMOR_PASS_PHRASE"]
    _field = re.compile(r'^(\s*)"qadena-armor-passphrase"\s*:\s*".*"(,?)\s*$')
    _done = False
    for i, l in enumerate(lines):
        m = _field.match(l)
        if m:
            lines[i] = '%s"qadena-armor-passphrase": "%s"%s' % (m.group(1), _ap, m.group(2))
            _done = True
    if _done:
        updated.append("ARMOR_PASS_PHRASE")
        vals.setdefault("ARMOR_PASS_PHRASE", _ap)
    else:
        skipped.append(("ARMOR_PASS_PHRASE", 0, "no qadena-armor-passphrase field in the template"))

if not dry:
    open(template, "w").write("\n".join(lines))

for k in updated:
    print("  updated  %s  (%d bytes)" % (k, len(vals[k])))
for k, ln, what in skipped:
    print("  SKIPPED  %s  line %d: %s -- left as-is" % (k, ln, what))
for k in novalue:
    print("  SKIPPED  %s: found its Name: but no Value:/SecretString: in that mapping" % k)
missing = sorted(set(vals) - set(updated) - set(k for k, _, _ in skipped) - set(novalue))
for k in missing:
    print("  ABSENT   %s: nothing in the template carries that Name:" % k)

print("\n  %d parameter(s) updated, %d available%s"
      % (len(updated), len(vals), "  [BOTH branches]" if both else "  [non-prod branch only]"))
sys.exit(0 if updated else 3)
PY
_rc=$?

if [ "$DRY_RUN" -eq 1 ]; then
	echo "  dry run: nothing written ($TEMPLATE was only read)"
	exit $_rc
fi

if [ $_rc -ne 0 ]; then
	# The half-written copy is the misleading artefact here -- it looks deployable and is not.
	echo "error: no parameters matched -- removing $OUT" >&2
	rm -f "$OUT"
	exit $_rc
fi

echo "  source:   $TEMPLATE  (unchanged)"
echo "  rendered: $OUT"
echo ""
echo "  Deploy it with, e.g.:"
echo "      aws cloudformation deploy --template-file $OUT \\"
echo "          --stack-name <stack> --parameter-overrides EnvType=<env>"
echo ""
echo "  It contains ARMORED PRIVATE KEYS.  Do not commit it."
