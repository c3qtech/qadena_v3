#!/usr/bin/env bash
#
# Generate the wallet key/username environment variables for env-template-uat
# from the *.base64 files produced on the Qadena machine.
#
# Each .base64 file is expected to hold the base64 encoding of a JSON array --
# either of wallet usernames (*-names.base64) or of armored private keys
# (*-keys.base64). That is exactly what config.go feeds to
# utils.ConvertBase64JsonStringToArray().
#
# Usage:
#   ./gen_key_env_vars.sh [KEY_DIR] [PREFIX] > uat-keys.env
#
#   KEY_DIR defaults to the current directory.
#   PREFIX  defaults to "sec" -- the leading component of the .base64 FILE names,
#           which is what setup_ekycph.sh / setup_enf.sh vary per deployment:
#
#             sec     -> secdsvs-names.base64, sec-create-wallet-sponsor-keys.base64, ...
#             ekycph  -> ekycphdsvs-names.base64, ekycph-create-wallet-sponsor-keys.base64, ...
#
# THE ENVIRONMENT VARIABLE NAMES DO NOT CHANGE WITH THE PREFIX, and that is
# deliberate: the backend reads the same SEC_* variables whichever deployment
# produced the files (see config.go, which binds SEC_DSVS_EPH_USERNAME and
# friends unconditionally).  Only the filenames carry the deployment name.  Do
# not "fix" this by renaming the variables to match the prefix -- that breaks
# every consumer.
#
# The output is written to stdout; progress and validation results go to stderr,
# so redirecting stdout gives you a clean block to paste into env-template-uat.
#
# NOTE: the output contains armored private keys. Do not commit it.

set -euo pipefail

KEY_DIR="${1:-.}"
PREFIX="${2:-sec}"

if [ ! -d "$KEY_DIR" ]; then
	echo "error: '$KEY_DIR' is not a directory" >&2
	exit 1
fi

case "$PREFIX" in
	*/*|"") echo "error: PREFIX must be a bare name like 'sec' or 'ekycph', not '$PREFIX'" >&2; exit 1 ;;
esac

# file stem -> environment variable name.
# Grouped as name/key pairs so the two arrays can be length-checked against
# each other; the section headers mirror the layout of env-template-uat.
# The stems are exactly the wallet names the setup script used, so they follow
# PREFIX; the variables on the right do not.  setup_ekycph.sh sets
# dsvsname=${PREFIX}dsvs, dsvsprovidername=${PREFIX}dsvssrvprv,
# identityprovidername=${PREFIX}identitysrvprv and
# createwalletsponsorname=${PREFIX}-create-wallet-sponsor, and writes
# <name>-names.base64 / <name>-keys.base64 for each -- which is what this table
# reproduces.
MAPPINGS="
# ${PREFIX}dsvs-eph config|${PREFIX}dsvs-names|SEC_DSVS_EPH_USERNAME|${PREFIX}dsvs-keys|SEC_DSVS_EPH_PRIVATE_KEY
# ${PREFIX}dsvssrvprv config|${PREFIX}dsvssrvprv-names|SEC_DSVS_SRV_PRV_USERNAME|${PREFIX}dsvssrvprv-keys|SEC_DSVS_SRV_PRV_PRIVATE_KEY
# ${PREFIX}identitysrvprv config|${PREFIX}identitysrvprv-names|SEC_IDENTITY_SRV_PRV_USERNAME|${PREFIX}identitysrvprv-keys|SEC_IDENTITY_SRV_PRV_PRIVATE_KEY
# pioneer sponsor config|${PREFIX}-create-wallet-sponsor-names|SEC_CREATE_WALLET_SPONSOR_USERNAME|${PREFIX}-create-wallet-sponsor-keys|SEC_CREATE_WALLET_SPONSOR_PRIVATE_KEY
# ${PREFIX}dsvs-eph-credential config|${PREFIX}dsvs-credential-names|SEC_DSVS_EPH_CREDENTIAL_USERNAME|${PREFIX}dsvs-credential-keys|SEC_DSVS_EPH_CREDENTIAL_PRIVATE_KEY
"

# json_length FILE_CONTENT_DECODED -- echoes the number of elements in a JSON
# array, or nothing if no JSON tool is available.
JSON_TOOL=""
if command -v jq >/dev/null 2>&1; then
	JSON_TOOL="jq"
elif command -v python3 >/dev/null 2>&1; then
	JSON_TOOL="python3"
fi

json_length() {
	case "$JSON_TOOL" in
	jq) printf '%s' "$1" | jq -e 'if type == "array" then length else error("not an array") end' 2>/dev/null ;;
	python3) printf '%s' "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(1) if not isinstance(d,list) else print(len(d))' 2>/dev/null ;;
	*) return 0 ;;
	esac
}

# read_b64 FILE -- echoes the file contents with all whitespace stripped, after
# checking that it is valid base64 wrapping a JSON array.
read_b64() {
	file="$1"

	if [ ! -f "$file" ]; then
		echo "error: missing file: $file" >&2
		return 1
	fi

	# base64 output is often line-wrapped; env vars must be a single line.
	content=$(tr -d '[:space:]' <"$file")

	if [ -z "$content" ]; then
		echo "error: empty file: $file" >&2
		return 1
	fi

	decoded=$(printf '%s' "$content" | base64 -d 2>/dev/null) || {
		echo "error: not valid base64: $file" >&2
		return 1
	}

	# Cheap structural check that works without a JSON tool.
	case "$(printf '%s' "$decoded" | tr -d '[:space:]' | cut -c1)" in
	"[") ;;
	*)
		echo "error: decoded content is not a JSON array: $file" >&2
		return 1
		;;
	esac

	printf '%s' "$content"
}

# DERIVED FROM MAPPINGS, NOT LISTED AGAIN.  This check used to repeat all ten
# stems literally, so when the table above gained a PREFIX the check kept looking
# for the "sec" files and refused every other deployment with ten "missing file"
# errors naming files the caller never asked for.  One table, one source of truth.
missing=0
while IFS='|' read -r header name_stem key_stem_var key_stem key_var; do
	[ -z "${header:-}" ] && continue
	for stem in "$name_stem" "$key_stem"; do
		if [ ! -f "$KEY_DIR/$stem.base64" ]; then
			echo "error: missing file: $KEY_DIR/$stem.base64" >&2
			missing=$((missing + 1))
		fi
	done
done <<<"$MAPPINGS"
if [ "$missing" -gt 0 ]; then
	echo "error: $missing file(s) missing from '$KEY_DIR', nothing written" >&2
	exit 1
fi

if [ -z "$JSON_TOOL" ]; then
	echo "warning: neither jq nor python3 found -- skipping array length checks" >&2
fi

echo "# Generated by scripts/gen_key_env_vars.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "# Source: $KEY_DIR (prefix: $PREFIX)"

failures=0
# Fed by here-string rather than a pipe so the loop body runs in this shell and
# the failure count survives.
while IFS='|' read -r header name_stem name_var key_stem key_var; do
	[ -z "${header:-}" ] && continue

	name_b64=$(read_b64 "$KEY_DIR/$name_stem.base64") || {
		failures=$((failures + 1))
		continue
	}
	key_b64=$(read_b64 "$KEY_DIR/$key_stem.base64") || {
		failures=$((failures + 1))
		continue
	}

	# A username array and its key array must line up: the app indexes into both
	# with the same account index.
	name_len=$(json_length "$(printf '%s' "$name_b64" | base64 -d)" || true)
	key_len=$(json_length "$(printf '%s' "$key_b64" | base64 -d)" || true)
	if [ -n "$name_len" ] && [ -n "$key_len" ]; then
		if [ "$name_len" -ne "$key_len" ]; then
			echo "warning: $name_var has $name_len entries but $key_var has $key_len -- these must match" >&2
		else
			echo "ok: $name_var / $key_var ($name_len entries)" >&2
		fi
	fi

	# base64 is [A-Za-z0-9+/=] only, so single quoting is always safe here.
	echo ""
	echo "$header"
	echo ""
	echo "$name_var='$name_b64'"
	echo "$key_var='$key_b64'"
done <<<"$MAPPINGS"

if [ "$failures" -gt 0 ]; then
	echo "error: $failures file(s) could not be read -- output above is incomplete" >&2
	exit 1
fi

exit 0
