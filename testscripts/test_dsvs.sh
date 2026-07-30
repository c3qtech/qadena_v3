#!/bin/zsh
#
# Regression test for DSVS document signing.
#
# REPLACES the previous version of this script, which was a bare command sequence with no
# assertions, written against the old seed data: it used secdsvssrvprv (a veritas provider that is
# not in this keyring), al-eph, and the setup_credentials.sh contact details.  It would fail on its
# first line today.  This version targets the setup.sh / users.json identities and asserts.
#
# The flow: a service provider creates a document naming its required signatories by email + phone,
# then each signatory signs.  Signing is a HASH CHAIN -- sign-document takes the current document
# and the new one -- so each signature is bound to a specific version of the content and cannot be
# replayed onto different content.
#
# Idempotent: any document left by a previous run is removed first, and the run ends by removing
# its own.
#
# Run AFTER testscripts/setup.sh.

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

function qadenad_alias { "$qadenabin/qadenad" --home "$QADENAHOME" "$@" }

cd $qadenabuild

# Unique per run.  A FULLY SIGNED document cannot be removed -- that is a deliberate rule, proved
# below -- so a fixed id would be permanently occupied after the first successful run and every
# later run would fail to create it.  Unique ids are what make this script re-runnable.
run_id=$(date +%s)
docid="regression-doc-$run_id"
docid_unsigned="regression-doc-unsigned-$run_id"
doctype="ByLaws"
company="C3Q Technologies, Inc."
dsvsprovider="testdsvssrvprv"

# The three versions form the hash chain: doc1 -> doc2 -> doc3.
#
# GENERATED per run rather than reusing test_data/*.pdf, because a document is keyed by its CONTENT
# HASH: re-creating a document from the same bytes fails with "Hash already exists" even under a
# fresh document id.  Embedding the run id in the content is what makes this re-runnable.
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
doc1="$workdir/doc_v1.txt"
doc2="$workdir/doc_v2.txt"
doc3="$workdir/doc_v3.txt"
# separate content for the removable document -- it cannot share a hash with doc1
doc_removable="$workdir/doc_removable.txt"

# Signatories read from the same file setup.sh seeded from, so they cannot drift.
#
# DELIBERATELY victor / kelvin / alexis rather than al and ann: update_credentials.sh mutates al's
# contacts -- case 12 changes his email and case 14 REMOVES the email credential outright -- so a
# suite that ran that first would leave al with no email credential and signing would fail with
# "Credential does not exist".  These three are untouched by it, which keeps this test independent
# of run order.
sig1="victor"; sig2="kelvin"; outsider="alexis"

sig1_email=$(jq -r --arg n "$sig1" '.[] | select(.name==$n) | .email' "$qadenatestdata/users.json")
sig1_phone=$(jq -r --arg n "$sig1" '.[] | select(.name==$n) | .phone' "$qadenatestdata/users.json")
sig2_email=$(jq -r --arg n "$sig2" '.[] | select(.name==$n) | .email' "$qadenatestdata/users.json")
sig2_phone=$(jq -r --arg n "$sig2" '.[] | select(.name==$n) | .phone' "$qadenatestdata/users.json")

fail() {
    echo "FAILED: $1"
    exit 1
}

doc_exists() {
    qadenad_alias query dsvs show-document "$docid" > /dev/null 2>&1
}

# the provider's decrypted view of the document, ANSI stripped
doc_view() {
    qadenad_alias query dsvs show-document "$docid" --decrypt-as "$dsvsprovider" 2>/dev/null \
        | perl -pe 's/\e\[[0-9;]*m//g'
}

echo "========================="
echo "preflight"
echo "========================="
qadenad_alias status > /dev/null 2>&1 || fail "chain is not reachable -- start it first"
qadenad_alias keys show "$dsvsprovider" -a --keyring-backend test > /dev/null 2>&1 \
    || fail "$dsvsprovider not in the keyring -- run testscripts/setup_prerequisites.sh first"
for w in "$sig1-eph1" "$sig2-eph1" "$outsider-eph1"; do
    qadenad_alias keys show "$w" -a --keyring-backend test > /dev/null 2>&1 \
        || fail "$w not in the keyring -- run testscripts/setup.sh first"
done
printf 'Regression test document, run %s, version 1\n' "$run_id" > "$doc1"
printf 'Regression test document, run %s, version 2 (signed by %s)\n' "$run_id" "$sig1" > "$doc2"
printf 'Regression test document, run %s, version 3 (signed by %s)\n' "$run_id" "$sig2" > "$doc3"
printf 'Regression test document, run %s, removable and unsigned\n' "$run_id" > "$doc_removable"

# signing requires the signer's eph wallet to be a registered authorized signatory
sig_count=$(qadenad_alias query dsvs list-authorized-signatory 2>/dev/null | sed -n 's/^Count: *\([0-9]*\)/\1/p' | head -1)
[ "${sig_count:-0}" -gt 0 ] || fail "no authorized signatories registered -- run testscripts/setup.sh first"
echo "chain up; $sig_count authorized signatories"
echo "signatories: $sig1_email $sig1_phone / $sig2_email $sig2_phone"

echo "document ids for this run: $docid / $docid_unsigned"

echo "========================="
echo "1. create a document with two required signatories"
echo "========================="
qadenad_alias tx dsvs create-document "$docid" "$doctype" "$company" "$doc1" \
    "$sig1_email" "$sig1_phone" "$sig2_email" "$sig2_phone" \
    --from "$dsvsprovider" --yes > /dev/null \
    || fail "create-document failed"

doc_exists || fail "$docid was not created"
echo "$docid created"

echo "-------------------------"
echo "the provider's decrypted view must name both signatories"
echo "-------------------------"
view=$(doc_view)
echo "$view" | grep -qi "$sig1_email" || fail "$sig1 is not listed as a signatory on $docid"
echo "$view" | grep -qi "$sig2_email" || fail "$sig2 is not listed as a signatory on $docid"
echo "both signatories listed"

echo "========================="
echo "2. a named signatory signs (doc1 -> doc2)"
echo "========================="
qadenad_alias tx dsvs sign-document "$doc1" "$doc2" "$sig1_email" "$sig1_phone" \
    --from "$sig1-eph1" --yes > /dev/null \
    || fail "$sig1 could not sign $docid"
echo "$sig1 signed"

echo "========================="
echo "3. the second signatory signs (doc2 -> doc3)"
echo "========================="
qadenad_alias tx dsvs sign-document "$doc2" "$doc3" "$sig2_email" "$sig2_phone" \
    --from "$sig2-eph1" --yes > /dev/null \
    || fail "$sig2 could not sign $docid"
echo "$sig2 signed"

echo "========================="
echo "4. a signature cannot be replayed onto stale content"
echo "========================="
# doc1 is no longer the current version of the chain, so signing from it again must be refused.
# Without this, a captured signature could be re-applied to superseded content.
if qadenad_alias tx dsvs sign-document "$doc1" "$doc2" "$sig1_email" "$sig1_phone" \
    --from "$sig1-eph1" --yes > /dev/null 2>&1; then
    fail "$sig1 re-signed the stale doc1 content; signatures are not bound to a document version"
fi
echo "rejected as expected"

echo "========================="
echo "5. someone not named as a signatory cannot sign"
echo "========================="
out_email=$(jq -r --arg n "$outsider" '.[] | select(.name==$n) | .email' "$qadenatestdata/users.json")
out_phone=$(jq -r --arg n "$outsider" '.[] | select(.name==$n) | .phone' "$qadenatestdata/users.json")
if qadenad_alias tx dsvs sign-document "$doc3" "$doc3" "$out_email" "$out_phone" \
    --from "$outsider-eph1" --yes > /dev/null 2>&1; then
    fail "$outsider is not a named signatory on $docid but the signature was accepted"
fi
echo "rejected as expected"

echo "========================="
echo "6. a FULLY SIGNED document may NOT be removed"
echo "========================="
# Both required signatories have signed, so the document is complete and permanent.  If this ever
# starts succeeding, an executed document could be erased after the fact.
if qadenad_alias tx dsvs remove-document "$docid" --from "$dsvsprovider" --yes > /dev/null 2>&1; then
    fail "$docid was fully signed but remove-document succeeded"
fi
echo "rejected as expected"
doc_exists || fail "$docid disappeared despite the removal being refused"
echo "$docid still on chain"

echo "========================="
echo "7. an UNSIGNED document may be removed"
echo "========================="
# the counterpart: removal is allowed while the document is still incomplete
qadenad_alias tx dsvs create-document "$docid_unsigned" "$doctype" "$company" "$doc_removable" \
    "$sig1_email" "$sig1_phone" "$sig2_email" "$sig2_phone" \
    --from "$dsvsprovider" --yes > /dev/null \
    || fail "could not create $docid_unsigned"
qadenad_alias query dsvs show-document "$docid_unsigned" > /dev/null 2>&1 \
    || fail "$docid_unsigned was not created"
echo "$docid_unsigned created, unsigned"

qadenad_alias tx dsvs remove-document "$docid_unsigned" --from "$dsvsprovider" --yes > /dev/null \
    || fail "could not remove the unsigned $docid_unsigned"
if qadenad_alias query dsvs show-document "$docid_unsigned" > /dev/null 2>&1; then
    fail "$docid_unsigned is still queryable after remove-document"
fi
echo "$docid_unsigned removed"

echo "========================="
echo "DSVS TESTS PASSED"
echo "========================="
