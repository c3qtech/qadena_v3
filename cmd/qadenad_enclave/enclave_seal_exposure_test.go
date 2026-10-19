package main

// VERIFICATION: can THIS build open a node's sealed enclave params?
//
// The point is to confirm, on the operator's own node, what the threat-model discussion established:
// enclave_params_<uid>.json is sealed with the PRODUCT key (MRSIGNER + product id), not the build
// (MRENCLAVE), so any enclave signed with the same key -- and that key ships in the repo -- opens it.
// A green result here is EVIDENCE for prioritising the sealing fix (release key out of the repo,
// and/or unique-key sealing), not an end in itself.
//
// IT PRINTS NOTHING SECRET.  Success is reported as a boolean plus REDACTED structure: which fields
// are present and their byte lengths, never a key, a share, or a secret.  That is all the proof the
// exposure needs; dumping the plaintext would only copy secrets somewhere new.
//
// HOW TO RUN IT, against a real node's file:
//
//	debug build:   QADENA_PARAMS_FILE=~/qadena/enclave_config/enclave_params_<uid>.json \
//	                 go test ./cmd/qadenad_enclave/ -run TestSealExposure -v
//	real SGX:      the same, but it must run INSIDE an ego enclave signed with the build's key --
//	                 i.e. `ego test` with this package's enclave signer -- or Unseal returns an error
//	                 for a reason that says nothing about the exposure.  Running it on the SAME CPU
//	                 that sealed the file is required either way (product keys are CPU-bound).
//
// With no QADENA_PARAMS_FILE set it round-trips a seal it writes itself, so the suite still exercises
// the path without reaching for anyone's real state.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// redactedParamsReport describes what was recovered WITHOUT disclosing any of it.
func redactedParamsReport(t *testing.T, ep storedEnclaveParams) {
	t.Helper()
	p := ep.PrivateEnclaveParams
	present := func(name string, n int) {
		// length only -- a byte count discloses nothing about a key's value.
		t.Logf("  recovered %-28s %s (%d bytes)", name, map[bool]string{true: "PRESENT", false: "absent"}[n > 0], n)
	}
	t.Log("UNSEALED the params with this build's key -- redacted inventory of what that exposed:")
	present("pioneerID", len(p.PioneerID))
	present("enclave private key", len(p.EnclavePrivK))
	present("pioneer private key", len(p.PioneerPrivK))
	present("sealed-table shared secret", len(p.SealedTableSharedSecret))
	present("jar private key", len(ep.SharedEnclaveParams.JarPrivK))
	present("regulator private key", len(ep.SharedEnclaveParams.RegulatorPrivK))
	present("SS owner records", len(ep.SharedEnclaveParams.SSIntervalOwners.GetPioneers()))
	t.Log("  (none of the above values are printed -- presence and length are the whole proof)")
}

func TestSealExposure(t *testing.T) {
	s := newTestEnclaveServer(t)

	path := os.Getenv("QADENA_PARAMS_FILE")
	if path == "" {
		// No real file named: prove the round-trip against one we seal ourselves, so the test is
		// self-contained and still covers the unseal path.
		dir := withSealedParamsDir(t, s)
		s.setPrivateEnclaveParamsPioneerInfo("pioneer-x", "wallet-x", "", "priv-x", "pub-x")
		s.setPrivateEnclaveParamsEnclaveInfo("armor-x", "epriv-x", "epub-x")
		s.setPrivateEnclaveParamsSealedTableSharedSecret([]byte("0123456789abcdef0123456789abcdef"))
		require.True(t, s.writeEnclaveParams())
		path = dir
		t.Logf("no QADENA_PARAMS_FILE set -- round-tripping a params file this test sealed at %s", path)
	} else {
		t.Logf("attempting to open operator-supplied sealed params: %s", path)
	}

	sealed, err := os.ReadFile(path)
	require.NoError(t, err, "cannot read the params file")

	// The one line that matters: can this build's key open it?  On a debug build Unseal strips the
	// signer-id prefix; on a real enclave it is ecrypto.Unseal under the product key.
	plain, err := s.Unseal(sealed)
	if err != nil {
		t.Fatalf("EXPOSURE NOT DEMONSTRATED HERE: this build could not unseal %s: %v\n"+
			"  (on real SGX this is expected UNLESS the test runs inside an enclave signed with the\n"+
			"   build's key, on the CPU that sealed the file -- see the file header)", path, err)
	}

	var ep storedEnclaveParams
	require.NoError(t, json.Unmarshal(plain, &ep), "unsealed, but the bytes are not storedEnclaveParams")

	redactedParamsReport(t, ep)
	t.Log("RESULT: a build carrying the repo signing key opened this node's sealed params.")
}
