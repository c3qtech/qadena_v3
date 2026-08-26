package keeper

// Where the supervisor looks for its children, and why the answer must be the same everywhere.
//
// qadenad, qadenad_enclave and signer_enclave are ONE artifact set -- the enclave carries most of
// the consensus-relevant logic, so a chain binary driving an enclave from a different build is a
// node that disagrees with itself while every process looks healthy.  Resolving children from the
// node home made that set splittable, and a staged-upgrade layout (cosmovisor swaps
// <upgrade>/bin/qadenad and nothing else) would split it on every upgrade.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// selfDir is the directory the resolver will look in: the running test binary's, with symlinks
// resolved exactly as enclaveBinPath resolves them.  On macOS the temp dir behind a test binary is
// reached through /var -> /private/var, so comparing unresolved paths fails for the wrong reason.
func selfDir(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}
	return filepath.Dir(self)
}

func TestEnclaveBinPathPrefersASibling(t *testing.T) {
	sib := filepath.Join(selfDir(t), "qadenad_enclave")
	if err := os.WriteFile(sib, []byte("not a real binary"), 0o755); err != nil {
		t.Skipf("cannot write beside the test binary (%v) -- the sibling path cannot be exercised here", err)
	}
	t.Cleanup(func() { os.Remove(sib) })

	// A node home that certainly exists is passed deliberately: the sibling must win even when the
	// fallback is perfectly usable, or an upgrade would keep resolving the old enclave.
	got, isSibling := enclaveBinPath(t.TempDir(), "qadenad_enclave")

	require.True(t, isSibling, "a binary beside the running qadenad must be preferred")
	require.Equal(t, sib, got)
}

// THE FALLBACK IS NOT COSMETIC: existing installs keep binaries in $HOME/qadena/bin while qadenad
// may be invoked from anywhere, so a sibling-only lookup would break every current deployment on
// the first restart.
func TestEnclaveBinPathFallsBackToTheNodeHome(t *testing.T) {
	home := t.TempDir()

	got, isSibling := enclaveBinPath(home, "definitely-not-installed-beside-us")

	require.False(t, isSibling)
	require.Equal(t, filepath.Join(home, "bin", "definitely-not-installed-beside-us"), got)
}

// EnclaveRealMode inspects the enclave binary for an ego signature and has no logger, so it takes
// the resolver's silent half.  If it disagreed with the spawn path the node could test one binary
// and execute another -- deciding "debug enclave" about a signed one, or the reverse.
func TestEnclaveRealModeUsesTheSameBinaryAsSpawn(t *testing.T) {
	home := t.TempDir()

	fromResolver, _ := enclaveBinPath(home, "qadenad_enclave")
	sib := filepath.Join(selfDir(t), "qadenad_enclave")

	if _, err := os.Stat(sib); err == nil {
		require.Equal(t, sib, fromResolver, "with a sibling present, both callers must see the sibling")
	} else {
		require.Equal(t, filepath.Join(home, "bin", "qadenad_enclave"), fromResolver)
	}
}
