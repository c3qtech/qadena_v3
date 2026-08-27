package keeper

// The adoption guard: liveness alone is not identity.  The one situation that reliably produces a
// live enclave socket at startup is a node that died without signalling its children -- the
// upgrade-height panic -- so the enclave most likely to be answering is the PREVIOUS build's.
// These tests drive the two probes the guard is built from against a fake enclave on a real unix
// socket, and a fake debug binary on disk, so the wiring (not just the comparison) is exercised.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

type fakeMeasurementEnclave struct {
	types.UnimplementedQadenaEnclaveServer
	uniqueID string
}

func (f *fakeMeasurementEnclave) QueryEnclaveMeasurement(_ context.Context, _ *types.QueryEnclaveMeasurementRequest) (*types.QueryEnclaveMeasurementResponse, error) {
	return &types.QueryEnclaveMeasurementResponse{UniqueID: f.uniqueID, SignerID: "signer-test"}, nil
}

// withFakeEnclaveSocket serves the fake on the EXACT path runningEnclaveUniqueID dials
// (/tmp/qadena_<port>.sock), on a test-only port so a real enclave on 50051 is never touched.
func withFakeEnclaveSocket(t *testing.T, uniqueID string) {
	t.Helper()
	oldPort := DefaultPort
	DefaultPort = 50951 + (os.Getpid() % 100) // avoid collisions between parallel packages
	sock := fmt.Sprintf("/tmp/qadena_%d.sock", DefaultPort)
	os.Remove(sock)

	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := grpc.NewServer()
	types.RegisterQadenaEnclaveServer(srv, &fakeMeasurementEnclave{uniqueID: uniqueID})
	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(func() {
		srv.Stop()
		os.Remove(sock)
		DefaultPort = oldPort
	})
}

func TestRunningEnclaveUniqueIDAsksTheSocket(t *testing.T) {
	withFakeEnclaveSocket(t, "unique777")
	require.Equal(t, "unique777", runningEnclaveUniqueID(2*time.Second))
}

func TestRunningEnclaveUniqueIDUnreachableIsUnknown(t *testing.T) {
	oldPort := DefaultPort
	DefaultPort = 50899 // nothing listens here
	t.Cleanup(func() { DefaultPort = oldPort })
	require.Equal(t, "", runningEnclaveUniqueID(500*time.Millisecond),
		"no socket must read as UNKNOWN, never as a mismatch")
}

// The debug branch execs the binary itself with -unique-id -- the same probe
// install_release.sh's debug_id_of uses.  A shell stub stands in for the enclave binary.
func TestBinaryUniqueIDDebugExec(t *testing.T) {
	home := t.TempDir() // no SGX devices in a test env, so EnclaveRealMode(home) is false
	bin := filepath.Join(t.TempDir(), "qadenad_enclave")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\necho unique888\n"), 0o755))

	require.Equal(t, "unique888", binaryUniqueID(home, bin))
}

func TestBinaryUniqueIDUnreadableIsUnknown(t *testing.T) {
	home := t.TempDir()
	require.Equal(t, "", binaryUniqueID(home, filepath.Join(home, "does-not-exist")),
		"an unreadable binary must read as UNKNOWN -- an enclave predating the probe must not be bricked")
}
