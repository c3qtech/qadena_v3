package keeper_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The debug attestation the test harness verifies against.  c.DebugVerifyRemoteReport splits the
// gunzipped report on ":" and checks r[0] == "TRUST-ME" and r[3] == sha256hex(certifyData); the
// handler then requires an EnclaveIdentity row matching r[1]/r[2] with ActiveStatus.
//
// Built here rather than mocked so the tests exercise the REAL gate: every case below produces a
// report that genuinely verifies, which is the point -- the authorization checks must reject
// messages whose attestation is perfectly valid.  That is exactly the attacker's position: a node
// running a trusted measurement, saying something it has no right to say.
const (
	testUniqueID = "test-unique-id"
	testSignerID = "test-signer-id"
)

func debugRemoteReport(t *testing.T, certifyData string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(certifyData))
	plain := strings.Join([]string{
		"TRUST-ME", testUniqueID, testSignerID, hex.EncodeToString(sum[:]), "",
	}, ":")

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(plain))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// pioneerRowMsg builds a message whose attestation covers exactly the five fields the handler
// re-joins, so the only thing under test is the authorization that follows.
func pioneerRowMsg(t *testing.T, creator, pubKID, nodeID, nodeType, ip string) *types.MsgPioneerUpdateIntervalPublicKeyID {
	t.Helper()
	report := debugRemoteReport(t, strings.Join([]string{creator, pubKID, nodeID, nodeType, ip}, "|"))
	return types.NewMsgPioneerUpdateIntervalPublicKeyID(creator, pubKID, nodeID, nodeType, ip, report)
}

// setupRowTest returns a context with an Active enclave identity registered, which every message
// below needs to clear attestation.
func setupRowTest(t *testing.T) (types.MsgServer, sdk.Context) {
	t.Helper()
	k, ms, goCtx := setupMsgServer(t)
	ctx := testCtx(goCtx)
	k.SetEnclaveIdentityNoEnclave(ctx, types.EnclaveIdentity{
		UniqueID: testUniqueID,
		SignerID: testSignerID,
		Status:   types.ActiveStatus,
	})
	return ms, ctx
}

// A pioneer registering for the first time is first-come: before the row exists there is no
// consensus-safe notion of who owns pioneer N.
func TestPioneerRowFirstWriteIsAccepted(t *testing.T) {
	ms, ctx := setupRowTest(t)

	msg := pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.1")
	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx, msg)
	require.NoError(t, err)
}

// THE CASE THIS CHANGE EXISTS FOR: a node may move its OWN address.  Creator == the stored PubKID,
// which for a Pioneer row is the same bech32 string, so the ordinary transaction signature is the
// possession proof.
func TestPioneerRowSelfUpdateMovesTheAddress(t *testing.T) {
	ms, ctx := setupRowTest(t)

	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.1"))
	require.NoError(t, err)

	_, err = ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.99"))
	require.NoError(t, err)
}

// THE SECURITY FIX.  Bob's enclave is genuinely attested -- the report verifies, the measurement is
// Active -- and he is still refused, because the row is Alice's.  Left unchecked this repoints
// share-fetch and who-has traffic at a host of the attacker's choosing.
func TestPioneerRowCrossNodeUpdateIsRejected(t *testing.T) {
	ms, ctx := setupRowTest(t)

	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.1"))
	require.NoError(t, err)

	// Bob names himself as creator but targets Alice's row.
	_, err = ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "bob", "bob", "pioneer1", types.PioneerNodeType, "6.6.6.6"))
	require.ErrorIs(t, err, types.ErrNotRowOwner)
}

// An empty address means "no opinion".  AddAsValidator and SyncEnclave both publish Pioneer rows
// with an empty ExternalIPAddress, and SetIntervalPublicKeyID overwrites unconditionally -- so
// without the carry-forward a re-sync silently drops a healthy pioneer out of
// getAddressPublishedPioneers, shrinking the set getThreshold is computed from.
func TestPioneerRowEmptyAddressDoesNotEraseTheStoredOne(t *testing.T) {
	k, ms, goCtx := setupMsgServer(t)
	ctx := testCtx(goCtx)
	k.SetEnclaveIdentityNoEnclave(ctx, types.EnclaveIdentity{
		UniqueID: testUniqueID, SignerID: testSignerID, Status: types.ActiveStatus,
	})

	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.1"))
	require.NoError(t, err)

	_, err = ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, ""))
	require.NoError(t, err)

	row, found := k.GetIntervalPublicKeyID(ctx, "pioneer1", types.PioneerNodeType)
	require.True(t, found)
	require.Equal(t, "10.0.0.1", row.ExternalIPAddress, "an empty address must not erase the stored one")
}

// Fields the message does not carry must survive an address-only update.  ServiceProviderType and
// HomePioneerID were already carried forward; PreviousPubKID is derived by SetIntervalPublicKeyID.
func TestPioneerRowUpdatePreservesCarriedFields(t *testing.T) {
	k, ms, goCtx := setupMsgServer(t)
	ctx := testCtx(goCtx)
	k.SetEnclaveIdentityNoEnclave(ctx, types.EnclaveIdentity{
		UniqueID: testUniqueID, SignerID: testSignerID, Status: types.ActiveStatus,
	})

	k.SetIntervalPublicKeyID(ctx, types.IntervalPublicKeyID{
		PubKID:              "alice",
		NodeID:              "pioneer1",
		NodeType:            types.PioneerNodeType,
		ExternalIPAddress:   "10.0.0.1",
		ServiceProviderType: "ekyc-srv-prv",
		HomePioneerID:       "pioneer-home",
	})

	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.99"))
	require.NoError(t, err)

	row, found := k.GetIntervalPublicKeyID(ctx, "pioneer1", types.PioneerNodeType)
	require.True(t, found)
	require.Equal(t, "10.0.0.99", row.ExternalIPAddress)
	require.Equal(t, "ekyc-srv-prv", row.ServiceProviderType)
	require.Equal(t, "pioneer-home", row.HomePioneerID)
}

// The shared rows have no per-node owner, so the check is that the creator is a registered pioneer
// at all -- resolved through the same reverse index AuthenticateServiceProvider uses.
func TestSharedRowFromRegisteredPioneerIsAccepted(t *testing.T) {
	ms, ctx := setupRowTest(t)

	// Alice's Pioneer row is what makes her a registered pioneer.  InitEnclave broadcasts it
	// earlier in the same transaction than the SS row, so this ordering is the real one.
	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.1"))
	require.NoError(t, err)

	_, err = ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "alice", "ss-key-1", types.SSNodeID, types.SSNodeType, ""))
	require.NoError(t, err)
}

// An attested enclave that is not a pioneer cannot rewrite the SS row -- the check tx.proto has
// aspired to in a comment since it was written.
func TestSharedRowFromNonPioneerIsRejected(t *testing.T) {
	ms, ctx := setupRowTest(t)

	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx,
		pioneerRowMsg(t, "mallory", "ss-key-evil", types.SSNodeID, types.SSNodeType, ""))
	require.ErrorIs(t, err, types.ErrCreatorNotPioneer)
}

// Attestation still comes first: a report that does not cover these exact fields is refused before
// any authorization question is asked.
func TestRowRejectedWhenAttestationDoesNotCoverTheFields(t *testing.T) {
	ms, ctx := setupRowTest(t)

	msg := pioneerRowMsg(t, "alice", "alice", "pioneer1", types.PioneerNodeType, "10.0.0.1")
	msg.ExternalIPAddress = "10.0.0.99" // no longer what the report certifies
	_, err := ms.PioneerUpdateIntervalPublicKeyID(ctx, msg)
	require.ErrorIs(t, err, types.ErrInvalidEnclave)
}
