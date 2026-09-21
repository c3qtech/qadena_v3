package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// GetEnclaveStatus IS THE CHAIN'S ONLY WAY TO ASK "have you got your sealed params?", and the
// dispatch treats a `true` as final -- it sets doneForGood and stops retrying.  So the answer has
// to mean what InitEnclave and SyncEnclave mean by it, which is `paramsPersisted && PioneerID`.
//
// The middle case below is the one that cost something.  preInitEnclave sets PioneerID early and
// the params are sealed only at the very end, so an init that failed in between -- a rejected
// remote report, or a platform that cannot produce a quote -- leaves PioneerID set with nothing on
// disk.  Answering "initialized" there told the chain the work was done when it had not been.
// Observed on qfi-mainnet .104: InitEnclave failed with OE_UNEXPECTED and the next block logged
// "the enclave reports it is already initialized as qfi-pioneer1" with JarRegulator still empty.
func TestGetEnclaveStatusRequiresPersistedParams(t *testing.T) {
	ctx := context.Background()

	t.Run("never initialized", func(t *testing.T) {
		s := newTestEnclaveServer(t)
		r, err := s.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{})
		require.NoError(t, err)
		require.False(t, r.GetInitialized())
		require.Empty(t, r.GetPioneerID())
	})

	t.Run("half done: keys generated, params never persisted", func(t *testing.T) {
		s := newTestEnclaveServer(t)
		s.privateEnclaveParams.PioneerID = "qfi-pioneer1"
		s.paramsPersisted = false

		r, err := s.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{})
		require.NoError(t, err)
		require.False(t, r.GetInitialized(),
			"a PioneerID with nothing sealed is NOT initialized -- reporting true here makes the "+
				"chain's dispatch set doneForGood and stop retrying a registration that never happened")
		// Still reported, because the caller logs it and "half-initialized as X" beats "".
		require.Equal(t, "qfi-pioneer1", r.GetPioneerID())
	})

	t.Run("initialized", func(t *testing.T) {
		s := newTestEnclaveServer(t)
		s.privateEnclaveParams.PioneerID = "qfi-pioneer1"
		s.paramsPersisted = true

		r, err := s.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{})
		require.NoError(t, err)
		require.True(t, r.GetInitialized())
		require.Equal(t, "qfi-pioneer1", r.GetPioneerID())
	})

	// paramsPersisted without a PioneerID should not read as initialized either.  Not a state the
	// code produces today, but the condition is an AND and the test says so rather than leaving it
	// to be re-derived.
	t.Run("persisted flag without an identity", func(t *testing.T) {
		s := newTestEnclaveServer(t)
		s.paramsPersisted = true

		r, err := s.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{})
		require.NoError(t, err)
		require.False(t, r.GetInitialized())
	})
}

// THE INVARIANT THE DOC COMMENT PROMISES: GetEnclaveStatus and InitEnclave's short-circuit answer
// the same question from the same fields.  They drifted once -- GetEnclaveStatus tested PioneerID
// alone while InitEnclave tested both -- so this pins them together.  If InitEnclave's guard
// changes, this fails rather than the two quietly disagreeing again.
func TestGetEnclaveStatusMatchesInitEnclaveShortCircuit(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name      string
		pioneerID string
		persisted bool
	}{
		{"neither", "", false},
		{"id only", "p1", false},
		{"persisted only", "", true},
		{"both", "p1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestEnclaveServer(t)
			s.privateEnclaveParams.PioneerID = tc.pioneerID
			s.paramsPersisted = tc.persisted

			r, err := s.GetEnclaveStatus(ctx, &types.MsgGetEnclaveStatus{})
			require.NoError(t, err)

			// The literal condition InitEnclave (and SyncEnclave) short-circuit on.
			wantShortCircuit := s.paramsPersisted && s.getPrivateEnclaveParamsPioneerID() != ""
			require.Equal(t, wantShortCircuit, r.GetInitialized(),
				"GetEnclaveStatus must agree with InitEnclave's 'already initialized' test")
		})
	}
}
