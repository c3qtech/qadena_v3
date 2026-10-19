package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	typesproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"
)

const testChain = "test-chain"

func testVote(h int64, r int32, t typesproto.SignedMsgType, blockHash byte, ts time.Time) *typesproto.Vote {
	v := &typesproto.Vote{Type: t, Height: h, Round: r, Timestamp: ts}
	if blockHash != 0 {
		v.BlockID = typesproto.BlockID{
			Hash:          append(make([]byte, 31), blockHash),
			PartSetHeader: typesproto.PartSetHeader{Total: 1, Hash: append(make([]byte, 31), blockHash)},
		}
	}
	return v
}

func freshPV(t *testing.T) (string, ed25519.PrivKey) {
	t.Helper()
	return filepath.Join(t.TempDir(), "signer_state.json"), ed25519.GenPrivKey()
}

// THE POINT: two different votes for the same height/round/step are never both signed.
func TestRefusesConflictingVote(t *testing.T) {
	path, priv := freshPV(t)
	pv, _, err := loadPrivValidator(priv, path)
	require.NoError(t, err)
	ts := time.Unix(1700000000, 0).UTC()

	require.NoError(t, signVote(pv, testChain, testVote(10, 0, typesproto.PrevoteType, 0xAA, ts)))
	err = signVote(pv, testChain, testVote(10, 0, typesproto.PrevoteType, 0xBB, ts))
	require.ErrorContains(t, err, "conflicting data")
}

// A crash between signing and the WAL makes the node ask again.  Identical bytes, or bytes that
// differ only in timestamp, get the SAME signature back -- never a second one -- and no stall.
func TestReSignsTheSameVoteAfterACrash(t *testing.T) {
	path, priv := freshPV(t)
	pv, _, err := loadPrivValidator(priv, path)
	require.NoError(t, err)
	ts := time.Unix(1700000000, 0).UTC()

	first := testVote(10, 0, typesproto.PrecommitType, 0xAA, ts)
	require.NoError(t, signVote(pv, testChain, first))

	// "restart": a new process reading the same state file
	pv2, note, err := loadPrivValidator(priv, path)
	require.NoError(t, err)
	require.Contains(t, note, "height 10")

	again := testVote(10, 0, typesproto.PrecommitType, 0xAA, ts)
	require.NoError(t, signVote(pv2, testChain, again))
	require.Equal(t, first.Signature, again.Signature)

	later := testVote(10, 0, typesproto.PrecommitType, 0xAA, ts.Add(time.Second))
	require.NoError(t, signVote(pv2, testChain, later))
	require.Equal(t, first.Signature, later.Signature, "timestamp-only difference: the old signature")
	require.Equal(t, ts, later.Timestamp, "and the old timestamp")

	require.ErrorContains(t, signVote(pv2, testChain, testVote(10, 0, typesproto.PrecommitType, 0xBB, ts)), "conflicting data",
		"the protection survives the restart")
}

func TestRefusesRegressions(t *testing.T) {
	path, priv := freshPV(t)
	pv, _, err := loadPrivValidator(priv, path)
	require.NoError(t, err)
	ts := time.Unix(1700000000, 0).UTC()

	require.NoError(t, signVote(pv, testChain, testVote(10, 2, typesproto.PrecommitType, 0xAA, ts)))
	require.ErrorContains(t, signVote(pv, testChain, testVote(9, 0, typesproto.PrevoteType, 0xAA, ts)), "height regression")
	require.ErrorContains(t, signVote(pv, testChain, testVote(10, 1, typesproto.PrevoteType, 0xAA, ts)), "round regression")
	require.ErrorContains(t, signVote(pv, testChain, testVote(10, 2, typesproto.PrevoteType, 0xAA, ts)), "step regression")
	require.NoError(t, signVote(pv, testChain, testVote(11, 0, typesproto.PrevoteType, 0xCC, ts)), "moving on is fine")
}

func TestRefusesConflictingProposal(t *testing.T) {
	path, priv := freshPV(t)
	pv, _, err := loadPrivValidator(priv, path)
	require.NoError(t, err)
	ts := time.Unix(1700000000, 0).UTC()
	prop := func(b byte) *typesproto.Proposal {
		return &typesproto.Proposal{Type: typesproto.ProposalType, Height: 20, Round: 0, PolRound: -1, Timestamp: ts,
			BlockID: typesproto.BlockID{Hash: append(make([]byte, 31), b), PartSetHeader: typesproto.PartSetHeader{Total: 1, Hash: append(make([]byte, 31), b)}}}
	}
	require.NoError(t, signProposal(pv, testChain, prop(0xAA)))
	require.ErrorContains(t, signProposal(pv, testChain, prop(0xBB)), "conflicting data")
	// and a prevote at that height/round may still follow the proposal
	require.NoError(t, signVote(pv, testChain, testVote(20, 0, typesproto.PrevoteType, 0xAA, ts)))
}

// The state written before this change: vote TYPE as the step, no sign bytes.  Mapped to the
// highest step it could have meant, so nothing at or below it is ever signed.
func TestLegacyStateIsHonouredConservatively(t *testing.T) {
	path, priv := freshPV(t)
	require.NoError(t, os.WriteFile(path, []byte(`{"height": 30, "round": 1, "step": 2}`), 0600))
	pv, note, err := loadPrivValidator(priv, path)
	require.NoError(t, err)
	require.Contains(t, note, "LEGACY")
	ts := time.Unix(1700000000, 0).UTC()

	require.Error(t, signVote(pv, testChain, testVote(30, 1, typesproto.PrecommitType, 0xAA, ts)), "precommit at the legacy H/R")
	require.Error(t, signVote(pv, testChain, testVote(30, 1, typesproto.PrevoteType, 0xAA, ts)), "prevote at the legacy H/R")
	require.Error(t, signVote(pv, testChain, testVote(29, 0, typesproto.PrevoteType, 0xAA, ts)), "an earlier height")
	require.NoError(t, signVote(pv, testChain, testVote(30, 2, typesproto.PrevoteType, 0xAA, ts)), "the next round")
}

// Unknown state is no state: refuse rather than sign blind.
func TestUnreadableStateRefusesToStart(t *testing.T) {
	path, priv := freshPV(t)
	require.NoError(t, os.WriteFile(path, []byte(`{not json`), 0600))
	_, _, err := loadPrivValidator(priv, path)
	require.ErrorContains(t, err, "refusing to sign")
}

func TestNoStateFileIsANewValidator(t *testing.T) {
	path, priv := freshPV(t)
	pv, note, err := loadPrivValidator(priv, path)
	require.NoError(t, err)
	require.Contains(t, note, "no last-sign state")
	require.NoError(t, signVote(pv, testChain, testVote(1, 0, typesproto.PrevoteType, 0xAA, time.Unix(1700000000, 0).UTC())))
	_, err = os.Stat(path)
	require.NoError(t, err, "the state is on disk once something is signed")
}
