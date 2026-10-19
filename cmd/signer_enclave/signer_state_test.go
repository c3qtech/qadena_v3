package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// writeValidatorKeyFiles lays out a home the way a node has one: plaintext in config/, optionally a
// sealed copy in enclave_config/.
func writeValidatorKeyFiles(t *testing.T, sealedBody []byte) (home string, priv ed25519.PrivKey) {
	t.Helper()
	home = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "config"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "enclave_config"), 0755))

	priv = ed25519.GenPrivKey()
	var k PrivValidatorKey
	k.Address = "ADDR"
	k.PubKey.Type = "tendermint/PubKeyEd25519"
	k.PubKey.Value = base64.StdEncoding.EncodeToString(priv.PubKey().Bytes())
	k.PrivKey.Type = "tendermint/PrivKeyEd25519"
	k.PrivKey.Value = base64.StdEncoding.EncodeToString(priv[:])
	raw, err := json.Marshal(k)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, "config", "priv_validator_key.json"), raw, 0600))

	if sealedBody != nil {
		require.NoError(t, os.WriteFile(filepath.Join(home, "enclave_config", "priv_validator_key.json"), sealedBody, 0600))
	}
	return home, priv
}

// THE RULE: the signer must work whenever the unencrypted key is present.  A sealed copy this build
// cannot open -- which is every rebuilt signer's first start, and every node whose VM moved -- must
// fall back and re-seal rather than stop the validator dead.
func TestLoadKeyFallsBackToPlaintextWhenTheSealedCopyIsUnreadable(t *testing.T) {
	// A sealed blob from some other measurement: the debug seal tags with uniqueID, so this is not ours.
	home, priv := writeValidatorKeyFiles(t, []byte("someOtherMeasurement{\"not\":\"ours\"}"))

	got, pub, err := loadKey(home)
	require.NoError(t, err, "an unreadable sealed key must not be fatal while the plaintext is there")
	require.Equal(t, priv[:], got[:])
	require.Equal(t, priv.PubKey().Address(), pub.Address())

	// and it re-sealed for THIS measurement, replacing the stale copy
	resealed, rerr := os.ReadFile(filepath.Join(home, "enclave_config", "priv_validator_key.json"))
	require.NoError(t, rerr)
	require.True(t, bytes.HasPrefix(resealed, []byte(uniqueID)), "the sealed copy was not rewritten for this measurement")

	info, serr := os.Stat(filepath.Join(home, "enclave_config", "priv_validator_key.json"))
	require.NoError(t, serr)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm(), "a validator key must not be world-readable")
}

// First start on a fresh node: no sealed copy at all, seal it from the plaintext.
func TestLoadKeySealsFromPlaintextOnFirstStart(t *testing.T) {
	home, priv := writeValidatorKeyFiles(t, nil)
	got, _, err := loadKey(home)
	require.NoError(t, err)
	require.Equal(t, priv[:], got[:])
	sealed, rerr := os.ReadFile(filepath.Join(home, "enclave_config", "priv_validator_key.json"))
	require.NoError(t, rerr)
	require.True(t, bytes.HasPrefix(sealed, []byte(uniqueID)))
}

// A readable sealed copy is used as-is.
func TestLoadKeyUsesAReadableSealedCopy(t *testing.T) {
	home, priv := writeValidatorKeyFiles(t, nil)
	_, _, err := loadKey(home) // first start seals it
	require.NoError(t, err)

	// remove the plaintext: the sealed copy alone must now suffice
	require.NoError(t, os.Remove(filepath.Join(home, "config", "priv_validator_key.json")))
	got, _, err := loadKey(home)
	require.NoError(t, err)
	require.Equal(t, priv[:], got[:])
}

// Neither usable: fail, and name both paths so the operator knows what to restore.
func TestLoadKeyFailsClearlyWhenNeitherIsUsable(t *testing.T) {
	home, _ := writeValidatorKeyFiles(t, []byte("someOtherMeasurement{\"not\":\"ours\"}"))
	require.NoError(t, os.Remove(filepath.Join(home, "config", "priv_validator_key.json")))

	_, _, err := loadKey(home)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enclave_config")
	require.Contains(t, err.Error(), "config/priv_validator_key.json")
	require.Contains(t, err.Error(), "offline backup")
}
