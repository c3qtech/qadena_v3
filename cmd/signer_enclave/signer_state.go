package main

// DOUBLE-SIGN PROTECTION.
//
// A validator that signs two different votes or proposals for the same height, round and step is
// equivocating -- the evidence is slashable and jails it.  With a REMOTE signer CometBFT keeps no
// last-sign state of its own, so this process is the only thing that can refuse.  It used to record
// height/round/step after every signature and never consult it: canSign existed, and both call
// sites were commented out.  A crash, a restore, or a second copy of this process running by
// mistake could equivocate unopposed.
//
// THE RULE IS COMETBFT'S, NOT A NEW ONE.  This delegates to privval.FilePV from the vendored
// CometBFT -- the same code a validator with a local key file runs:
//
//   - anything BEHIND the last signed height/round/step is refused (regression);
//   - the SAME height/round/step is signed again only when the bytes are identical, or differ
//     only in timestamp -- the crash-after-sign-before-WAL case -- and then the PREVIOUS signature
//     is returned, never a new one;
//   - anything else at the same step is "conflicting data" and refused.
//
// The naive version (refuse any step <= last) is probably why the check was switched off: it also
// refuses the identical re-sign a crash restart asks for, and the validator stalls.  FilePV allows
// exactly that case and nothing more.
//
// DURABLE BEFORE RELEASED.  FilePV writes the state with an atomic temp-file rename before the
// signature is returned, and PANICS if it cannot -- this process dies without answering rather than
// hand out a signature it has no record of.  The state file holds only public data (heights,
// signatures, sign bytes); it is not sealed, so it is not CPU-bound and survives a move to another
// host.  recover_enclave_after_cpu_move.sh carries it across.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	typesproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// signMu serialises signing: FilePV is not safe for concurrent use.
var signMu sync.Mutex

// CometBFT's step numbering (privval/file.go).  The legacy state file used the vote TYPE instead
// (prevote 1, precommit 2) and wrote 2 for proposals as well.
const (
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
)

// loadPrivValidator returns a FilePV for priv whose last-sign state is read from statePath.
//
//   - no file: a fresh validator; protection starts here.  Logged, because after a restore it means
//     the state was not carried over.
//   - a file this cannot parse: REFUSES -- signing without knowing what was last signed is the
//     exact failure this exists to prevent.
//   - a LEGACY file (height/round/step, no sign bytes): the step is mapped conservatively to the
//     highest it could have meant, and with no sign bytes nothing at that height/round/step can be
//     re-signed.  At worst one round at one height is skipped; nothing is ever signed twice.
func loadPrivValidator(priv crypto.PrivKey, statePath string) (*privval.FilePV, string, error) {
	pv := privval.NewFilePV(priv, "", statePath)
	b, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return pv, "no last-sign state at " + statePath + " -- starting double-sign protection from nothing (expected on a new validator; after a restore it means the state was NOT carried over)", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("cannot read last-sign state %s: %w", statePath, err)
	}
	var st privval.FilePVLastSignState
	if err := cmtjson.Unmarshal(b, &st); err != nil {
		// THE LEGACY FILE IS PLAIN encoding/json: its height is a JSON NUMBER, where cmtjson
		// writes 64-bit integers as strings.  Without this fallback every existing validator
		// would refuse to start on its first boot after the upgrade.
		var legacy struct {
			Height int64 `json:"height"`
			Round  int32 `json:"round"`
			Step   int8  `json:"step"`
		}
		if lerr := json.Unmarshal(b, &legacy); lerr != nil {
			return nil, "", fmt.Errorf("last-sign state %s is unreadable (%v) -- refusing to sign without it; restore it from backup, or move it aside ONLY if this validator has certainly not signed at or above the chain's current height", statePath, err)
		}
		st = privval.FilePVLastSignState{Height: legacy.Height, Round: legacy.Round, Step: legacy.Step}
	}
	if len(st.Signature) > 0 && len(st.SignBytes) == 0 {
		return nil, "", fmt.Errorf("last-sign state %s has a signature but no sign bytes -- refusing to sign", statePath)
	}
	note := fmt.Sprintf("last-sign state loaded: height %d round %d step %d", st.Height, st.Round, st.Step)
	if st.Height > 0 && len(st.SignBytes) == 0 {
		legacy := st.Step
		switch st.Step {
		case 1:
			st.Step = stepPrevote
		default:
			st.Step = stepPrecommit
		}
		note = fmt.Sprintf("LEGACY last-sign state (height %d round %d step %d, no sign bytes) -- treated as step %d; nothing at or below it will be signed",
			st.Height, st.Round, legacy, st.Step)
	}
	pv.LastSignState.Height = st.Height
	pv.LastSignState.Round = st.Round
	pv.LastSignState.Step = st.Step
	pv.LastSignState.Signature = st.Signature
	pv.LastSignState.SignBytes = st.SignBytes
	return pv, note, nil
}

// signVote signs vote in place, or refuses with an error to send back to the node.
func signVote(pv *privval.FilePV, chainID string, vote *typesproto.Vote) error {
	signMu.Lock()
	defer signMu.Unlock()
	return pv.SignVote(chainID, vote)
}

// signProposal signs proposal in place, or refuses with an error to send back to the node.
func signProposal(pv *privval.FilePV, chainID string, proposal *typesproto.Proposal) error {
	signMu.Lock()
	defer signMu.Unlock()
	return pv.SignProposal(chainID, proposal)
}
