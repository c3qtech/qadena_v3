package main

// PRIVATE-PARAMS ESCROW: how a node survives its VM moving to a different CPU.
//
// enclave_params_<uid>.json is sealed with the PRODUCT key, which SGX derives from a root key fused
// into the physical CPU.  A cloud VM that lands on another host (Azure deallocate, resize, redeploy,
// service healing) comes back with that file unreadable -- "cipher: message authentication failed"
// -- and the enclave-born half of it has no other copy anywhere:
//
//	EnclavePrivK / EnclavePubK / EnclaveArmorPrivK   the key the chain records as this pioneer's
//	                                                  EnclavePubKType.  Everything a client encrypts
//	                                                  to its HOME pioneer -- recovery shares,
//	                                                  protect-key shares, SS shares -- is encrypted
//	                                                  to this key.
//	SealedTableSharedSecret                           the key to every stable-sealed row key
//	TrustHeightHighWaterMark, PioneerIsValidator      small, but not derivable
//
// The shared half (jar, regulator, trusted set, SS owners) is re-fetched from any peer by
// sync-enclave, and the pioneer key is the operator's.  Only the fields above were ever at risk.
// Re-keying the pioneer on chain is not a substitute: it needs a transaction, which needs a live
// chain, which a moved node holding most of the stake is the reason there is not -- and everything
// encrypted to the old EnclavePubK would be lost for good anyway.
//
// So every write of the sealed params also writes those fields here, encrypted under a key derived
// from the JAR private key.  That key is held by every enclave in the trusted set and by nothing
// else, and arrives at a recovering node only through sync-enclave from a seed running its own
// measurement -- the same attested channel, and the same trust boundary, the jar and regulator
// private keys already cross.  The blob itself is not CPU-bound, so ordinary file backups carry it.
//
// WHAT IS DELIBERATELY NOT HERE:
//
//   - SS shares.  Every trusted enclave can open every escrow blob, so escrowed shares would let one
//     enclave collect a threshold of them.  A recovered node has none until a re-share; its own
//     getSSPrivK still works by gathering from the other owners.
//   - The pioneer key.  The operator supplies it to sync-enclave again, exactly as at first join.
//   - The trusted set and every other shared field.  Restoring them from a snapshot would be a
//     rollback; the seed supplies the current ones.
//
// FRESHNESS.  A blob is a snapshot, so restoring it is a rollback of what it holds.  The watermark is
// therefore taken as max(escrowed, the seed's attested height), never the escrowed value alone, and
// the EnclavePubK is checked against the one the CHAIN records for this pioneer before anything is
// installed -- a stale or substituted blob for another key is refused.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/crypto/hkdf"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	escrowVersion  = 1
	escrowFileName = "private_params_escrow.json"
	escrowHKDFInfo = "qadena private-params escrow v1"
)

// escrowedPrivateParams is the plaintext inside the blob: the enclave-born fields of
// PrivateEnclaveParams and nothing else.
type escrowedPrivateParams struct {
	PioneerID                string
	EnclaveArmorPrivK        string
	EnclavePrivK             string
	EnclavePubK              string
	SealedTableSharedSecret  []byte
	TrustHeightHighWaterMark int64
	PioneerIsValidator       bool
}

// escrowFile is what lands on disk.  PioneerID, JarID and EnclavePubK are in the clear so a restore
// can refuse the wrong blob before decrypting, and so an operator can see whose it is; all three are
// public on chain anyway.  They are also bound into the AEAD, so they cannot be edited.
type escrowFile struct {
	Version     int
	PioneerID   string
	JarID       string
	EnclavePubK string
	Nonce       []byte
	Ciphertext  []byte
}

func (s *qadenaServer) escrowPath() string {
	return s.HomePath + "/enclave_config/" + escrowFileName
}

func escrowKey(jarPrivK string) ([]byte, error) {
	if jarPrivK == "" {
		return nil, errors.New("no jar private key: nothing to derive the escrow key from")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(jarPrivK), nil, []byte(escrowHKDFInfo)), key); err != nil {
		return nil, err
	}
	return key, nil
}

func escrowAAD(f *escrowFile) []byte {
	return []byte(fmt.Sprintf("qadena-escrow|%d|%s|%s|%s", f.Version, f.PioneerID, f.JarID, f.EnclavePubK))
}

func escrowAEAD(jarPrivK string) (cipher.AEAD, error) {
	key, err := escrowKey(jarPrivK)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealEscrow encrypts p for the fleet whose jar key is jarPrivK.
func sealEscrow(p escrowedPrivateParams, jarID, jarPrivK string) ([]byte, error) {
	aead, err := escrowAEAD(jarPrivK)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	f := escrowFile{Version: escrowVersion, PioneerID: p.PioneerID, JarID: jarID, EnclavePubK: p.EnclavePubK}
	f.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(f.Nonce); err != nil {
		return nil, err
	}
	f.Ciphertext = aead.Seal(nil, f.Nonce, plain, escrowAAD(&f))
	return json.Marshal(f)
}

// openEscrow decrypts a blob, refusing one that belongs to another pioneer or another jar.
func openEscrow(b []byte, pioneerID, jarID, jarPrivK string) (*escrowedPrivateParams, error) {
	var f escrowFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("escrow is not readable JSON: %w", err)
	}
	if f.Version != escrowVersion {
		return nil, fmt.Errorf("escrow version %d, this build reads %d", f.Version, escrowVersion)
	}
	if f.PioneerID != pioneerID {
		return nil, fmt.Errorf("escrow belongs to pioneer %q, not %q", f.PioneerID, pioneerID)
	}
	if f.JarID != jarID {
		return nil, fmt.Errorf("escrow was written under jar %q, the seed's jar is %q", f.JarID, jarID)
	}
	aead, err := escrowAEAD(jarPrivK)
	if err != nil {
		return nil, err
	}
	if len(f.Nonce) != aead.NonceSize() {
		return nil, errors.New("escrow nonce has the wrong length")
	}
	plain, err := aead.Open(nil, f.Nonce, f.Ciphertext, escrowAAD(&f))
	if err != nil {
		return nil, fmt.Errorf("escrow does not decrypt under the seed's jar key: %w", err)
	}
	var p escrowedPrivateParams
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, err
	}
	// The clear header and the sealed body must agree; the AAD binds the header, this binds the body.
	if p.PioneerID != f.PioneerID || p.EnclavePubK != f.EnclavePubK {
		return nil, errors.New("escrow header and body disagree")
	}
	if p.EnclavePrivK == "" || p.EnclavePubK == "" || len(p.SealedTableSharedSecret) == 0 {
		return nil, errors.New("escrow is missing enclave key material")
	}
	return &p, nil
}

// writeEscrow refreshes the escrow from the current params.  Called after every successful sealed
// write, so the blob is never older than the sealed file it backs up.  Silent when the node has
// nothing to escrow yet (no pioneer, no enclave key, or no jar key to encrypt under).
func (s *qadenaServer) writeEscrow() error {
	s.mutex.RLock()
	p := escrowedPrivateParams{
		PioneerID:                s.privateEnclaveParams.PioneerID,
		EnclaveArmorPrivK:        s.privateEnclaveParams.EnclaveArmorPrivK,
		EnclavePrivK:             s.privateEnclaveParams.EnclavePrivK,
		EnclavePubK:              s.privateEnclaveParams.EnclavePubK,
		SealedTableSharedSecret:  s.privateEnclaveParams.SealedTableSharedSecret,
		TrustHeightHighWaterMark: s.privateEnclaveParams.TrustHeightHighWaterMark,
		PioneerIsValidator:       s.privateEnclaveParams.PioneerIsValidator,
	}
	jarID := s.sharedEnclaveParams.JarID
	jarPrivK := s.sharedEnclaveParams.JarPrivK
	s.mutex.RUnlock()

	if p.PioneerID == "" || p.EnclavePrivK == "" || jarPrivK == "" {
		return nil
	}
	b, err := sealEscrow(p, jarID, jarPrivK)
	if err != nil {
		return err
	}
	// 0600: the content is encrypted, but nothing else on the host needs to read it.
	return atomicWriteFile(s.escrowPath(), b, 0600)
}

// readEscrow returns the blob on disk, or (nil, nil) when there is none.
func (s *qadenaServer) readEscrow() ([]byte, error) {
	b, err := os.ReadFile(s.escrowPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// restoreFromEscrow installs this pioneer's own enclave-born keys from the escrow, for a node whose
// sealed params can no longer be opened.  remote is the seed's shared params, just received over
// the attested sync-enclave channel and not yet installed; the escrow key derives from its jar key.
//
// Fail-closed at every step, and it touches the params only once every check has passed:
//   - the blob must name this pioneer and the seed's jar, and decrypt under the jar key;
//   - its EnclavePubK must be the one the CHAIN records for this pioneer -- a blob from an earlier
//     registration, or another node's, is refused rather than installed.
func (s *qadenaServer) restoreFromEscrow(queryClient types.QueryClient, pioneerID string, pwalletID string, remote *types.EncryptableSharedEnclaveParams, seedHeight int64) error {
	b, err := s.readEscrow()
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", s.escrowPath(), err)
	}
	if b == nil {
		return fmt.Errorf("there is no escrow at %s", s.escrowPath())
	}
	p, err := openEscrow(b, pioneerID, remote.JarID, remote.JarPrivK)
	if err != nil {
		return err
	}

	res, err := queryClient.PublicKey(context.Background(), &types.QueryGetPublicKeyRequest{
		PubKID:   pwalletID,
		PubKType: types.EnclavePubKType,
	})
	if err != nil {
		return fmt.Errorf("cannot read this pioneer's enclave key from the chain (pubKID %s): %w", pwalletID, err)
	}
	if pk := res.GetPublicKey(); pk.PubK != p.EnclavePubK {
		return fmt.Errorf("the escrowed enclave key is not the one the chain records for %s -- the escrow is stale or not this node's", pioneerID)
	}

	// THE ENCLAVE KEY IN THE KEYRING TOO.  preInitEnclave created a fresh one under the same name;
	// replace it so nothing can sign or decrypt with the key the chain has never seen.
	kb := clientCtx.Keyring
	_ = kb.Delete(types.EnclaveKeyringName)
	if err := kb.ImportPrivKey(types.EnclaveKeyringName, p.EnclaveArmorPrivK, ArmorPassPhrase); err != nil {
		return fmt.Errorf("cannot import the escrowed enclave key into the keyring: %w", err)
	}

	s.setPrivateEnclaveParamsEnclaveInfo(p.EnclaveArmorPrivK, p.EnclavePrivK, p.EnclavePubK)
	s.setPrivateEnclaveParamsSealedTableSharedSecret(p.SealedTableSharedSecret)
	s.setPrivateEnclaveParamsPioneerIsValidator(p.PioneerIsValidator)

	// THE WATERMARK NEVER COMES BACK LOWER THAN THE PRESENT.  The escrow is a snapshot, so its mark
	// may be old; the seed's attested height is current.  advance is monotonic, so taking both gives
	// the max.
	s.advanceTrustHeightHighWaterMark(p.TrustHeightHighWaterMark, 1)
	s.advanceTrustHeightHighWaterMark(seedHeight, 1)

	c.LoggerInfo(logger, "restored pioneer "+pioneerID+" from the escrow: enclave key matches the chain; trust watermark "+
		strconv.FormatInt(s.getPrivateEnclaveParamsTrustHeightHighWaterMark(), 10)+
		" (escrowed "+strconv.FormatInt(p.TrustHeightHighWaterMark, 10)+", seed "+strconv.FormatInt(seedHeight, 10)+")")
	c.LoggerInfo(logger, "    this node holds NO secret-sharing shares now (they are never escrowed); its keys are still")
	c.LoggerInfo(logger, "    reconstructible from the other owners, but a re-share is needed to restore the margin")
	return nil
}
