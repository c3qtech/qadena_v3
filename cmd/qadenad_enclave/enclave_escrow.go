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
// WHAT IT IS ENCRYPTED TO: THE CURRENT SS INTERVAL KEY.  The secret must be one that NEVER leaves
// the enclaves.  The jar key does not qualify -- the regulator is to be given it, and with it every
// node's escrow, i.e. every enclave's identity key.  The SS interval key does: it exists only as
// Shamir shares held by owner enclaves (encrypted on chain to each owner's enclave key) and as
// reconstructions cached inside enclaves.  So the escrow is as Shamir-protected as the data the
// interval key protects, and opening it takes a threshold of that key's owners, each of which
// attests the requester before releasing a share.
//
// Hybrid, not plain ECIES: a fresh AES-256-GCM data key encrypts the fields, with the clear header
// bound in as associated data, and only that data key is ECIES-wrapped to the SS public key.  ECIES
// alone would leave the header unauthenticated.  Writing needs only the PUBLIC key, which every
// enclave caches; no private key is reconstructed to write an escrow.
//
// WHAT IS DELIBERATELY NOT HERE:
//
//   - SS shares.  They come back from the chain: each PublicKey row carries every owner's share
//     encrypted to that owner's EnclavePubK, which this escrow restores.
//   - The pioneer key.  The operator supplies it to sync-enclave again, exactly as at first join.
//   - The trusted set and every other shared field.  Restoring them from a snapshot would be a
//     rollback; the seed supplies the current ones.
//
// FRESHNESS.  A blob is a snapshot, so restoring it is a rollback of what it holds.  The watermark is
// therefore taken as max(escrowed, the seed's attested height), never the escrowed value alone, and
// the EnclavePubK is checked against the one the CHAIN records for this pioneer before anything is
// installed -- a stale or substituted blob for another key is refused.  The SS public key named in
// the header is checked against the chain too, so a forged header cannot steer the restore to a
// key of the attacker's choosing.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const (
	escrowVersion  = 2
	escrowFileName = "private_params_escrow.json"
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

// escrowFile is what lands on disk.  Everything outside the two encrypted fields is public on chain
// anyway, in the clear so a restore can refuse the wrong blob -- and find the right SS key --
// before doing any work, and authenticated as associated data so none of it can be edited.
type escrowFile struct {
	Version     int
	PioneerID   string
	EnclavePubK string
	SSPubKID    string // the SS interval key the data key is wrapped to
	SSPubK      string
	WrappedKey  []byte // ECIES(SSPubK, data key)
	Nonce       []byte
	Ciphertext  []byte // AES-256-GCM(data key, fields)
}

// escrowSSKey is the SS interval key new escrows are written to: the current one, recorded on the
// execution thread by UpdateHeight (noteEscrowSSKey), because finding it reads the block store.
// writeEscrow runs wherever the params are saved, so it reads this snapshot instead.
var escrowSSKey struct {
	mu           sync.Mutex
	pubKID, pubK string
}

func currentEscrowSSKey() (pubKID, pubK string) {
	escrowSSKey.mu.Lock()
	defer escrowSSKey.mu.Unlock()
	return escrowSSKey.pubKID, escrowSSKey.pubK
}

func setEscrowSSKey(pubKID, pubK string) (changed bool) {
	escrowSSKey.mu.Lock()
	defer escrowSSKey.mu.Unlock()
	changed = escrowSSKey.pubKID != pubKID
	escrowSSKey.pubKID, escrowSSKey.pubK = pubKID, pubK
	return changed
}

func (s *qadenaServer) escrowPath() string {
	return s.HomePath + "/enclave_config/" + escrowFileName
}

func escrowAAD(f *escrowFile) []byte {
	return []byte(fmt.Sprintf("qadena-escrow|%d|%s|%s|%s|%s", f.Version, f.PioneerID, f.EnclavePubK, f.SSPubKID, f.SSPubK))
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealEscrow encrypts p so that only an enclave holding the SS interval key ssPubKID can read it.
func sealEscrow(p escrowedPrivateParams, ssPubKID, ssPubK string) ([]byte, error) {
	if ssPubKID == "" || ssPubK == "" {
		return nil, errors.New("no SS interval key to write the escrow to")
	}
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	wrapped := c.BEncrypt(ssPubK, dataKey)
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("could not wrap the data key to SS key %s", ssPubKID)
	}
	aead, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	f := escrowFile{
		Version: escrowVersion, PioneerID: p.PioneerID, EnclavePubK: p.EnclavePubK,
		SSPubKID: ssPubKID, SSPubK: ssPubK, WrappedKey: wrapped,
	}
	f.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(f.Nonce); err != nil {
		return nil, err
	}
	f.Ciphertext = aead.Seal(nil, f.Nonce, plain, escrowAAD(&f))
	return json.Marshal(f)
}

// readEscrowHeader parses a blob and checks it is this pioneer's, without decrypting anything.
func readEscrowHeader(b []byte, pioneerID string) (*escrowFile, error) {
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
	if f.SSPubKID == "" || f.SSPubK == "" || len(f.WrappedKey) == 0 {
		return nil, errors.New("escrow names no SS interval key")
	}
	return &f, nil
}

// openEscrow decrypts a blob with the reconstructed SS interval private key.
func openEscrow(f *escrowFile, ssPrivK string) (*escrowedPrivateParams, error) {
	// The key must be the one the header names, or the unwrap below is meaningless.
	if got, err := derivePubKBase64(ssPrivK); err != nil || got != f.SSPubK {
		return nil, errors.New("the SS private key does not match the key the escrow was written to")
	}
	dataKey := c.BDecrypt(ssPrivK, f.WrappedKey)
	if len(dataKey) != 32 {
		return nil, errors.New("could not unwrap the escrow's data key")
	}
	aead, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	if len(f.Nonce) != aead.NonceSize() {
		return nil, errors.New("escrow nonce has the wrong length")
	}
	plain, err := aead.Open(nil, f.Nonce, f.Ciphertext, escrowAAD(f))
	if err != nil {
		return nil, fmt.Errorf("escrow does not decrypt: %w", err)
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

// noteEscrowSSKey records the current SS interval key and, when it has changed, re-writes the
// escrow to it.  EXECUTION THREAD ONLY: it reads the block store.  Called every block from
// UpdateHeight; the lookup is two point reads, and the write happens only on a change -- the first
// interval key after init or join, and each rotation after that.
func (s *qadenaServer) noteEscrowSSKey() {
	pubKID, _, _, found := s.getIntervalPublicKeyId(types.SSNodeID, types.SSNodeType)
	if !found || pubKID == "" {
		return
	}
	pubK, ok := s.getPubKCache(pubKID)
	if !ok || pubK == "" {
		if pubK, ok = s.getPublicKey(pubKID, types.TransactionPubKType); !ok || pubK == "" {
			return
		}
	}
	// ONLY A KEY OTHERS CAN REBUILD.  A restore cannot use this node's own share -- it decrypts only
	// with the key being recovered -- so a key whose OTHER owners cannot reach its threshold would
	// leave the escrow openable only by luck (some enclave happening to hold it cached).  The first
	// interval key of a chain is exactly that: minted while the genesis pioneer was the only
	// addressable owner.  Keep the previous escrow until a rotation produces a key that qualifies.
	if cur, _ := currentEscrowSSKey(); cur != pubKID {
		if others, need, ok := s.escrowKeyOthers(pubKID); !ok {
			if !escrowKeyWarned[pubKID] {
				escrowKeyWarned[pubKID] = true
				c.LoggerInfo(logger, "escrow: NOT moving to SS interval key "+pubKID+" -- "+strconv.Itoa(others)+
					" other owner(s), "+strconv.Itoa(need)+" needed to rebuild it without this node; "+
					map[bool]string{true: "keeping the escrow on " + cur, false: "no escrow yet -- this node cannot survive a CPU move until a rotation mints a key other pioneers own"}[cur != ""])
			}
			return
		}
	}
	if !setEscrowSSKey(pubKID, pubK) || !s.paramsPersisted {
		return
	}
	if err := s.writeEscrow(); err != nil {
		c.LoggerError(logger, "could not re-write the private-params escrow to SS key "+pubKID+
			" -- this node will NOT survive a move to another CPU: "+err.Error())
		return
	}
	c.LoggerInfo(logger, "private-params escrow written to SS interval key "+pubKID)
}

// escrowKeyWarned limits the "not moving" note to once per key; noteEscrowSSKey runs every block.
// Execution thread only, like its caller.
var escrowKeyWarned = map[string]bool{}

// escrowKeyOthers reports how many owners of pubKID other than this node there are, how many shares
// rebuilding it takes, and whether the others alone suffice.
func (s *qadenaServer) escrowKeyOthers(pubKID string) (others, need int, ok bool) {
	owners, found := s.getOwners(pubKID)
	if !found {
		return 0, 1, false
	}
	me := s.getPrivateEnclaveParamsPioneerID()
	for _, o := range owners.PioneerIDs {
		if o != me {
			others++
		}
	}
	need = getThreshold(len(owners.PioneerIDs))
	return others, need, others >= need && others > 0
}

// writeEscrow refreshes the escrow from the current params, to the current SS interval key.  Called
// after every successful sealed write and on every SS key change.  Silent when there is nothing to
// escrow yet (no pioneer or enclave key) or no SS key known yet -- noteEscrowSSKey writes it as soon
// as one is.
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
	s.mutex.RUnlock()

	if p.PioneerID == "" || p.EnclavePrivK == "" {
		return nil
	}
	ssPubKID, ssPubK := currentEscrowSSKey()
	if ssPubKID == "" {
		c.LoggerDebug(logger, "escrow: no SS interval key known yet; written once one is")
		return nil
	}
	b, err := sealEscrow(p, ssPubKID, ssPubK)
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
// sealed params can no longer be opened.  Runs inside SyncEnclave, after the seed's shared params
// and owner map have been received but before anything is installed; owners and bootstrapAddrs are
// what the seed sent.
//
// THE SS KEY IS GATHERED HERE, AS ANY ENCLAVE GATHERS ONE: shares are fetched from the key's owners
// over attested queries -- no transaction, so this works while the chain is halted -- encrypted to
// the temporary enclave key preInitEnclave minted for this sync.  This node cannot contribute a share
// of its own: decrypting its share needs the very key it is recovering.
//
// Fail-closed at every step, and it touches the params only once every check has passed:
//   - the blob must name this pioneer, and the SS public key it names must be the chain's;
//   - its EnclavePubK must be the one the CHAIN records for this pioneer -- a blob from an earlier
//     registration, or another node's, is refused rather than installed;
//   - the gathered SS key must derive to the named public key, and the blob must authenticate.
func (s *qadenaServer) restoreFromEscrow(queryClient types.QueryClient, pioneerID string, pwalletID string,
	owners *types.EncryptableEnclaveSSOwnerMap, bootstrapAddrs map[string]string, seedHeight int64) error {
	b, err := s.readEscrow()
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", s.escrowPath(), err)
	}
	if b == nil {
		return fmt.Errorf("there is no escrow at %s", s.escrowPath())
	}
	f, err := readEscrowHeader(b, pioneerID)
	if err != nil {
		return err
	}

	// Both public keys against the chain, BEFORE any network work: cheap, and it means a stale or
	// forged blob is refused without asking peers for anything.
	encRes, err := queryClient.PublicKey(context.Background(), &types.QueryGetPublicKeyRequest{
		PubKID: pwalletID, PubKType: types.EnclavePubKType,
	})
	if err != nil {
		return fmt.Errorf("cannot read this pioneer's enclave key from the chain (pubKID %s): %w", pwalletID, err)
	}
	if pk := encRes.GetPublicKey(); pk.PubK != f.EnclavePubK {
		return fmt.Errorf("the escrowed enclave key is not the one the chain records for %s -- the escrow is stale or not this node's", pioneerID)
	}
	ssRes, err := queryClient.PublicKey(context.Background(), &types.QueryGetPublicKeyRequest{
		PubKID: f.SSPubKID, PubKType: types.TransactionPubKType,
	})
	if err != nil {
		return fmt.Errorf("cannot read SS interval key %s from the chain: %w", f.SSPubKID, err)
	}
	if pk := ssRes.GetPublicKey(); pk.PubK != f.SSPubK {
		return fmt.Errorf("the escrow names SS key %s with a public key the chain does not record", f.SSPubKID)
	}

	ssPrivK, err := s.gatherEscrowSSKey(pioneerID, f.SSPubKID, f.SSPubK, owners, bootstrapAddrs)
	if err != nil {
		return err
	}
	p, err := openEscrow(f, ssPrivK)
	if err != nil {
		return err
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

	// Re-escrow to the same key on the final save; noteEscrowSSKey moves it to the current key on
	// the first block after start.
	setEscrowSSKey(f.SSPubKID, f.SSPubK)

	c.LoggerInfo(logger, "restored pioneer "+pioneerID+" from the escrow (SS key "+f.SSPubKID+
		"): enclave key matches the chain; trust watermark "+
		strconv.FormatInt(s.getPrivateEnclaveParamsTrustHeightHighWaterMark(), 10)+
		" (escrowed "+strconv.FormatInt(p.TrustHeightHighWaterMark, 10)+", seed "+strconv.FormatInt(seedHeight, 10)+")")
	return nil
}

// gatherEscrowSSKey reconstructs the SS interval key an escrow was written to, from the owner map
// and peer addresses the seed sent.  planSSReconstruct cannot be used: it reads owners and addresses
// from the block store, which a standalone enclave mid-sync has not got, and it consults the seed's
// address map only once the chain position is known.  The job is built from the seed's data
// instead; runSSReconstruct then does exactly what it does for any gather, integrity check included.
func (s *qadenaServer) gatherEscrowSSKey(me, ssPubKID, ssPubK string,
	owners *types.EncryptableEnclaveSSOwnerMap, bootstrapAddrs map[string]string) (string, error) {
	var ownerIDs []string
	if owners != nil {
		if o, ok := owners.Pioneers[ssPubKID]; ok && o != nil {
			ownerIDs = o.PioneerIDs
		}
	}
	if len(ownerIDs) == 0 {
		return "", fmt.Errorf("the seed lists no owners for SS key %s", ssPubKID)
	}
	job := &ssReconstructJob{
		pubKID:   ssPubKID,
		owners:   reorderPioneerIDs(ownerIDs, me),
		me:       me,
		nodes:    make(map[string]string),
		fallback: make(map[string]string),
	}
	job.threshold = getThreshold(len(job.owners))
	ownerSet := make(map[string]bool, len(ownerIDs))
	for _, o := range ownerIDs {
		ownerSet[o] = true
	}
	for p, ip := range bootstrapAddrs {
		if p == me || ip == "" {
			continue
		}
		if ownerSet[p] {
			job.nodes[p] = "tcp://" + ip + ":26657"
		} else if len(job.fallback) < effectiveProbeCap() {
			job.fallback[p] = "tcp://" + ip + ":26657"
		}
	}
	// This node is an owner but cannot contribute: its share decrypts only with the key being
	// recovered.  So the threshold must come from the OTHER owners.
	if len(job.nodes) < job.threshold {
		c.LoggerError(logger, "escrow: SS key "+ssPubKID+" needs "+strconv.Itoa(job.threshold)+
			" share(s) but the seed knows addresses for only "+strconv.Itoa(len(job.nodes))+
			" other owner(s) -- trying anyway, then asking non-owners who has it")
	}
	// The integrity check in runSSReconstruct verifies against the cached public key.  This one was
	// just checked against the chain, so it is the right thing to cache.
	if _, cached := s.getPubKCache(ssPubKID); !cached {
		s.setPubKCache(ssPubKID, ssPubK)
	}
	c.LoggerInfo(logger, "escrow: gathering SS key "+ssPubKID+" from "+strconv.Itoa(len(job.nodes))+
		" owner(s), threshold "+strconv.Itoa(job.threshold))
	privK := s.runSSReconstruct(job, "escrow-restore")
	if privK == "" {
		return "", fmt.Errorf("could not reconstruct SS key %s: fewer than %d of its other owners answered", ssPubKID, job.threshold)
	}
	c.LoggerInfo(logger, "escrow: SS key "+ssPubKID+" rebuilt via=escrow-restore (threshold "+
		strconv.Itoa(job.threshold)+", "+strconv.Itoa(len(job.nodes))+" other owner(s) asked)")
	return privK, nil
}
