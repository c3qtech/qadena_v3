package main

import (
	_ "embed"
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"slices"
	"strconv"
	"sync"

	//	"net/http"
	"context"
	"flag"

	"bytes"
	"os"
	"strings"
	"syscall"

	"encoding/hex"

	"compress/gzip"

	"crypto/sha256"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"crypto/tls"

	"github.com/cosmos/cosmos-sdk/client/flags"

	//	"github.com/cosmos/cosmos-sdk/client/rpc"
	sdk "github.com/cosmos/cosmos-sdk/types"
	//	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	"net"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"

	cmdcfg "github.com/c3qtech/qadena_v3/cmd/config"
	dsvstypes "github.com/c3qtech/qadena_v3/x/dsvs/types"
	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
	qadenaflags "github.com/cosmos/cosmos-sdk/client/flags"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	//	"github.com/cosmos/cosmos-sdk/client/config"

	"github.com/cosmos/cosmos-sdk/client"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	//	"github.com/c3qtech/qadena/app"

	"sort"
	"time"

	"encoding/json"
	"errors"

	"github.com/cometbft/cometbft/crypto/tmhash"
	//	"github.com/cometbft/cometbft/libs/log"

	"io/ioutil"
	"math/big"
	"math/rand/v2"

	"github.com/hashicorp/vault/shamir"

	cosmossdkiolog "cosmossdk.io/log"
	"cosmossdk.io/math"
	"cosmossdk.io/store"
	storemetrics "cosmossdk.io/store/metrics"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"

	tmdb "github.com/cosmos/cosmos-db"
	tmdbopt "github.com/syndtr/goleveldb/leveldb/opt"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	amino "github.com/cosmos/cosmos-sdk/codec"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	proto "github.com/cosmos/gogoproto/proto"

	enccodec "github.com/cosmos/cosmos-sdk/std"

	evmcryptocodec "github.com/cosmos/evm/crypto/codec"
	evmhd "github.com/cosmos/evm/crypto/hd"
	evmeip712 "github.com/cosmos/evm/ethereum/eip712"

	"google.golang.org/grpc/credentials/insecure"

	"os/signal"

	_ "github.com/c3qtech/qadena_v3/internal/qsortrshim"
)

// pingServer is used to implement helloworld.GreeterServer.
type pingServer struct {
	types.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *pingServer) SayHello(ctx context.Context, in *types.HelloRequest) (*types.HelloReply, error) {
	c.LoggerDebug(logger, "Received: "+in.GetName())

	return &types.HelloReply{Message: "Ping " + in.GetName()}, nil
}

// qadenaServer is used to implement the enclave grpc server
type qadenaServer struct {
	types.UnimplementedQadenaEnclaveServer

	ServerCtx     sdk.Context
	CacheCtx      sdk.Context
	CacheCtxWrite func()
	Cdc           *amino.ProtoCodec
	StoreKey      storetypes.StoreKey

	// The same goleveldb that backs the multistore, held directly for the raw (non-IAVL)
	// height-bookkeeping keys under qmeta/ -- confirmedHeight and the height->version index must
	// live OUTSIDE the tree so a tree rollback cannot rewrite them.  See enclave_height.go.
	// The interface type (not *tmdb.GoLevelDB) so unit tests can hand in a MemDB.
	MetaDB tmdb.DB

	// A separate, UNVERSIONED goleveldb for state that must survive a rollback of the tree:
	// SS interval shares/keys and the unvalidated-identity queue.  See enclave_secrets.go.
	SecretsDB tmdb.DB

	privateEnclaveParams PrivateEnclaveParams
	sharedEnclaveParams  types.EncryptableSharedEnclaveParams

	// The per-block enclave->chain delivery queues (changed wallets/credentials/recover keys,
	// removed credentials, committed suspicious transactions) live in VERSIONED state under
	// EnclaveOutboxKeyPrefix, not here -- see enclave_outbox.go.  As RAM they were lost on
	// restart and cleared before the block that consumed them was durable; in the tree they
	// commit, abort and roll back with the block itself.

	// The AML rolling window used to live here as transactionMap, an in-memory map. It now lives in
	// the KV store under EnclaveScanTransferHistoryKeyPrefix, because as process memory it was lost
	// on every restart, differed between validators -- which decide transfer acceptance from it --
	// and survived the rollback of the very transfer that added to it.

	// Reports filed by the transaction currently executing, held back until it is known to have
	// SUCCEEDED.  TransactionComplete promotes them into the suspicious outbox on success and
	// discards them on failure, mirroring exactly what it already does with the KV cache.
	//
	// Without this a report outlives the transaction that produced it: a bank send that crosses the
	// threshold files its report inside the send restriction and can then still fail in SendCoins --
	// on insufficient funds, say -- leaving the regulator with a report asserting a movement of value
	// that never happened.  It also makes the report SET depend on where a mid-loop failure landed,
	// which is a consensus hazard and not merely bad evidence.
	pendingSuspiciousTransactions []types.SuspiciousTransaction

	HomePath    string
	RealEnclave bool

	// paramsPersisted is true only once sealed params have actually been WRITTEN (or read back at
	// startup) -- as opposed to merely populated in memory by preInitEnclave.
	//
	// InitEnclave and SyncEnclave both short-circuit on "am I already initialized?", and both used
	// to answer that from the in-memory PioneerID.  preInitEnclave sets that field EARLY, while the
	// params are only saved at the very end, after the registration tx is accepted.  So a sync that
	// failed mid-way -- a rejected remote report, say -- left PioneerID set and nothing on disk, and
	// every retry then returned Status:true having done nothing at all.  Observed exactly that: a
	// second sync-enclave reported SUCCEEDED with an empty enclave_config/ and no registration on
	// chain, which reads as "already done" when the truth is "never done".
	paramsPersisted bool

	mutex sync.RWMutex
}

type storedEnclaveParams struct {
	PrivateEnclaveParams PrivateEnclaveParams
	SharedEnclaveParams  types.EncryptableSharedEnclaveParams
}

var clientCtx client.Context
var RootCmd *cobra.Command

var enclaveUpgradeMode bool = false

//var walletMap map[string]types.Wallet

//var protectKeyMap map[string]types.ProtectKey
//var protectSubWalletIDByOriginalWalletIDMap map[string]string

type SSIDAndPrivK struct {
	PubKID string
	PubK   string
	PrivK  string
}

type CredentialKey struct {
	credentialID   string
	credentialType string
}

var testSeal bool = false

//go:embed test_unique_id.txt
var uniqueID string

//go:embed test_signer_id.txt
var signerID string

//go:embed version.txt
var version string

// The enclave's own configuration, embedded so the heap size the GC is told about is the same
// number ego signed the enclave with.  Holding that constant in two places is how they drift, and
// a GC limit above the real heap is worse than none: it would pace against memory that does not
// exist and still die at the same allocation.
//
//go:embed enclave.json
var enclaveConfigJSON []byte

// Fraction of the enclave heap the GC is allowed to fill before it collects hard.  The remainder
// covers the runtime's own bookkeeping and leaves room for one large transient to land -- the
// allocation that killed a node was a single 64MB argon2 buffer, so the headroom has to exceed the
// biggest single allocation the enclave makes, not just a rounding margin.
const memoryLimitPercent = 75

// How often the enclave reports its heap.  Frequent enough to show a trend within one regression
// run, rare enough to be free.
const reportMemStatsInterval = 60 * time.Second

// IAVL node cache size, in NODES.  See the note at SetIAVLCacheSize for why the SDK's 500,000
// default is wrong for an enclave with a fixed heap, and why a small cache costs nothing given that
// GetStoreHash scans the whole tree on most blocks.
const iavlCacheNodes = 20000

func setMemoryLimitFromHeapSize() {
	var cfg struct {
		HeapSize int64 `json:"heapSize"`
	}
	if err := json.Unmarshal(enclaveConfigJSON, &cfg); err != nil || cfg.HeapSize <= 0 {
		// Leave the default rather than guess: a wrong limit is worse than none.
		c.LoggerError(logger, "could not read heapSize from the embedded enclave.json; GC left unpaced")
		return
	}

	limit := cfg.HeapSize * memoryLimitPercent / 100 * 1024 * 1024
	debug.SetMemoryLimit(limit)
	c.LoggerInfo(logger, "enclave heap "+strconv.FormatInt(cfg.HeapSize, 10)+"MB, GC soft limit "+
		strconv.FormatInt(limit/1024/1024, 10)+"MB")
}

// reportMemStats logs the heap periodically.  The enclave had NO memory observability at all, which
// is why diagnosing the out-of-memory above meant reading a crash dump and eliminating hypotheses
// one at a time: the fatal error names the allocation that failed, never the one holding the heap.
//
// heapAlloc is live data; heapSys is what the runtime has taken from the enclave heap; the gap
// between them is garbage not yet returned.  A heapAlloc that climbs run over run is a leak; a
// heapSys that climbs while heapAlloc stays flat is the collector falling behind, which is what
// happened here.
// dumpHeapProfileOnSignal writes a pprof heap profile whenever the enclave is sent SIGUSR1.
//
// memstats says HOW MUCH is on the heap; this says WHAT.  The distinction matters -- a working set
// that grows with chain state and a leak look identical in a single number, and the only way to tell
// them apart is to see which allocation sites hold the bytes.
//
// A signal and a file rather than net/http/pprof, for two reasons.  It costs nothing when unused,
// where an HTTP listener is a permanently open port on a process that holds every private key on the
// node.  And it works unchanged under SGX: enclave.json mounts the host filesystem, so the profile
// lands somewhere readable, whereas serving HTTP from inside an enclave is a different problem.
//
//	kill -USR1 $(pgrep -f qadenad_enclave)
//	go tool pprof -top ~/qadena/logs/enclave-heap-<stamp>.pprof
func dumpHeapProfileOnSignal(homePath string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)

	for range ch {
		// A profile of freshly-collected memory is the honest one: without this the dump also
		// counts garbage the collector simply has not reached yet, which is exactly the confusion
		// this is meant to resolve.
		runtime.GC()

		path := homePath + "/logs/enclave-heap-" + time.Now().UTC().Format("20060102T150405Z") + ".pprof"
		f, err := os.Create(path)
		if err != nil {
			c.LoggerError(logger, "could not create heap profile "+path+": "+err.Error())
			continue
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			c.LoggerError(logger, "could not write heap profile: "+err.Error())
		} else {
			c.LoggerInfo(logger, "wrote heap profile to "+path)
		}
		f.Close()
	}
}

func reportMemStats() {
	var m runtime.MemStats
	for {
		time.Sleep(reportMemStatsInterval)
		runtime.ReadMemStats(&m)
		c.LoggerInfo(logger, fmt.Sprintf(
			"memstats heapAlloc=%dMB heapSys=%dMB heapIdle=%dMB heapReleased=%dMB nextGC=%dMB numGC=%d goroutines=%d",
			m.HeapAlloc>>20, m.HeapSys>>20, m.HeapIdle>>20, m.HeapReleased>>20, m.NextGC>>20,
			m.NumGC, runtime.NumGoroutine()))
	}
}

var keyUpdateFrequency int64 = 555

var unvalidatedEnclaveIdentitiesCheckCounter int64 = 1

var SupportsUnixDomainSockets bool = true

const (
	EnclaveSSIntervalOwnersKeyPrefix = "Enclave/SSIntervalOwners/value/"
	EnclaveSSIntervalSharesKeyPrefix = "Enclave/SSIntervalShares/value/"
	EnclaveSSIntervalPrivKKeyPrefix  = "Enclave/SSIntervalPrivK/value/"
	EnclaveSSIntervalPubKKeyPrefix   = "Enclave/SSIntervalPubK/value/"
	EnclaveCredentialHashKeyPrefix   = "Enclave/CredentialHash/value/"
	// reverse of EnclaveCredentialHashKeyPrefix: credentialID -> every identity hash that
	// resolves to it.  Hashes cannot be enumerated backwards out of the forward index, and
	// without this a removed credential would leave its hashes permanently blocking the
	// uniqueness check.
	EnclaveCredentialHashesByCredentialIDKeyPrefix       = "Enclave/CredentialHashesByCredentialID/value/"
	EnclaveCredentialPCXYKeyPrefix                       = "Enclave/CredentialPCXY/value/"
	EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix = "Enclave/ProtectSubWalletIDByOriginalWalletID/value/"
	EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix = "Enclave/RecoverOriginalWalletIDByNewWalletID/value/"
	//	EnclaveAuthorizedSignatoryKeyPrefix                  = "Enclave/AuthorizedSignatory/value/"
	EnclaveUnvalidatedEnclaveIdentityKeyPrefix = "Enclave/UnvalidatedEnclaveIdentity/value/"
	// The AML rolling window, keyed by source wallet.  In the KV store rather than in memory
	// because it is consensus input: ScanTransaction runs on every validator and its verdict
	// decides whether the transfer is rejected, so a node holding a different history would reach
	// a different verdict.  Being in the store also means it survives restarts and, because writes
	// go through CacheCtx, that a rolled-back transfer leaves no entry behind.
	EnclaveScanTransferHistoryKeyPrefix = "Enclave/ScanTransferHistory/value/"
	// The last chain height whose writes this store has committed, stamped INSIDE the IAVL
	// version so it travels with the tree: roll the tree back and the stamp rolls back with it,
	// making every committed version self-describing.  See enclave_height.go for the full model.
	// Deliberately ABSENT from GetStoreHash's key list -- it is node-local bookkeeping (each
	// node's enclave may sit at a different height during recovery) and must never enter a
	// cross-node store comparison.
	EnclavePreparedHeightKeyPrefix = "Enclave/PreparedHeight/value/"
)

func EnclaveKeyKey(k string) []byte {
	var key []byte

	idBytes := []byte(k)
	key = append(key, idBytes...)
	key = append(key, []byte("/")...)

	return key
}

func EnclaveKeyBKeyCredentialType(k []byte, credentialType string) []byte {
	var key []byte

	idBytes := k
	key = append(key, idBytes...)
	key = append(key, []byte("/"+credentialType)...)
	key = append(key, []byte("/")...)

	return key
}

func (s *qadenaServer) SealWithProductKey(b []byte) (ret []byte, err error) {
	if s.RealEnclave {
		ret, err = ecrypto.SealWithProductKey(b, nil)

		if err != nil {
			c.LoggerError(logger, "sealing error "+err.Error())
			return
		}
	} else {
		ret = append([]byte(signerID), b...)
		err = nil
	}
	return
}

func (s *qadenaServer) SealWithUniqueKey(b []byte) (ret []byte, err error) {
	if s.RealEnclave {
		ret, err = ecrypto.SealWithUniqueKey(b, nil)

		if err != nil {
			c.LoggerError(logger, "sealing error "+err.Error())
			return
		}
	} else {
		ret = append([]byte(uniqueID), b...)
		err = nil
	}
	return
}

func (s *qadenaServer) MustSeal(b []byte) (ret []byte) {
	var err error
	ret, err = s.SealWithProductKey(b)
	if err != nil {
		panic("Could not seal " + err.Error())
	}
	return
}

func (s *qadenaServer) MustUnseal(b []byte) (ret []byte) {
	var err error
	ret, err = s.Unseal(b)
	if err != nil {
		panic("Could not seal " + err.Error())
	}
	return
}

// encrypting at different times will generate the same ciphertext
func (s *qadenaServer) MustSealStable(b []byte) (ret []byte) {
	ret, err := c.SharedSecretNoNonceEncrypt(s.getPrivateEnclaveParamsSealedTableSharedSecret(), b)

	if err != nil {
		panic("Could not seal stable " + err.Error())
	}
	return
}

func (s *qadenaServer) MustUnsealStable(b []byte) (ret []byte) {
	ret, err := c.SharedSecretNoNonceDecrypt(s.getPrivateEnclaveParamsSealedTableSharedSecret(), b)

	if err != nil {
		panic("Could not unseal stable " + err.Error())
	}

	return
}

func (s *qadenaServer) Unseal(b []byte) (ret []byte, err error) {
	if s.RealEnclave {
		ret, err = ecrypto.Unseal(b, nil)

		if err != nil {
			c.LoggerError(logger, "unsealing error "+err.Error())
			return
		}
	} else {
		if bytes.HasPrefix(b, []byte(uniqueID)) {
			c.LoggerDebug(logger, "unsealing with unique id")
			err = nil
			l := len(uniqueID)

			x := b[l:]
			c.LoggerDebug(logger, "x "+string(x))
			ret = x
		} else if bytes.HasPrefix(b, []byte(signerID)) {
			c.LoggerDebug(logger, "unsealing with signer id")
			err = nil
			ret = b[len(signerID):]
			c.LoggerDebug(logger, "ret "+string(ret))
		} else {
			err = errors.New("Couldn't unseal, unrecognized prefix")
		}
	}
	return
}

var logger cosmossdkiolog.Logger

type EnclaveSSShareMap map[string]string // maps from pubkid to a share

// used to share contents from enclave to enclave; also for debugging
type EnclaveSSOwnerMap map[string][]string  // maps from pubkid to an array of Pioneer IDs
type EnclavePrivKCacheMap map[string]string // maps pubkid to privk

// only used to share contents from enclave to enclave
type EnclavePubKCacheMap map[string]string // maps pubkid to pubk

// end of never shared

const (
	EnvPrefix       = "QADENA"
	ArmorPassPhrase = "8675309" // this is only used in-process, in the enclave, does not affect security
)

func findSenderOption(senderOptions []string, option string) bool {
	if sort.SearchStrings(senderOptions, option) == len(senderOptions) {
		return false
	}
	return true
}

func getThreshold(shareCount int) int {
	threshold := 1
	switch shareCount {
	case 0:
		fallthrough
	case 1:
		fallthrough
	case 2:
		fallthrough
	case 3:
		threshold = 1
	case 4:
		fallthrough
	case 5:
		fallthrough
	case 6:
		threshold = 2
	case 7:
		fallthrough
	case 8:
		fallthrough
	case 9:
		fallthrough
	case 10:
		threshold = 3
	case 11:
		fallthrough
	case 12:
		fallthrough
	case 13:
		fallthrough
	case 14:
		fallthrough
	case 15:
		threshold = 4
	default:
		threshold = 5
	}
	c.LoggerDebug(logger, "threshold for shareCount", shareCount, "is", strconv.Itoa(threshold))
	return threshold
}

func (s *qadenaServer) addSSShare(pioneerIDs []string, pubKID string, privK string, pubK string) (shares []string, err error) {
	c.LoggerDebug(logger, "addSSSShare")
	shares = make([]string, 0)
	shareCount := len(pioneerIDs)
	threshold := getThreshold(shareCount)
	if threshold == 1 {
		for i := 0; i < shareCount; i++ {
			shares = append(shares, privK)
		}
	} else {
		// create shares
		var byteShares [][]byte

		byteShares, err = shamir.Split([]byte(privK), shareCount, threshold)
		if err != nil {
			c.LoggerError(logger, "err creating shamir share "+err.Error())
			return
		}
		for _, share := range byteShares {
			shares = append(shares, hex.EncodeToString(share))
		}
	}

	s.setOwnersAndShare(pubKID, pioneerIDs, shares[0])

	s.setPrivKCache(pubKID, privK)
	s.setPubKCache(pubKID, pubK)
	return
}

func (s *qadenaServer) getPubK(pubKID string) string {
	v, _ := s.getPubKCache(pubKID)
	return v
}

func randomizePioneerIDs(pioneerIDs []string, myPioneerID string) []string {
	// clone the slice
	pioneerIDs = append([]string{}, pioneerIDs...)

	// Find index of myPioneerID
	index := slices.Index(pioneerIDs, myPioneerID)

	if index != -1 {
		pioneerIDs = slices.Delete(pioneerIDs, index, index+1)
	}

	// Shuffle the slice
	rand.Shuffle(len(pioneerIDs), func(i, j int) {
		pioneerIDs[i], pioneerIDs[j] = pioneerIDs[j], pioneerIDs[i]
	})
	return pioneerIDs
}

func reorderPioneerIDs(pioneerIDs []string, myPioneerID string) []string {
	pioneerIDs = append([]string{}, pioneerIDs...)
	// Check if myPioneerID exists in the list
	if !slices.Contains(pioneerIDs, myPioneerID) {
		return pioneerIDs // Return unchanged if not found
	}

	// Find index of myPioneerID
	index := slices.Index(pioneerIDs, myPioneerID)

	// Remove it from the slice
	pioneerIDs = slices.Delete(pioneerIDs, index, index+1)

	// Prepend myPioneerID to the front
	return append([]string{myPioneerID}, pioneerIDs...)
}

func (s *qadenaServer) getSSPrivK(pubKID string) string {
	privK, found := s.getPrivKCache(pubKID)
	if !found || privK == "" {
		// check if this can be reconstructed via Shamir Secret Sharing
		owners, found := s.getOwners(pubKID)

		if !found {
			c.LoggerError(logger, "No SS owners found, can't reconstruct privk for "+pubKID)
			return ""
		}

		// for now, reach out to all owners to get their shares
		bshares := make([][]byte, 0)

		ownersPioneerIDs := reorderPioneerIDs(owners.PioneerIDs, s.getPrivateEnclaveParamsPioneerID())

		// make a copy of owners.PioneerIDs, but if
		shareCount := len(ownersPioneerIDs)
		c.LoggerDebug(logger, "SS owners", c.PrettyPrint(owners))
		c.LoggerDebug(logger, "shareCount", shareCount)
		threshold := getThreshold(shareCount)
		collectedShares := 0
		for _, owner := range ownersPioneerIDs {
			c.LoggerDebug(logger, "SS owner "+owner)
			var share string
			if owner == s.getPrivateEnclaveParamsPioneerID() {
				// we are one of the owners
				share, _ = s.getShare(pubKID)
				collectedShares++
			} else {
				ownerIP, found := s.getPioneerIPAddress(owner)
				if !found {
					continue
				}
				node := "tcp://" + ownerIP + ":26657"
				RootCmd.Flags().Set(flags.FlagNode, node)
				queryClientCtx, err := client.ReadPersistentCommandFlags(clientCtx, RootCmd.Flags())

				if err != nil {
					continue
				}

				queryClient := types.NewQueryClient(queryClientCtx)

				c.LoggerDebug(logger, "Calling QueryEnclaveSecretShare "+owner+" "+pubKID)

				report, err := s.getRemoteReport(strings.Join([]string{
					s.getPrivateEnclaveParamsEnclavePubK(),
					pubKID,
				}, "|"))
				if err != nil {
					continue
				}

				params := &types.QueryEnclaveSecretShareRequest{
					RemoteReport: report,
					EnclavePubK:  s.getPrivateEnclaveParamsEnclavePubK(),
					PubKID:       pubKID,
				}

				if s.RealEnclave {
					c.LoggerDebug(logger, "params (redacted)")
				} else {
					c.LoggerDebug(logger, "params "+c.PrettyPrint(params))
				}

				res, err := queryClient.EnclaveSecretShare(context.Background(), params)
				if err != nil {
					c.LoggerError(logger, "err "+err.Error())
					continue
				}

				// need to verify remote report

				if !s.verifyRemoteReport(
					res.GetRemoteReport(),
					strings.Join([]string{
						string(res.GetEncSecretShareEnclavePubK()),
					}, "|")) {
					c.LoggerError(logger, "remote report unverified")
					continue
				}

				_, err = c.BDecryptAndUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), res.GetEncSecretShareEnclavePubK(), &share)
				if err != nil {
					c.LoggerError(logger, "couldn't decrypt "+err.Error())
					continue
				}
				collectedShares++
			}

			// special case, there's only 1 share so this is the actual privk!
			if threshold == 1 && collectedShares == threshold {
				// store it for later use
				s.setPrivKCache(pubKID, share)
				return share
			}

			bshare, err := hex.DecodeString(share)
			if err != nil {
				c.LoggerError(logger, "couldn't hex decode "+err.Error())
				continue
			}
			bshares = append(bshares, bshare)

			if len(bshares) == threshold {
				c.LoggerDebug(logger, "we have enough to reconstruct the privk")
				break
			}
		}

		if len(bshares) < threshold {
			c.LoggerError(logger, "not enough shares to reconstruct privk")
			return ""
		}
		privK, err := shamir.Combine(bshares)
		if err != nil {
			c.LoggerError(logger, "error from shamir "+err.Error())
			return ""
		}
		sPrivK := string(privK)
		// store it for later use
		s.setPrivKCache(pubKID, sPrivK)
		return sPrivK
	}
	return privK
}

func (s *qadenaServer) getEnclavePubK(pioneerID string) (enclavePubK string, found bool) {
	var pioneerWalletID string
	pioneerWalletID, _, _, found = s.getIntervalPublicKeyId(pioneerID, types.PioneerNodeType)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find walletID for pioneerID "+pioneerID)
		return
	}
	enclavePubK, found = s.getPublicKey(pioneerWalletID, types.EnclavePubKType)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find enclave pubk for pioneerID "+pioneerID)
		return
	}
	return
}

// lastSavedEnclaveParams is the PLAINTEXT marshalling of the params as last written, used only
// to decide whether a write is needed.  Comparing plaintext rather than the sealed bytes is the
// whole point: MustSeal draws a fresh nonce every call, so two seals of identical content differ
// and a ciphertext comparison would never match.
//
// Not persisted.  After a restart it is empty, so the first save of a process always writes --
// which is the safe direction: at worst one redundant write per process, never a skipped one.
var lastSavedEnclaveParams []byte

// saveEnclaveParamsIfChanged writes the params file only when its contents would actually differ.
//
// Callers on a periodic path use this instead of saveEnclaveParams.  enclave_params_<uniqueID>.json
// holds SealedTableSharedSecret -- the key to every stable-sealed row in both stores, with no
// backup -- so every rewrite is a window in which a crash leaves it torn and those rows
// permanently unreadable.  A rewrite that changes nothing is that risk taken for no reason.
func (s *qadenaServer) saveEnclaveParamsIfChanged() bool {
	ep := storedEnclaveParams{
		PrivateEnclaveParams: s.privateEnclaveParams,
		SharedEnclaveParams:  s.sharedEnclaveParams,
	}
	b, err := json.Marshal(ep)
	if err != nil {
		// fall through to the unconditional save, which reports the error properly
		c.LoggerError(logger, "saveEnclaveParamsIfChanged marshal error "+err.Error())
		return s.saveEnclaveParams()
	}
	if lastSavedEnclaveParams != nil && bytes.Equal(lastSavedEnclaveParams, b) {
		c.LoggerDebug(logger, "enclave params unchanged, not rewriting")
		return true
	}
	return s.saveEnclaveParams()
}

func (s *qadenaServer) saveEnclaveParams() bool {
	// Set on the way out, below, only if the write succeeds.
	ep := storedEnclaveParams{
		PrivateEnclaveParams: s.privateEnclaveParams,
		SharedEnclaveParams:  s.sharedEnclaveParams,
	}

	c.LoggerDebug(logger, "saveEnclaveParams")

	b, err := json.Marshal(ep)

	var b2 []byte

	if testSeal {
		b2, err = json.Marshal(ep)
	}

	if err != nil {
		c.LoggerError(logger, "saveEnclaveParams marshal error "+err.Error())
		return false
	}

	// remember the PLAINTEXT we are about to seal, so saveEnclaveParamsIfChanged can tell a
	// real change from a re-seal of identical content
	plaintext := append([]byte(nil), b...)

	c.LoggerDebug(logger, "sealing with product key (encrypting)")
	b, err = s.SealWithProductKey(b)

	if testSeal {
		b2, err = s.SealWithProductKey(b2)
	}

	if err != nil {
		c.LoggerError(logger, "sealing error "+err.Error())
		return false
	}

	// ATOMIC, deliberately.  This file holds SealedTableSharedSecret -- the key for every
	// stable-sealed row in the enclave's stores.  A plain WriteFile to the live path can be
	// interrupted mid-write, and a truncated file here does not fail gracefully: it fails
	// UNSEALABLY, taking every sealed key with it, permanently.  Temp file, fsync, rename --
	// the rename is atomic on POSIX, so the live path always holds either the old blob or the
	// new one, never a torn one.
	err = atomicWriteFile(s.HomePath+"/enclave_config/enclave_params_"+uniqueID+".json", b, 0644)
	if testSeal {
		err = atomicWriteFile(s.HomePath+"/enclave_config/enclave_params_backup.json", b2, 0644)
	}

	if err != nil {
		c.LoggerError(logger, "err writing file "+err.Error())
		return false
	}

	lastSavedEnclaveParams = plaintext
	// The write succeeded, so the params now survive a restart.  This -- not the in-memory
	// PioneerID -- is what "already initialized" must mean.
	s.paramsPersisted = true

	c.LoggerDebug(logger, "saved")

	if testSeal {
		// save some dummy values to test for info leaks
		s.setPrivKCache("deadbeef-privkcache-key", "deadbeef-privkcache-value")
		_, found := s.getPrivKCache("deadbeef-privkcache-key")
		if !found {
			c.LoggerError(logger, "Couldn't find privk for deadbeef-privkcache-key")
		} else {
			c.LoggerDebug(logger, "Found privk for deadbeef-privkcache-key")
		}
		s.setOwnersAndShare("deadbeef-ownersandshare-key", make([]string, 0), "deadbeef-ownersandshare-value")
		s.setCredentialByHash("deadbeef-credentialbyhash-key", "deadbeef-privcredentialbyhash-value")
		s.setRecoverOriginalWalletIDByNewWalletID("deadbeef-recoveroriginalwalletidbynewwalletid-key", "deadbeef-recoveroriginalwalletidbynewwalletid-value")
		s.setProtectSubWalletIDByOriginalWalletID("deadbeef-protectsubwalletidbyoriginalwalletid-key", "deadbeef-protectsubwalletidbyoriginalwalletid-value")
	}

	return true
}

func (s *qadenaServer) getRemoteReport(certifyData string) (report []byte, err error) {
	hash := sha256.Sum256([]byte(certifyData))
	var reportbytes []byte
	if s.RealEnclave {
		// Create a report that includes the hash of an enclave generated certificate cert.
		reportbytes, err = enclave.GetRemoteReport(hash[:])
		if err != nil {
			c.LoggerError(logger, "error getting remote report "+err.Error())
			return
		}
	} else {
		reportbytes = []byte("TRUST-ME:" + uniqueID + ":" + signerID + ":" + hex.EncodeToString(hash[:]) + ":" + certifyData)
	}

	// use gzip compression
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	_, err = writer.Write(reportbytes)
	if err != nil {
		return
	}

	if err = writer.Close(); err != nil {
		return
	}

	report = buf.Bytes()

	c.LoggerDebug(logger, "report compression savings", len(reportbytes)-len(report))
	return
}

func (s *qadenaServer) verifyRemoteReport(remoteReportBytes []byte, certifyData string) bool {
	return s.verifyRemoteReportInternal(remoteReportBytes, certifyData, false)
}

// returns true if valid
// remoteReportMeasurement verifies a report cryptographically and returns WHOSE it is, consulting no
// trust list at all.
//
// For the bootstrap paths, which have no trust list to consult yet and must instead compare the
// measurement against something they already know: the sync-enclave seed (must be our own build) and
// the upgrade handover (must be the measurement the operator named).  Everything else should keep
// using verifyRemoteReport, which answers the different and usually correct question -- "is this
// measurement one I trust".
func (s *qadenaServer) remoteReportMeasurement(remoteReportBytes []byte, certifyData string) (ok bool, uid string, sid string) {
	return s.verifyRemoteReportMeasurement(remoteReportBytes, certifyData)
}

func (s *qadenaServer) verifyRemoteReportInternal(remoteReportBytes []byte, certifyData string, checkEnclaveUniqueIDOnly bool) bool {
	ok, localUniqueID, signerID := s.verifyRemoteReportMeasurement(remoteReportBytes, certifyData)
	if !ok {
		return false
	}

	if checkEnclaveUniqueIDOnly {
		if localUniqueID == uniqueID {
			c.LoggerDebug(logger, "Succeeded verifying remote report uniqueID: "+localUniqueID+" == enclave uniqueID: "+uniqueID)
			return true
		}
		c.LoggerDebug(logger, "Failed verifying remote report uniqueID: "+localUniqueID+" != enclave uniqueID: "+uniqueID)
		return false
	}

	found := s.getEnclaveIdentity(localUniqueID, signerID, false) // only get active ones
	if !found {
		c.LoggerError(logger, "But couldn't find an active enclave identity for uniqueID: "+localUniqueID)
		return false
	}
	c.LoggerDebug(logger, "Succeeded finding an active enclave identity for uniqueID: "+localUniqueID)
	return true
}

// verifyRemoteReportMeasurement does the cryptographic half only: unpack, verify, and report which
// measurement signed it.  Split out of verifyRemoteReportInternal so the bootstrap paths can reach
// the measurement without the trust-list check that necessarily fails for them.
func (s *qadenaServer) verifyRemoteReportMeasurement(remoteReportBytes []byte, certifyData string) (bool, string, string) {
	var localUniqueID string
	var signerID string
	var success bool

	// gunzip report
	var buf bytes.Buffer
	reader, err := gzip.NewReader(bytes.NewReader(remoteReportBytes))
	if err != nil {
		c.LoggerError(logger, "error gunzipping remote report "+err.Error())
		return false, "", ""
	}
	_, err = buf.ReadFrom(reader)
	if err != nil {
		c.LoggerError(logger, "error gunzipping remote report "+err.Error())
		return false, "", ""
	}
	remoteReportBytes = buf.Bytes()

	if s.RealEnclave {
		remoteReport, err := enclave.VerifyRemoteReport(remoteReportBytes)
		if err != nil {
			c.LoggerDebug(logger, "remote report tcbstatus "+tcbstatus.Explain(remoteReport.TCBStatus))
			if remoteReport.TCBStatus == tcbstatus.Revoked || remoteReport.TCBStatus == tcbstatus.OutOfDate {
				c.LoggerError(logger, "error verifying remote report "+err.Error())
				return false, "", ""
			} else {
				c.LoggerError(logger, "neither revoked nor completely out-of-date")
			}
		}

		hash := sha256.Sum256([]byte(certifyData))
		if !bytes.Equal(remoteReport.Data[:len(hash)], hash[:]) {
			c.LoggerDebug(logger, "mismatch hash")
			c.LoggerDebug(logger, "remoteReportData hash "+hex.EncodeToString(remoteReport.Data[:len(hash)]))
			c.LoggerDebug(logger, "certifyData hash "+hex.EncodeToString(hash[:]))
			return false, "", ""
		}
		c.LoggerDebug(logger, "hash match")

		localUniqueID = hex.EncodeToString(remoteReport.UniqueID)
		signerID = hex.EncodeToString(remoteReport.SignerID)
	} else {
		success, localUniqueID, signerID = c.DebugVerifyRemoteReport(logger, remoteReportBytes, certifyData)
		if !success {
			c.LoggerError(logger, "couldn't verify remote report")
			return false, "", ""
		}
	}
	c.LoggerDebug(logger, "Succeeded verifying remote report, uniqueID: "+localUniqueID)
	return true, localUniqueID, signerID
}

func (s *qadenaServer) loadEnclaveParams() bool {
	filename := s.HomePath + "/enclave_config/enclave_params_" + uniqueID + ".json"
	fileBytes, err := ioutil.ReadFile(filename)

	if err != nil {
		c.LoggerInfo(logger, "Couldn't read file "+filename+" but this is ok if the enclave has not yet been initialized.")
		return false
	} else {
		// Read back from disk: persisted by construction.
		s.paramsPersisted = true
		c.LoggerInfo(logger, "Read file "+filename)
	}

	c.LoggerDebug(logger, "unsealing with product key (decrypting)")
	fileBytes, err = s.Unseal(fileBytes)

	if err != nil {
		c.LoggerError(logger, "unsealing error "+err.Error())
		return false
	}

	var ep storedEnclaveParams

	err = json.Unmarshal([]byte(fileBytes), &ep)

	if err != nil {
		c.LoggerError(logger, "Couldn't unmarshal fileBytes")
		return false
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "storedEnclaveParams (redacted)")
	} else {
		c.LoggerDebug(logger, "storedEnclaveParams "+c.PrettyPrint(ep))
	}

	s.setPrivateEnclaveParamsPioneerInfo(
		ep.PrivateEnclaveParams.PioneerID,
		ep.PrivateEnclaveParams.PioneerWalletID,
		ep.PrivateEnclaveParams.PioneerArmorPrivK,
		ep.PrivateEnclaveParams.PioneerPrivK,
		ep.PrivateEnclaveParams.PioneerPubK)

	s.setPrivateEnclaveParamsEnclaveInfo(
		ep.PrivateEnclaveParams.EnclaveArmorPrivK,
		ep.PrivateEnclaveParams.EnclavePrivK,
		ep.PrivateEnclaveParams.EnclavePubK)

	s.setPrivateEnclaveParamsSealedTableSharedSecret(
		ep.PrivateEnclaveParams.SealedTableSharedSecret)

	s.setPrivateEnclaveParamsPioneerExternalIPAddress(
		ep.PrivateEnclaveParams.PioneerExternalIPAddress)

	s.setPrivateEnclaveParamsPioneerIsValidator(
		ep.PrivateEnclaveParams.PioneerIsValidator)

	s.setSharedEnclaveParamsRegulatorInfo(
		ep.SharedEnclaveParams.RegulatorID,
		ep.SharedEnclaveParams.RegulatorPubK,
		ep.SharedEnclaveParams.RegulatorPrivK,
		ep.SharedEnclaveParams.RegulatorArmorPrivK,
	)

	s.setSharedEnclaveParamsJarInfo(
		ep.SharedEnclaveParams.JarID,
		ep.SharedEnclaveParams.JarPubK,
		ep.SharedEnclaveParams.JarPrivK,
		ep.SharedEnclaveParams.JarArmorPrivK,
	)

	s.setSharedEnclaveParamsSSIntervalOwners(
		ep.SharedEnclaveParams.SSIntervalOwners)

	s.setSharedEnclaveParamsSSIntervalPubKCache(
		ep.SharedEnclaveParams.SSIntervalPubKCache)

	// THE TRUSTED SET, which is the whole reason a node keeps its trust across a restart or a wiped
	// data/ -- without this line it is written to disk and dropped on the way back, and the next
	// save then erases the copy on disk as well.
	s.setSharedEnclaveParamsActiveEnclaveIdentities(
		ep.SharedEnclaveParams.ActiveEnclaveIdentities)
	c.LoggerInfo(logger, "loaded trusted set: "+strconv.Itoa(len(ep.SharedEnclaveParams.ActiveEnclaveIdentities))+
		" enclave identities (0 means this node can only trust itself until a sync-enclave bootstrap)")

	// populate our keyring

	kb := clientCtx.Keyring

	if s.getPrivateEnclaveParamsPioneerArmorPrivK() != "" {
		err = kb.ImportPrivKey(s.getPrivateEnclaveParamsPioneerID(), s.getPrivateEnclaveParamsPioneerArmorPrivK(), ArmorPassPhrase)

		if err != nil {
			c.LoggerError(logger, "couldn't import pioneer privk "+err.Error())
			return false
		}
	}

	if s.getSharedEnclaveParamsJarArmorPrivK() != "" {
		err = kb.ImportPrivKey(s.getSharedEnclaveParamsJarID(), s.getSharedEnclaveParamsJarArmorPrivK(), ArmorPassPhrase)

		if err != nil {
			c.LoggerError(logger, "couldn't import jar privk "+err.Error())
			return false
		}
	}

	if s.getSharedEnclaveParamsRegulatorArmorPrivK() != "" {
		err = kb.ImportPrivKey(s.getSharedEnclaveParamsRegulatorID(), s.getSharedEnclaveParamsRegulatorArmorPrivK(), ArmorPassPhrase)

		if err != nil {
			c.LoggerError(logger, "couldn't import regulator privk "+err.Error())
			return false
		}
	}

	return true
}

func (s *qadenaServer) preInitEnclave(ctx context.Context, isValidator bool, pioneerID string, externalIPAddress string, pioneerArmorPrivK string, pioneerArmorPassPhrase string) (pwalletID string, pwalletAddr sdk.AccAddress, enclaveWalletID string, err error) {
	kb := clientCtx.Keyring

	if pioneerID != "" {
		c.LoggerDebug(logger, "Importing pioneer key")
		//
		// 		c.LoggerInfo(logger, "Importing pioneer key", pioneerID, pioneerArmorPrivK)
		err = kb.ImportPrivKey(pioneerID, pioneerArmorPrivK, pioneerArmorPassPhrase)

		if err != nil {
			c.LoggerError(logger, "couldn't import privk "+err.Error())
			return
		}

		gpwalletID, gpwalletAddr, pioneerPubK, pioneerPrivK, pioneerArmorPrivK, gerr := c.GetAddressByName(clientCtx, pioneerID, ArmorPassPhrase)
		if gerr != nil {
			c.LoggerError(logger, "couldn't get address for "+pioneerID+" "+err.Error())
			return
		}
		pwalletID = gpwalletID
		pwalletAddr = gpwalletAddr

		s.setPrivateEnclaveParamsPioneerInfo(pioneerID, pwalletID, pioneerArmorPrivK, pioneerPrivK, pioneerPubK)
	}

	// creating our enclave key
	c.LoggerDebug(logger, "Creating enclave key")

	mnemonic, err := c.GenerateNewMnemonic()
	if err != nil {
		c.LoggerError(logger, "Couldn't create new mnemonic")
		return
	}

	createPublicKeyReq := c.PublicKeyReq{
		FriendlyName:    types.EnclaveKeyringName,
		RecoverMnemonic: mnemonic,
		IsEphemeral:     false,
		EphAccountIndex: 0,
	}

	_, _, _, _, err = c.CreatePublicKey(clientCtx, createPublicKeyReq)
	if err != nil {
		c.LoggerError(logger, "couldn't create enclave key")
		return
	}

	enclaveWalletID, _, enclavePubK, enclavePrivK, enclaveArmorPrivK, err := c.GetAddressByName(clientCtx, types.EnclaveKeyringName, ArmorPassPhrase)
	if err != nil {
		c.LoggerError(logger, "couldn't get address for "+types.EnclaveKeyringName+" "+err.Error())
		return
	}

	s.setPrivateEnclaveParamsEnclaveInfo(enclaveArmorPrivK, enclavePrivK, enclavePubK)

	s.setPrivateEnclaveParamsSealedTableSharedSecret(c.GenerateSharedSecret()) // create a private key for all our "sealed" tables

	// bootstrapping!

	s.setPrivateEnclaveParamsPioneerIsValidator(isValidator)
	s.setPrivateEnclaveParamsPioneerExternalIPAddress(externalIPAddress)

	setExternalIPAddress := ""
	if isValidator {
		setExternalIPAddress = externalIPAddress
	}

	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		NodeID:            s.getPrivateEnclaveParamsPioneerID(),
		NodeType:          types.PioneerNodeType,
		PubKID:            s.getPrivateEnclaveParamsPioneerWalletID(),
		ExternalIPAddress: setExternalIPAddress,
	})

	s.setPublicKeyNoNotify(types.PublicKey{
		PubKID:   s.getPrivateEnclaveParamsPioneerWalletID(),
		PubKType: types.TransactionPubKType,
		PubK:     s.getPrivateEnclaveParamsPioneerPubK(),
	})
	s.setPublicKeyNoNotify(types.PublicKey{
		PubKID:   s.getPrivateEnclaveParamsPioneerWalletID(),
		PubKType: types.EnclavePubKType,
		PubK:     s.getPrivateEnclaveParamsEnclavePubK(),
	})

	return
}

func (s *qadenaServer) ExportPrivateKey(ctx context.Context, in *types.MsgExportPrivateKey) (*types.ExportPrivateKeyReply, error) {
	if s.RealEnclave {
		return nil, types.ErrGenericTransaction
	}
	c.LoggerDebug(logger, "ExportPrivateKey "+c.PrettyPrint(in))

	_, _, _, privK, err := c.GetAddressByNameNoArmor(clientCtx, in.PubKID)
	if err != nil {
		return nil, err
	}

	return &types.ExportPrivateKeyReply{PrivK: privK}, nil
}

func (s *qadenaServer) UpdateSSIntervalKey(ctx context.Context, in *types.MsgUpdateSSIntervalKey) (*types.UpdateSSIntervalKeyReply, error) {
	if s.RealEnclave {
		return nil, types.ErrGenericTransaction
	}

	if !s.updateSSIntervalKey() {
		c.LoggerError(logger, "couldn't update SS interval key")
	}

	return &types.UpdateSSIntervalKeyReply{}, nil
}

func (s *qadenaServer) RemovePrivateKey(ctx context.Context, in *types.MsgRemovePrivateKey) (*types.RemovePrivateKeyReply, error) {
	if s.RealEnclave {
		return nil, types.ErrGenericTransaction
	}

	privK, _ := s.getPrivKCache(in.PubKID)

	s.removePrivKCache(in.PubKID)
	c.LoggerDebug(logger, "RemovePrivateKey "+c.PrettyPrint(in)+" previous value "+privK)
	c.LoggerDebug(logger, "getPrivK "+s.getSSPrivK(in.PubKID))
	return &types.RemovePrivateKeyReply{}, nil
}

func (s *qadenaServer) ExportPrivateState(ctx context.Context, in *types.MsgExportPrivateState) (*types.ExportPrivateStateReply, error) {
	if s.RealEnclave && !testSeal {
		return nil, types.ErrGenericTransaction
	}

	c.LoggerDebug(logger, "ExportPrivateState")

	// AS-OF-HEIGHT dump.  This is the tool the 2026-08-09 fork had no answer to: "what did this
	// enclave hold at the height where the two nodes diverged?"  Diff two nodes' dumps at the same
	// height and the divergence is located rather than inferred.
	var reply *types.ExportPrivateStateReply
	err := s.withHeightPinned(in.Height, func(view *qadenaServer) error {
		var e error
		reply, e = view.exportPrivateStateFromCurrentView(in)
		return e
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// defaultExportMaxBytes keeps a full export inside gRPC's 4 MiB default receive cap with room for
// framing.  A caller that has raised its own cap (cmd/qadenad does, for these commands) can raise
// this too via max_bytes; the point of the default is that the failure is a NAMED SECTION AND A
// SIZE rather than a transport error from a reply that was already built.
const defaultExportMaxBytes = 3 << 20

// canonicalizeSection makes a section's JSON comparable between two enclaves.
//
// Map sections are already canonical: encoding/json sorts map keys, and the exporters unseal both
// key and value, so what is left is plaintext in a fixed order.  ARRAY SECTIONS ARE NOT: they come
// from getAll* store iteration, and where a prefix is stable-sealed that order is per-node, so two
// correct enclaves would produce different bytes for identical content.  Sorting the elements by
// their own encoding removes that without needing to know which prefixes are sealed -- and is a
// no-op for the sections that were already ordered.
func canonicalizeSection(raw []byte) ([]byte, int64) {
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		// Not an array: a map, scalar or struct.  Count map entries where we can, else one row.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err == nil {
			return raw, int64(len(m))
		}
		return raw, 1
	}
	strs := make([]string, len(elems))
	for i, e := range elems {
		strs[i] = string(e)
	}
	sort.Strings(strs)
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, sv := range strs {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(sv)
	}
	buf.WriteByte(']')
	return buf.Bytes(), int64(len(strs))
}

// exportSection names one section of the dump and the way to FETCH IT ON DEMAND.
//
// A thunk rather than a struct field: the caller usually wants one section, or the content of
// none of them.  See exportPrivateStateFromCurrentView for why that matters.
type exportSection struct {
	name  string
	fetch func() any
}

// exportSections lists every section, IN A FIXED ORDER that is part of the output.  It is the
// order the dump has always had, so diffs against older dumps still line up, and --digest-only
// output is directly diffable between two nodes without sorting.
//
// Append new sections at the end.
func (s *qadenaServer) exportSections() []exportSection {
	return []exportSection{
		{"PrivateEnclaveParams", func() any { return s.privateEnclaveParams }},
		{"SharedEnclaveParams", func() any { return s.sharedEnclaveParams }},
		{"Wallets", func() any { return s.getAllWallets() }},
		{"Credentials", func() any { return s.getAllCredentials() }},
		{"CredentialHashMap", func() any { return s.exportSealedTable(EnclaveCredentialHashKeyPrefix) }},
		{"CredentialHashAliasMap", func() any { return s.exportSealedCredentialIdentityHistoryTable() }},
		{"RecoverOriginalWalletIDByNewWalletIDMap", func() any {
			return s.exportSealedTable(EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix)
		}},
		{"RecoverKeyByOriginalWalletIDs", func() any { return s.getAllRecoverKeyByOriginalWalletIDs() }},
		{"JarRegulators", func() any { return s.getAllJarRegulators() }},
		{"PioneerJars", func() any { return s.getAllPioneerJars() }},
		{"PublicKeys", func() any { return s.getAllPublicKeys() }},
		{"IntervalPublicKeyIds", func() any { return s.getAllIntervalPublicKeyIds() }},
		{"ProtectKeys", func() any { return s.getAllProtectKeys() }},
		{"ProtectSubWalletIDByOriginalWalletIDMap", func() any {
			return s.exportSealedTable(EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix)
		}},
		{"CredentialPCXYMap", func() any { return s.exportTable(EnclaveCredentialPCXYKeyPrefix) }},

		// These four live in the secrets DB, not the versioned store -- see enclave_secrets.go.
		// They are therefore NOT affected by the height pin: a historical export reports the
		// secrets as they are now.
		{"EnclaveSSShareMap", func() any { return s.exportSealedSecretsTable(EnclaveSSIntervalSharesKeyPrefix) }},
		{"EnclaveSSOwnersMap", func() any { return *s.getAllOwners() }}, // EnclaveSSIntervalOwnersKeyPrefix
		{"EnclavePrivKCacheMap", func() any { return s.exportSealedSecretsTable(EnclaveSSIntervalPrivKKeyPrefix) }},
		{"EnclavePubKCacheMap", func() any { return s.exportSecretsTable(EnclaveSSIntervalPubKKeyPrefix) }},

		{"AuthorizedSignatories", func() any { return s.getAllDSVSAuthorizedSignatories() }},
		{"EnclaveIdentityMap", func() any { return s.getAllEnclaveIdentities() }},

		// Added because their absence is exactly what made the 2026-08-09 fork undiagnosable.
		// ScanTransferHistory is a CONSENSUS INPUT -- the AML window decides whether a transfer is
		// refused and whether a suspicious transaction is filed -- so two nodes disagreeing about a
		// block cannot be explained without it.  The outbox and the height watermarks say what the
		// enclave was about to hand the chain and which height it believed it was at.
		{"ScanTransferHistoryMap", func() any { return s.exportScanTransferHistoryTable() }},
		{"Outbox", func() any { return exportOutbox(s) }},

		// The watermarks are read from the CURRENT view even under a height pin: preparedHeight
		// lives inside the tree and so rolls back with it (giving the pinned height), while
		// confirmedHeight and the index horizon are raw MetaDB keys outside the tree and always
		// report now.  That asymmetry is intentional -- confirmedHeight is the record of what the
		// network has, which a historical read must not be able to un-say -- but it means these
		// three are not all "as of H".
		{"PreparedHeight", func() any { return s.getPreparedHeight() }},
		{"ConfirmedHeight", func() any { return s.getConfirmedHeight() }},
		{"EarliestIndexedHeight", func() any { return s.earliestIndexedHeight() }},
	}
}

// exportPrivateStateFromCurrentView dumps whatever s.CacheCtx currently points at.  Split from
// ExportPrivateState so the height pin wraps it rather than being interleaved with it.
func (s *qadenaServer) exportPrivateStateFromCurrentView(in *types.MsgExportPrivateState) (*types.ExportPrivateStateReply, error) {
	// ONE SECTION AT A TIME, fetched only if it is wanted.  Marshalling a single struct holding
	// every table gave no way to digest one section, no way to fetch one, and no way to discover
	// the result was too large except by handing it to the transport and having it refused --
	// which is how this command started failing at ~10k blocks with ResourceExhausted
	// (8328613 vs 4194304) once the reply outgrew gRPC's default receive cap.
	//
	// Laziness is the point, not a refinement.  --section wants exactly one table and
	// --digest-only reads every table but KEEPS none, so populating all of them up front would do
	// the whole store's work and hold the whole store in memory in both cases.  Peak memory is now
	// one section, which is the same discipline the private-state IMPORT already follows for the
	// same reason: enclave EPC is tens to a couple of hundred MB.
	maxBytes := int64(in.GetMaxBytes())
	if maxBytes == 0 {
		maxBytes = defaultExportMaxBytes
	}
	want := in.GetSection()

	sections := s.exportSections()

	var digests []*types.PrivateStateSectionDigest
	var total int64
	body := bytes.NewBufferString("{")
	wrote := 0
	matched := false

	for _, sec := range sections {
		name := sec.name
		if want != "" && name != want {
			continue
		}
		matched = true

		raw, err := json.Marshal(sec.fetch())
		if err != nil {
			return nil, fmt.Errorf("export section %s: %w", name, err)
		}
		canon, rows := canonicalizeSection(raw)

		if in.GetDigestOnly() {
			sum := sha256.Sum256(canon)
			digests = append(digests, &types.PrivateStateSectionDigest{
				Name:   name,
				Rows:   rows,
				Sha256: hex.EncodeToString(sum[:]),
				Bytes:  int64(len(canon)),
			})
			continue
		}

		total += int64(len(canon))
		if total > maxBytes {
			// ABANDON HERE, not after assembling everything.  The caller gets a section name and a
			// size, which is actionable -- digest_only always fits, and section= pulls just this
			// one -- and the enclave never holds the whole oversized document, which matters where
			// the memory budget is EPC.
			return nil, fmt.Errorf(
				"private-state export exceeds %d bytes: section %s adds %d bytes over %d rows, "+
					"bringing the total to %d.  Re-run with --digest-only to compare sections "+
					"without their content, then --section=<name> to fetch only the one that "+
					"differs, or raise --max-bytes if the transport can carry it",
				maxBytes, name, len(canon), rows, total)
		}

		if wrote > 0 {
			body.WriteByte(',')
		}
		nameJSON, _ := json.Marshal(name)
		body.Write(nameJSON)
		body.WriteByte(':')
		body.Write(canon)
		wrote++
	}

	if want != "" && !matched {
		return nil, fmt.Errorf("no private-state section named %q; run with --digest-only to list them", want)
	}

	if in.GetDigestOnly() {
		return &types.ExportPrivateStateReply{Digests: digests}, nil
	}

	body.WriteByte('}')
	return &types.ExportPrivateStateReply{State: body.String()}, nil
}

func (s *qadenaServer) exportTable(pfx string) (tableMap map[string]string) {
	tableMap = make(map[string]string)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		c.LoggerDebug(logger, "key "+string(itr.Key()))
		fixedKey := string(itr.Key()[:len(itr.Key())-1])
		c.LoggerDebug(logger, "fixedKey "+fixedKey)
		var val types.EnclaveStoreString
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		tableMap[fixedKey] = val.GetS()
		itr.Next()
	}
	itr.Close()
	return
}

func (s *qadenaServer) exportSealedTable(pfx string) (tableMap map[string]string) {
	tableMap = make(map[string]string)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(pfx))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		key := s.MustUnsealStable(itr.Key())
		c.LoggerDebug(logger, "key "+string(key))
		fixedKey := string(key[:len(key)-1])
		c.LoggerDebug(logger, "fixedKey "+fixedKey)
		var val types.EnclaveStoreString
		s.Cdc.MustUnmarshal(s.MustUnseal(itr.Value()), &val)
		tableMap[fixedKey] = val.GetS()
		itr.Next()
	}
	itr.Close()
	return
}

// exportSealedCredentialIdentityHistoryTable is exportSealedTable for the alias index, which
// stores EncryptableCredentialIdentityHistory rather than EnclaveStoreString.  The generic
// exporter would decode those values as a bare string and silently drop all but the last hash.
func (s *qadenaServer) exportSealedCredentialIdentityHistoryTable() (tableMap map[string]types.EncryptableCredentialIdentityHistory) {
	tableMap = make(map[string]types.EncryptableCredentialIdentityHistory)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashesByCredentialIDKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		key := s.MustUnsealStable(itr.Key())
		fixedKey := string(key[:len(key)-1])
		var val types.EncryptableCredentialIdentityHistory
		s.Cdc.MustUnmarshal(s.MustUnseal(itr.Value()), &val)
		tableMap[fixedKey] = val
		itr.Next()
	}
	itr.Close()
	return
}

func (s *qadenaServer) GenerateSecretShare(nodeID string, nodeType string) (msgPAPK *types.MsgPioneerAddPublicKey, msgPUIPKI *types.MsgPioneerUpdateIntervalPublicKeyID, msgPBSSPK *types.MsgPioneerBroadcastSecretSharePrivateKey, err error) {

	// create ss key
	var mnemonic string
	mnemonic, err = c.GenerateNewMnemonic()
	if err != nil {
		c.LoggerError(logger, "Couldn't create new mnemonic")
		return
	}

	createPublicKeyForReq := c.PublicKeyReq{
		FriendlyName:    mnemonic,
		RecoverMnemonic: mnemonic,
		IsEphemeral:     false,
		EphAccountIndex: 0,
	}

	_, _, _, _, err = c.CreatePublicKey(clientCtx, createPublicKeyForReq)
	if err != nil {
		c.LoggerError(logger, "couldn't create secret share key "+err.Error())
		return
	}
	var walletID, intervalPubK, intervalPrivK string
	walletID, _, intervalPubK, intervalPrivK, err = c.GetAddressByNameNoArmor(clientCtx, mnemonic)

	pioneers := s.getAllPioneers()

	// generate broadcast SS message
	privKeys := make([]*types.SecretSharePrivK, 0)
	for _, pioneer := range pioneers {
		var ssPrivK types.SecretSharePrivK
		ssPrivK.PioneerID = pioneer
		enclavePubK, found := s.getEnclavePubK(pioneer)
		if !found {
			c.LoggerError(logger, "couldn't find enclave pubk for "+pioneer)
			return
		}
		var ssIDAndPrivK types.EncryptableSSIDAndPrivK
		ssIDAndPrivK.PubKID = walletID
		ssIDAndPrivK.PrivK = intervalPrivK
		ssIDAndPrivK.PubK = intervalPubK
		ssPrivK.EncEnclaveSSIDAndPrivK = c.ProtoMarshalAndBEncrypt(enclavePubK, &ssIDAndPrivK)
		privKeys = append(privKeys, &ssPrivK)
	}

	// generate shares

	var shares []string
	shares, err = s.addSSShare(pioneers, walletID, intervalPrivK, intervalPubK)
	if err != nil {
		c.LoggerError(logger, "couldn't addSSShare "+err.Error())
		return
	}

	gShares := make([]*types.Share, 0)

	for i, share := range shares {
		pioneerWalletID, _, _, found := s.getIntervalPublicKeyId(pioneers[i], types.PioneerNodeType)
		if !found {
			c.LoggerError(logger, "BAD!  Couldn't find walletID for pioneerID "+pioneers[i])
			err = types.ErrKeyNotFound
			return
		}
		enclavePubK, found := s.getPublicKey(pioneerWalletID, types.EnclavePubKType)
		if !found {
			c.LoggerError(logger, "BAD!  Couldn't find enclave pubk for pioneerID "+pioneers[i])
			err = types.ErrKeyNotFound
			return
		}
		var gShare types.Share
		gShare.PioneerID = pioneers[i]
		gShare.EncEnclaveShare = c.MarshalAndBEncrypt(enclavePubK, share)
		gShares = append(gShares, &gShare)
	}

	// ss
	var report []byte

	var b []byte
	b, err = json.Marshal(gShares)
	if err != nil {
		return
	}

	var pwalletAddr sdk.AccAddress
	pwalletAddr, err = sdk.AccAddressFromBech32(s.getPrivateEnclaveParamsPioneerWalletID())
	if err != nil {
		c.LoggerError(logger, "couldn't convert to addr", s.getPrivateEnclaveParamsPioneerWalletID(), err)
		return
	}
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		walletID,
		intervalPubK,
		types.TransactionPubKType,
		string(b),
	}, "|"))
	if err != nil {
		return
	}

	msgPAPK = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		walletID,
		intervalPubK,
		types.TransactionPubKType,
		gShares,
		report,
	)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		walletID,
		types.SSNodeID,
		types.SSNodeType,
		"",
	}, "|"))
	if err != nil {
		return
	}

	msgPUIPKI = types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		walletID,
		types.SSNodeID,
		types.SSNodeType,
		"",
		report,
	)

	b, err = json.Marshal(privKeys)
	if err != nil {
		return
	}

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		string(b),
	}, "|"))
	if err != nil {
		return
	}

	msgPBSSPK = types.NewMsgPioneerBroadcastSecretSharePrivateKey(
		pwalletAddr.String(),
		privKeys,
		report,
	)

	return
}

// GetEnclaveStatus answers the one question the chain cannot work out for itself: has this enclave
// already been given its sealed params, by InitEnclave or by SyncEnclave?
//
// The chain needs it at startup to decide whether to initialize, and every alternative it has is a
// proxy that is wrong somewhere.  InitEnclaveReply is a single bool meaning "accepted", identical
// for "I initialized now" and "I was already initialized".  Chain state (is there a JarRegulator
// row?) REWINDS during block replay -- a joiner executing block 2 sees no row, because at that
// point in history there was none, and would re-initialize an enclave that SyncEnclave had already
// set up minutes earlier.  Genesis membership answers who the node is, not what its enclave holds.
//
// Read from the same field InitEnclave short-circuits on, so the answer and the behaviour cannot
// drift apart.  Side-effect free: it is a read, safe to call before the chain has decided anything.
func (s *qadenaServer) GetEnclaveStatus(ctx context.Context, in *types.MsgGetEnclaveStatus) (*types.GetEnclaveStatusReply, error) {
	pioneerID := s.getPrivateEnclaveParamsPioneerID()
	return &types.GetEnclaveStatusReply{
		Initialized: pioneerID != "",
		PioneerID:   pioneerID,
	}, nil
}

func (s *qadenaServer) InitEnclave(ctx context.Context, in *types.MsgInitEnclave) (*types.InitEnclaveReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "InitEnclave")
	} else {
		c.LoggerDebug(logger, "InitEnclave "+c.PrettyPrint(in))
	}

	kb := clientCtx.Keyring
	_ = kb

	// Same reasoning as SyncEnclave: "initialized" means the params reached disk, not that
	// preInitEnclave populated them in memory during an attempt that then failed.
	if s.paramsPersisted && s.getPrivateEnclaveParamsPioneerID() != "" {
		c.LoggerDebug(logger, "already initialized, no need to do this again!")
		return &types.InitEnclaveReply{Status: true}, nil
	}
	if s.getPrivateEnclaveParamsPioneerID() != "" {
		c.LoggerInfo(logger, "a previous init got as far as generating keys but never persisted them -- redoing it")
	}

	pwalletID, pwalletAddr, enclaveWalletID, err := s.preInitEnclave(ctx, true, in.PioneerID, in.ExternalAddress, in.PioneerArmorPrivK, in.PioneerArmorPassPhrase)
	if err != nil {
		c.LoggerError(logger, "couldn't preInitEnclave "+err.Error())
		return nil, err
	}

	_ = enclaveWalletID // unused

	ssNewMsgPioneerAddPublicKey, ssNewMsgPioneerUpdateIntervalPublicKeyId, ssNewMsgPioneerBroadcastSecretSharePrivateKey, err := s.GenerateSecretShare(types.SSNodeID, types.SSNodeType)

	if err != nil {
		c.LoggerError(logger, "couldn't GenerateSecretShare "+err.Error())
		return nil, err
	}

	// create jar1 key
	mnemonicForJar1, err := c.GenerateNewMnemonic()
	if err != nil {
		c.LoggerError(logger, "Couldn't create new mnemonic")
		return nil, err
	}

	createPublicKeyForJar1Req := c.PublicKeyReq{
		FriendlyName:    in.JarID,
		RecoverMnemonic: mnemonicForJar1,
		IsEphemeral:     false,
		EphAccountIndex: 0,
	}

	_, _, _, _, err = c.CreatePublicKey(clientCtx, createPublicKeyForJar1Req)
	if err != nil {
		c.LoggerError(logger, "couldn't create jar key")
		return nil, err
	}
	var jarWalletID string
	jarWalletID, _, jarPubK, jarPrivK, jarArmorPrivK, err := c.GetAddressByName(clientCtx, in.JarID, ArmorPassPhrase)
	if err != nil {
		c.LoggerError(logger, "couldn't get address for "+in.JarID+" "+err.Error())
		return nil, err
	}

	s.setSharedEnclaveParamsJarInfo(in.JarID, jarPubK, jarPrivK, jarArmorPrivK)

	// create regulator1 key
	mnemonicForRegulator1, err := c.GenerateNewMnemonic()
	if err != nil {
		c.LoggerError(logger, "Couldn't create new mnemonic")
		return nil, err
	}

	createPublicKeyForRegulator1Req := c.PublicKeyReq{
		FriendlyName:    in.RegulatorID,
		RecoverMnemonic: mnemonicForRegulator1,
		IsEphemeral:     false,
		EphAccountIndex: 0,
	}

	_, _, _, _, err = c.CreatePublicKey(clientCtx, createPublicKeyForRegulator1Req)
	if err != nil {
		c.LoggerError(logger, "couldn't create regulator key")
		return nil, err
	}
	var regulatorWalletID string
	regulatorWalletID, _, regulatorPubK, regulatorPrivK, regulatorArmorPrivK, err := c.GetAddressByName(clientCtx, in.RegulatorID, ArmorPassPhrase)
	if err != nil {
		c.LoggerError(logger, "couldn't get address for "+in.RegulatorID+" "+err.Error())
		return nil, err
	}

	s.setSharedEnclaveParamsRegulatorInfo(in.RegulatorID, regulatorPubK, regulatorPrivK, regulatorArmorPrivK)

	if s.RealEnclave {
		c.LoggerDebug(logger, "keyring (redacted)")
	} else {
		c.LoggerDebug(logger, "keyring "+c.PrettyPrint(clientCtx.Keyring))
	}

	msgs := make([]sdk.Msg, 0)

	report, err := s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsEnclavePubK(),
		types.EnclavePubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg := types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsEnclavePubK(),
		types.EnclavePubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	//
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		in.ExternalAddress,
	}, "|"))
	if err != nil {
		return nil, err
	}

	msg2 := types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		in.ExternalAddress,
		report,
	)
	msgs = append(msgs, msg2)

	// ss
	msgs = append(msgs, ssNewMsgPioneerAddPublicKey)

	// jar
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		jarWalletID,
		s.getSharedEnclaveParamsJarPubK(),
		types.CredentialPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		jarWalletID,
		s.getSharedEnclaveParamsJarPubK(),
		types.CredentialPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		jarWalletID,
		s.getSharedEnclaveParamsJarPubK(),
		types.TransactionPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		jarWalletID,
		s.getSharedEnclaveParamsJarPubK(),
		types.TransactionPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	// regulator
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		regulatorWalletID,
		s.getSharedEnclaveParamsRegulatorPubK(),
		types.CredentialPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		regulatorWalletID,
		s.getSharedEnclaveParamsRegulatorPubK(),
		types.CredentialPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		regulatorWalletID,
		s.getSharedEnclaveParamsRegulatorPubK(),
		types.TransactionPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		regulatorWalletID,
		s.getSharedEnclaveParamsRegulatorPubK(),
		types.TransactionPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	// update interval bindings

	// ss

	msgs = append(msgs, ssNewMsgPioneerUpdateIntervalPublicKeyId)

	_ = ssNewMsgPioneerBroadcastSecretSharePrivateKey

	// jar
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		jarWalletID,
		s.getSharedEnclaveParamsJarID(),
		types.JarNodeType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg2 = types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		jarWalletID,
		s.getSharedEnclaveParamsJarID(),
		types.JarNodeType,
		"",
		report,
	)
	msgs = append(msgs, msg2)

	// regulator
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		regulatorWalletID,
		s.getSharedEnclaveParamsRegulatorID(),
		types.RegulatorNodeType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg2 = types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		regulatorWalletID,
		s.getSharedEnclaveParamsRegulatorID(),
		types.RegulatorNodeType,
		"",
		report,
	)
	msgs = append(msgs, msg2)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		s.getSharedEnclaveParamsJarID(),
		s.getSharedEnclaveParamsRegulatorID(),
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg3 := types.NewMsgPioneerUpdateJarRegulator(
		pwalletAddr.String(),
		s.getSharedEnclaveParamsJarID(),
		s.getSharedEnclaveParamsRegulatorID(),
		report,
	)
	msgs = append(msgs, msg3)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		s.getPrivateEnclaveParamsPioneerID(),
		s.getSharedEnclaveParamsJarID(),
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg4 := types.NewMsgPioneerUpdatePioneerJar(
		pwalletAddr.String(),
		s.getPrivateEnclaveParamsPioneerID(),
		s.getSharedEnclaveParamsJarID(),
		report,
	)
	msgs = append(msgs, msg4)

	flagSet := RootCmd.Flags()

	/*
		flagSet.Set(flags.FlagGas, "4000000")

		flagSet.Set(flags.FlagGasPrices, "100000aqdn")
	*/

	c.LoggerDebug(logger, "msgs "+c.PrettyPrint(msgs))

	clientCtx = clientCtx.WithFrom(pwalletID).WithFromAddress(pwalletAddr).WithFromName(s.getPrivateEnclaveParamsPioneerID())
	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "various update msgs in InitEnclave", msgs...)

	if err != nil {
		c.LoggerError(logger, "failed to broadcast "+err.Error())
		return nil, err
	}

	// seal it
	status := s.saveEnclaveParams()
	if !status {
		c.LoggerError(logger, "couldn't save enclave parms")
		return &types.InitEnclaveReply{Status: false}, nil
	}

	return &types.InitEnclaveReply{Status: status}, nil
}

func (s *qadenaServer) UpdateHeight(ctx context.Context, in *types.MsgUpdateHeight) (*types.UpdateHeightReply, error) {
	c.LoggerDebug(logger, "UpdateHeight "+c.PrettyPrint(in))

	// Remember where the chain is and whether we are watching it happen or replaying it.  Every
	// trust decision below consults these two: an attestation's age is measured against the height,
	// and historical blocks must not restate current trust.  Logged on transition only -- per-block
	// would drown the log, and the transition is the interesting event.
	if setChainPosition(in.Height, in.IsLive) {
		if in.IsLive {
			c.LoggerInfo(logger, "chain is LIVE at height "+strconv.FormatInt(in.Height, 10)+" -- trust changes now apply")
			// Catching up is over, so settle what catching up deferred: honour deactivations we
			// skipped, and queue for validation anything the chain considers active that we do not
			// trust.  Runs on the transition only, not per block.
			go s.reconcileTrustOnGoingLive()
		} else {
			c.LoggerInfo(logger, "chain is REPLAYING at height "+strconv.FormatInt(in.Height, 10)+" -- trust changes are deferred until caught up")
		}
	}

	if in.IsProposer {
		if !s.getPrivateEnclaveParamsPioneerIsValidator() {
			go func() {
				c.LoggerDebug(logger, "is a proposer, but not yet a validator from the standpoint of this enclave")

				if s.getPrivateEnclaveParamsPioneerID() != "" {
					if !s.updateIsValidator() {
						c.LoggerError(logger, "failed updateIsValidator()")
					}
				} else {
					c.LoggerError(logger, "pioneerID is empty, not initialized yet, will not call updateIsValidator() yet")
				}
			}()
		}

		if in.Height%keyUpdateFrequency == 0 {
			go func() {
				if !s.updateSSIntervalKey() {
					c.LoggerError(logger, "failed updateSSIntervalKey()")
				}
			}()
		}

	}

	unvalidatedEnclaveIdentitiesCheckCounter--
	c.LoggerDebug(logger, "unvalidatedEnclaveIdentitiesCheckCounter "+c.PrettyPrint(unvalidatedEnclaveIdentitiesCheckCounter))
	if unvalidatedEnclaveIdentitiesCheckCounter == 0 {
		// EVERY NODE DECIDES; ONLY THE PROPOSER BROADCASTS.
		//
		// These were one action, gated together on IsProposer, which left a plain full node unable
		// to resolve anything it had queued -- it never proposes, so it never asked peers, so trust
		// it missed while replaying stayed missed.  They are separate concerns: deciding updates
		// only our own trusted set and is every node's business, while broadcasting the verdict must
		// stay single-writer or every node floods the same transaction.
		broadcast := in.IsProposer
		go func() {
			c.LoggerDebug(logger, "checking for unvalidated enclave identities (broadcast="+strconv.FormatBool(broadcast)+")")
			s.validateEnclaveIdentities(broadcast)
		}()
		// set it to max to a large number to prevent it from firing again
		unvalidatedEnclaveIdentitiesCheckCounter = keyUpdateFrequency
	}

	return &types.UpdateHeightReply{Status: true}, nil
}

func (s *qadenaServer) updateSSIntervalKey() bool {
	c.LoggerDebug(logger, "updateSSIntervalKey")

	c.LoggerDebug(logger, "Going to create a new SS share")
	// create a new interval key if we are the leader
	if s.RealEnclave {
		c.LoggerDebug(logger, "enclaveParams (redacted)")
	} else {
		c.LoggerDebug(logger, "enclaveParams"+c.PrettyPrint(s.privateEnclaveParams))
	}

	ssNewMsgPioneerAddPublicKey, ssNewMsgPioneerUpdateIntervalPublicKeyId, ssNewMsgPioneerBroadcastSecretSharePrivateKey, err := s.GenerateSecretShare(types.SSNodeID, types.SSNodeType)
	msgs := make([]sdk.Msg, 0)
	msgs = append(msgs, ssNewMsgPioneerAddPublicKey)
	msgs = append(msgs, ssNewMsgPioneerUpdateIntervalPublicKeyId)
	msgs = append(msgs, ssNewMsgPioneerBroadcastSecretSharePrivateKey)

	flagSet := RootCmd.Flags()

	/*
		flagSet.Set(flags.FlagGas, "4000000")

		flagSet.Set(flags.FlagGasPrices, "100000aqdn")
	*/

	if s.RealEnclave {
		c.LoggerDebug(logger, "msgs (redacted)")
	} else {
		c.LoggerDebug(logger, "msgs "+c.PrettyPrint(msgs))
	}

	var pwalletAddr sdk.AccAddress
	pwalletAddr, err = sdk.AccAddressFromBech32(s.getPrivateEnclaveParamsPioneerWalletID())
	if err != nil {
		c.LoggerError(logger, "couldn't convert to addr "+s.getPrivateEnclaveParamsPioneerWalletID()+" "+err.Error())
		return false
	}

	clientCtx = clientCtx.WithFrom(s.getPrivateEnclaveParamsPioneerWalletID()).WithFromAddress(pwalletAddr).WithFromName(s.getPrivateEnclaveParamsPioneerID())
	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "various update msgs in UpdateHeight", msgs...)

	if err != nil {
		c.LoggerError(logger, "failed to broadcast "+err.Error())
		return false
	}

	// seal it -- but only if the params actually changed.
	//
	// This call persists nothing today: the rotation's durable writes all go through addSSShare
	// -> setOwnersAndShare / setPrivKCache / setPubKCache, none of which touch
	// privateEnclaveParams or sharedEnclaveParams.  That holds at the repo root commit and at
	// every commit since.  The history is SQUASHED, though, so an earlier version may well have
	// needed it -- which is why the call stays rather than being deleted on the strength of a
	// history that cannot be fully read.
	//
	// What is removed is the needless REWRITE.  This runs every keyUpdateFrequency (555) blocks
	// -- roughly every 14 minutes at 1.5s blocks -- and enclave_params_<uniqueID>.json holds
	// SealedTableSharedSecret, the key to every stable-sealed row in both stores, with no backup
	// (enclave_params_backup.json is gated on testSeal, a hard-coded false).  Every rewrite is a
	// window in which a crash leaves that file torn and every sealed row permanently unreadable.
	// MustSeal draws a fresh nonce per call, so the bytes differed on every write even though the
	// plaintext never did: ~100 needless exposures a day, forever.
	//
	// saveEnclaveParamsIfChanged keeps whatever the original intent was -- if some future path
	// does start mutating params during a rotation, it saves, automatically -- while writing
	// nothing when there is nothing to write.
	status := s.saveEnclaveParamsIfChanged()
	if !status {
		c.LoggerError(logger, "couldn't save enclave parms")
		return false
	}

	return true
}

func (s *qadenaServer) updateIsValidator() bool {
	c.LoggerDebug(logger, "is a proposer, but not yet a validator from the standpoint of the enclave")
	// we need to update the interval public key with the external IP address
	//
	pwalletID, pwalletAddr, _, _, err := c.GetAddressByNameNoArmor(clientCtx, s.getPrivateEnclaveParamsPioneerID())
	report, err := s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		s.getPrivateEnclaveParamsPioneerExternalIPAddress(),
	}, "|"))
	if err != nil {
		c.LoggerError(logger, "couldn't getRemoteReport "+err.Error())
		return false
	}
	msg := types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		s.getPrivateEnclaveParamsPioneerExternalIPAddress(),
		report,
	)

	msgs := make([]sdk.Msg, 0)
	msgs = append(msgs, msg)

	flagSet := RootCmd.Flags()

	/*
		flagSet.Set(flags.FlagGas, "4000000")

		flagSet.Set(flags.FlagGasPrices, "100000aqdn")
	*/

	if s.RealEnclave {
		c.LoggerDebug(logger, "msgs (redacted)")
	} else {
		c.LoggerDebug(logger, "msgs "+c.PrettyPrint(msgs))
	}

	clientCtx = clientCtx.WithFrom(pwalletID).WithFromAddress(pwalletAddr).WithFromName(s.getPrivateEnclaveParamsPioneerID())
	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "external IP address of this pioneer", msgs...)

	if err != nil {
		c.LoggerError(logger, "failed to broadcast "+err.Error())
		return false
	}

	s.setPrivateEnclaveParamsPioneerIsValidator(true)

	// seal it
	status := s.saveEnclaveParams()
	if !status {
		c.LoggerError(logger, "couldn't save enclave parms")
		return false
	}
	return true
}

func (s *qadenaServer) AddAsValidator(ctx context.Context, in *types.MsgAddAsValidator) (*types.AddAsValidatorReply, error) {
	c.LoggerDebug(logger, "AddAsValidator "+c.PrettyPrint(in))

	if s.getPrivateEnclaveParamsPioneerID() == "" {
		c.LoggerDebug(logger, "not yet initialized")
		return &types.AddAsValidatorReply{Status: false}, nil
	}

	//	kb := clientCtx.Keyring

	queryClient := types.NewQueryClient(clientCtx)
	params := &types.QueryGetPioneerJarRequest{
		PioneerID: s.getPrivateEnclaveParamsPioneerID(),
	}

	res, err := queryClient.PioneerJar(context.Background(), params)

	if err != nil && !strings.Contains(err.Error(), "Key not found") {
		c.LoggerError(logger, "unable to query the chain")
		return nil, err
	} else if err == nil {
		if res.GetPioneerJar().JarID == s.getSharedEnclaveParamsJarID() {
			c.LoggerError(logger, "Already initialized")
			return &types.AddAsValidatorReply{Status: true}, nil
		} else {
			c.LoggerError(logger, "Already initialized, but the jar is wrong! "+s.getSharedEnclaveParamsJarID()+" chain value is "+res.GetPioneerJar().JarID)
		}
	}

	//  fmt.Println("err " + err.Error().Error())
	//  fmt.Println("res", res)

	pwalletID, pwalletAddr, _, _, err := c.GetAddressByNameNoArmor(clientCtx, s.getPrivateEnclaveParamsPioneerID())

	msgs := make([]sdk.Msg, 0)

	// enclave
	report, err := s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsEnclavePubK(),
		types.EnclavePubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg := types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsEnclavePubK(),
		types.EnclavePubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	// pioneer
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.CredentialPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.CredentialPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.TransactionPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.TransactionPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	// update interval bindings

	//
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg2 := types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		"",
		report,
	)
	msgs = append(msgs, msg2)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		s.getPrivateEnclaveParamsPioneerID(),
		s.getSharedEnclaveParamsJarID(),
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg4 := types.NewMsgPioneerUpdatePioneerJar(
		pwalletAddr.String(),
		s.getPrivateEnclaveParamsPioneerID(),
		s.getSharedEnclaveParamsJarID(),
		report,
	)
	msgs = append(msgs, msg4)

	flagSet := RootCmd.Flags()

	/*
		flagSet.Set(flags.FlagGas, "4000000")

		flagSet.Set(flags.FlagGasPrices, "100000aqdn")
	*/

	clientCtx = clientCtx.WithFrom(pwalletID).WithFromAddress(pwalletAddr).WithFromName(s.getPrivateEnclaveParamsPioneerID())
	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "various update msgs in InitEnclave", msgs...)

	if err != nil {
		c.LoggerError(logger, "failed to broadcast "+err.Error())
		return nil, err
	}

	return &types.AddAsValidatorReply{Status: true}, nil
}

// these enclave-to-enclave queries come in through the blockchain's query interface

func (s *qadenaServer) QueryEnclaveSyncEnclave(goCtx context.Context, in *types.QueryEnclaveSyncEnclaveRequest) (*types.QueryEnclaveSyncEnclaveResponse, error) {
	if err := s.refuseIfCatchingUp("sync-enclave (the jar and regulator keys)"); err != nil {
		return nil, err
	}
	if s.RealEnclave {
		c.LoggerDebug(logger, "QueryEnclaveSyncEnclave")
	} else {
		c.LoggerDebug(logger, "QueryEnclaveSyncEnclave "+c.PrettyPrint(in))
	}

	// need to validate the incoming request's remote report before we response back
	if !s.verifyRemoteReport(
		in.RemoteReport,
		strings.Join([]string{
			in.EnclavePubK,
		}, "|")) {
		return nil, types.ErrRemoteReportNotVerified
	}

	// clear out our enclave/pioneer-specific keys before transmitting
	tmpEnclaveParams := s.sharedEnclaveParams

	// ADVERTISE OUR TRUSTED SET.  This is the joiner's root of trust: it arrives with {self} and no
	// way to establish anything else -- genesis names measurements with no attestation attached, and
	// every quorum query it could make is itself gated on trust it does not yet have.
	//
	// Active entries only.  A joiner should not inherit trust the chain has already retired, and an
	// unvalidated entry is a judgement still in progress which it will see resolve through the
	// normal broadcast like everyone else.
	//
	// It rides inside the encrypted payload, so the remote report generated over the ciphertext
	// below already covers it: no new plaintext field, no second attestation.
	tmpEnclaveParams.ActiveEnclaveIdentities = s.activeTrustedEnclaveIdentities()
	c.LoggerInfo(logger, "sync-enclave: advertising "+strconv.Itoa(len(tmpEnclaveParams.ActiveEnclaveIdentities))+" active enclave identities to the joiner")

	// send these for now
	//	JarID         string
	//	JarArmorPrivK string
	//	JarPrivK      string
	//	JarPubK       string

	//	RegulatorID         string
	//	RegulatorArmorPrivK string
	//	RegulatorPrivK      string
	//	RegulatorPubK       string

	// do not send the SSIntervalShares
	// do not send our local private key cache

	// remove first intentionally send the public key cache
	//  tmpEnclaveParams.SSIntervalPubKCache = s.exportTable(EnclaveSSIntervalPubKKeyPrefix)

	// LEGACY, UNPAGED.  A caller that sends maxBytes == 0 predates paging, so answer the way we
	// always did.  Keeping this path is what lets a NEW joiner talk to an OLD seed and vice versa
	// during an upgrade window -- and sync-enclave is exactly where the two ends differ in version,
	// since it is how a fresh node meets an established one.
	if in.MaxBytes == 0 {
		// intentionally send the SSIntervalOwners
		tmpEnclaveParams.SSIntervalOwners = s.getAllOwners()

		enc := c.ProtoMarshalAndBEncrypt(in.EnclavePubK, &tmpEnclaveParams)

		report, err := s.getRemoteReport(strings.Join([]string{
			string(enc),
		}, "|"))
		if err != nil {
			return nil, err
		}

		return &types.QueryEnclaveSyncEnclaveResponse{RemoteReport: report,
			EncEnclaveParamsEnclavePubK: enc,
		}, nil
	}

	// PAGED.  SSIntervalOwners is the only field that grows with chain age -- one entry per
	// keyUpdateFrequency (555) blocks -- so it is the only one that pages.  The fixed-size key
	// material rides along on the first page.
	budget := int(in.MaxBytes)
	if budget > syncEnclavePageMaxBytes {
		budget = syncEnclavePageMaxBytes
	}

	owners, nextCursor, done := s.getOwnersPage(string(in.Cursor), budget)

	page := types.EncryptableSyncEnclavePage{
		SSIntervalOwners: owners,
		NextCursor:       []byte(nextCursor),
		Done:             done,
	}
	if len(in.Cursor) == 0 {
		// First page only.  SSIntervalOwners is left nil inside params -- the owners travel in the
		// page's own field so that every page carries them identically.
		tmpEnclaveParams.SSIntervalOwners = nil
		page.Params = &tmpEnclaveParams
	}

	enc := c.ProtoMarshalAndBEncrypt(in.EnclavePubK, &page)

	report, err := s.getRemoteReport(strings.Join([]string{
		string(enc),
	}, "|"))
	if err != nil {
		return nil, err
	}

	return &types.QueryEnclaveSyncEnclaveResponse{RemoteReport: report,
		EncSyncEnclavePagePubK: enc,
	}, nil
}

const (
	// Mirrors the private-state transfer: aim for 1 MiB, refuse to build more than 3 MiB, so a
	// single reply cannot approach gRPC's 4 MiB default message limit.
	syncEnclavePageTargetBytes = 1 << 20
	syncEnclavePageMaxBytes    = 3 << 20

	// A runaway-loop backstop, not a real limit.  At the 1 MiB target this is far more owners than
	// any plausible chain: 10M blocks yields ~18,000 entries, which is a handful of pages.
	syncEnclaveMaxPages = 1024
)

// getOwnersPage returns the slice of SSIntervalOwners that follows cursor, up to roughly budget
// bytes.  An empty cursor starts at the beginning; done reports that this page reached the end.
//
// The keys are SORTED, which is what makes the cursor a stable position: store.Keys() gives no
// ordering guarantee, and paging an unordered scan would silently skip or duplicate entries between
// calls.  A skipped interval is not a visible error -- it becomes a getSSPrivK that returns "" long
// afterwards.
func (s *qadenaServer) getOwnersPage(cursor string, budget int) (page map[string]*types.EncryptablePioneerIDs, nextCursor string, done bool) {
	store := s.secrets(EnclaveSSIntervalOwnersKeyPrefix)

	// Keys() is a snapshot, so getOwners below re-acquires the secrets lock safely
	keys := make([]string, 0)
	for _, key := range store.Keys() {
		keys = append(keys, string(key[:len(key)-1]))
	}
	sort.Strings(keys)

	page = make(map[string]*types.EncryptablePioneerIDs)
	used := 0
	for _, key := range keys {
		if cursor != "" && key <= cursor {
			continue
		}
		owners, found := s.getOwners(key)
		if !found {
			c.LoggerDebug(logger, "couldn't find in owners db")
			continue
		}
		page[key] = &owners
		nextCursor = key

		// Estimate rather than re-marshal the whole page each iteration: the budget only has to
		// keep us clear of the gRPC limit, and being a few hundred bytes out does not matter.
		used += len(key) + 8
		for _, id := range owners.PioneerIDs {
			used += len(id) + 2
		}
		if used >= budget {
			return page, nextCursor, false
		}
	}
	return page, nextCursor, true
}

func (s *qadenaServer) QueryEnclaveValidateEnclaveIdentity(goCtx context.Context, in *types.QueryEnclaveValidateEnclaveIdentityRequest) (*types.QueryEnclaveValidateEnclaveIdentityResponse, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "QueryEnclaveValidateEnclaveIdentity")
	} else {
		c.LoggerDebug(logger, "QueryEnclaveValidateEnclaveIdentity "+c.PrettyPrint(in))
	}

	// need to validate the incoming request's remote report before we response back
	if !s.verifyRemoteReport(
		in.RemoteReport,
		strings.Join([]string{
			in.UniqueID,
			in.SignerID,
			in.ProductID,
		}, "|")) {
		return nil, types.ErrRemoteReportNotVerified
	}

	found := s.getEnclaveIdentity(in.UniqueID, in.SignerID, true) // get active and unvalidated ones

	status := types.InactiveStatus
	if found {
		status = types.ActiveStatus
	}

	report, err := s.getRemoteReport(strings.Join([]string{
		status,
	}, "|"))
	if err != nil {
		return nil, err
	}

	return &types.QueryEnclaveValidateEnclaveIdentityResponse{RemoteReport: report,
		Status: status,
	}, nil
}

func (s *qadenaServer) QueryEnclaveSecretShare(goCtx context.Context, in *types.QueryEnclaveSecretShareRequest) (*types.QueryEnclaveSecretShareResponse, error) {
	if err := s.refuseIfCatchingUp("a secret share"); err != nil {
		return nil, err
	}
	if s.RealEnclave {
		c.LoggerDebug(logger, "QueryEnclaveSecretShare")
	} else {
		c.LoggerDebug(logger, "QueryEnclaveSecretShare "+c.PrettyPrint(in))
	}

	// need to validate the incoming request's remote report before we response back
	if !s.verifyRemoteReport(
		in.RemoteReport,
		strings.Join([]string{
			in.EnclavePubK,
			in.PubKID,
		}, "|")) {
		return nil, types.ErrRemoteReportNotVerified
	}

	share, found := s.getShare(in.PubKID)

	if !found || share == "" {
		c.LoggerError(logger, "Could not find share for "+in.PubKID)
		return nil, types.ErrKeyNotFound
	}

	encSecretShareEncPubK := c.MarshalAndBEncrypt(in.EnclavePubK, share)

	report, err := s.getRemoteReport(strings.Join([]string{
		string(encSecretShareEncPubK),
	}, "|"))
	if err != nil {
		return nil, err
	}

	return &types.QueryEnclaveSecretShareResponse{RemoteReport: report,
		EncSecretShareEnclavePubK: encSecretShareEncPubK,
	}, nil
}

func (s *qadenaServer) QueryEnclaveRecoverKeyShare(goCtx context.Context, in *types.QueryEnclaveRecoverKeyShareRequest) (*types.QueryEnclaveRecoverKeyShareResponse, error) {
	if err := s.refuseIfCatchingUp("a recover-key share"); err != nil {
		return nil, err
	}
	if s.RealEnclave {
		c.LoggerDebug(logger, "QueryEnclaveRecoverKeyShare")
	} else {
		c.LoggerDebug(logger, "QueryEnclaveRecoverKeyShare "+c.PrettyPrint(in))
	}

	// need to validate the incoming request's remote report before we response back
	if !s.verifyRemoteReport(
		in.RemoteReport,
		strings.Join([]string{
			in.NewWalletID,
			in.ShareWalletID,
			string(in.EncShareWalletPubK),
		}, "|")) {
		return nil, types.ErrRemoteReportNotVerified
	}

	newWalletID := in.NewWalletID
	shareWalletID := in.ShareWalletID
	encShareWalletPubK := in.EncShareWalletPubK

	originalWalletID, found := s.getRecoverOriginalWalletIDByNewWalletID(newWalletID)
	if !found {
		c.LoggerError(logger, "couldn't find original wallet being recovered by "+newWalletID)
		return nil, types.ErrKeyNotFound
	}

	recoverKey, found := s.getRecoverKeyByOriginalWalletID(originalWalletID)
	if !found {
		c.LoggerError(logger, "couldn't find recoverKey by "+originalWalletID)
		return nil, types.ErrKeyNotFound
	}

	protectKey, found := s.getProtectKey(originalWalletID)
	if !found {
		c.LoggerError(logger, "couldn't find protectKey by "+originalWalletID)
		return nil, types.ErrKeyNotFound
	}

	if shareWalletID != s.getPrivateEnclaveParamsPioneerID() {
		c.LoggerError(logger, "wrong pioneer to ask "+s.getPrivateEnclaveParamsPioneerID())
		return nil, types.ErrInvalidQueryRecoverKeyShare
	}

	credPubK, found := s.getPublicKey(newWalletID, types.CredentialPubKType)

	if !found {
		return nil, types.ErrInvalidQueryRecoverKeyShare
	}

	found = false

	var newEncShareWalletPubK []byte

	rShares := recoverKey.RecoverShare
	rShares = append(rShares, protectKey.RecoverShare...)

	for _, rShare := range rShares {
		if s.RealEnclave {
			c.LoggerDebug(logger, "processing rShare (redacted)")
		} else {
			c.LoggerDebug(logger, "processing rShare "+c.PrettyPrint(rShare))
		}
		var err error

		if rShare.WalletID == shareWalletID && bytes.Equal(rShare.EncWalletPubKShare, encShareWalletPubK) {
			c.LoggerDebug(logger, "decrypting locally")
			// special processing if only 1
			if protectKey.Threshold == 1 {
				var shareString string
				_, err = c.BDecryptAndUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), rShare.EncWalletPubKShare, &shareString)
				if err != nil {
					c.LoggerError(logger, "couldn't decrypt "+err.Error())
					return nil, types.ErrInvalidQueryRecoverKeyShare
				}
				newEncShareWalletPubK = c.MarshalAndBEncrypt(credPubK, shareString)
			} else {
				var shareString string
				_, err = c.BDecryptAndUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), rShare.EncWalletPubKShare, &shareString)
				if err != nil {
					c.LoggerError(logger, "couldn't decrypt "+err.Error())
					return nil, types.ErrInvalidQueryRecoverKeyShare
				}
				newEncShareWalletPubK = c.MarshalAndBEncrypt(credPubK, shareString)
			}
			found = true
			break
		}
	}

	if !found {
		c.LoggerDebug(logger, "couldn't find the share to decrypt")
		return nil, types.ErrInvalidQueryRecoverKeyShare
	}

	report, err := s.getRemoteReport(strings.Join([]string{
		string(newEncShareWalletPubK),
	}, "|"))
	if err != nil {
		return nil, err
	}

	return &types.QueryEnclaveRecoverKeyShareResponse{
		RemoteReport:       report,
		EncShareWalletPubK: newEncShareWalletPubK,
	}, nil
}

func (s *qadenaServer) QueryGetRecoverKey(goCtx context.Context, in *types.QueryGetRecoverKeyRequest) (*types.QueryGetRecoverKeyResponse, error) {
	if err := s.refuseIfCatchingUp("a recover key"); err != nil {
		return nil, err
	}
	if s.RealEnclave {
		c.LoggerDebug(logger, "QueryGetRecoverKey")
	} else {
		c.LoggerDebug(logger, "QueryGetRecoverKey "+c.PrettyPrint(in))
	}

	newWalletID := in.WalletID

	originalWalletID, found := s.getRecoverOriginalWalletIDByNewWalletID(newWalletID)
	if !found {
		c.LoggerError(logger, "couldn't find original wallet being recovered by "+newWalletID)
		return nil, types.ErrKeyNotFound
	}

	recoverKey, found := s.getRecoverKeyByOriginalWalletID(originalWalletID)
	if !found {
		c.LoggerError(logger, "couldn't find recoverKey by "+originalWalletID)
		return nil, types.ErrKeyNotFound
	}

	protectKey, found := s.getProtectKey(originalWalletID)
	if !found {
		c.LoggerError(logger, "couldn't find protectKey by "+originalWalletID)
		return nil, types.ErrKeyNotFound
	}

	if len(recoverKey.Signatory) < int(protectKey.Threshold) {
		c.LoggerError(logger, "Not enough signatories")
		return nil, types.ErrNotEnoughSignatoriesQueryGetRecoverKey
	}

	var recoverShare []*types.RecoverShare

	credPubK, found := s.getPublicKey(newWalletID, types.CredentialPubKType)

	if !found {
		return nil, types.ErrInvalidQueryGetRecoverKey
	}

	count := protectKey.Threshold

	rShares := recoverKey.RecoverShare
	rShares = append(rShares, protectKey.RecoverShare...)

	var encWalletPubKShare []byte

	for _, rShare := range rShares {
		if s.RealEnclave {
			c.LoggerDebug(logger, "processing rShare (redacted)")
		} else {
			c.LoggerDebug(logger, "processing rShare "+c.PrettyPrint(rShare))
		}
		var err error
		if rShare.WalletID == s.getPrivateEnclaveParamsPioneerID() {
			c.LoggerDebug(logger, "decrypting locally")
			// special processing if <= 1
			if protectKey.Threshold <= 1 {
				var shareString string
				_, err = c.BDecryptAndUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), rShare.EncWalletPubKShare, &shareString)
				if err != nil {
					c.LoggerError(logger, "couldn't decrypt "+err.Error())
					continue
				}
				encWalletPubKShare = c.MarshalAndBEncrypt(credPubK, shareString)
			} else {
				var shareString string
				_, err = c.BDecryptAndUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), rShare.EncWalletPubKShare, &shareString)
				if err != nil {
					c.LoggerError(logger, "couldn't decrypt "+err.Error())
					continue
				}
				encWalletPubKShare = c.MarshalAndBEncrypt(credPubK, shareString)
			}

		} else {
			// need to do this remotely
			// check if the walletID is a pioneerID
			shareWalletID := rShare.WalletID
			encShareWalletPubK := rShare.EncWalletPubKShare
			_, _, _, found := s.getIntervalPublicKeyId(shareWalletID, types.PioneerNodeType)
			if !found {
				c.LoggerDebug(logger, "not a PioneerID "+shareWalletID)
				continue
			}
			c.LoggerDebug(logger, "PioneerID "+shareWalletID)

			pioneerIP, found := s.getPioneerIPAddress(shareWalletID)
			if !found {
				c.LoggerDebug(logger, "can't find IP")
				continue
			}
			node := "tcp://" + pioneerIP + ":26657"
			RootCmd.Flags().Set(flags.FlagNode, node)
			queryClientCtx, err := client.ReadPersistentCommandFlags(clientCtx, RootCmd.Flags())

			queryClient := types.NewQueryClient(queryClientCtx)

			c.LoggerDebug(logger, "Calling QueryEnclaveRecoverKeyShare newWalletID "+newWalletID+"shareWalletID "+shareWalletID+" encShareWalletPubK "+string(encShareWalletPubK))

			report, err := s.getRemoteReport(strings.Join([]string{
				newWalletID,
				shareWalletID,
				string(encShareWalletPubK),
			}, "|"))
			if err != nil {
				c.LoggerError(logger, "s.getRemoteReport error "+err.Error())
				continue
			}

			params := &types.QueryEnclaveRecoverKeyShareRequest{
				RemoteReport:       report,
				NewWalletID:        newWalletID,
				ShareWalletID:      shareWalletID,
				EncShareWalletPubK: encShareWalletPubK,
			}

			if s.RealEnclave {
				c.LoggerDebug(logger, "params (redacted)")
			} else {
				c.LoggerDebug(logger, "params "+c.PrettyPrint(params))
			}

			res, err := queryClient.EnclaveRecoverKeyShare(context.Background(), params)
			if err != nil {
				c.LoggerError(logger, "err "+err.Error())
				continue
			}

			c.LoggerDebug(logger, "EnclaveRecoverKeyShare returned OK")

			if !s.verifyRemoteReport(
				res.GetRemoteReport(),
				strings.Join([]string{
					string(res.GetEncShareWalletPubK()),
				}, "|")) {
				c.LoggerError(logger, "remote report unverified")
				continue
			}

			encWalletPubKShare = res.GetEncShareWalletPubK()

			c.LoggerDebug(logger, "encWalletPubKShare "+string(encWalletPubKShare))
		}

		recoverShare = append(recoverShare, &types.RecoverShare{
			WalletID:           in.WalletID,
			EncWalletPubKShare: encWalletPubKShare,
		})

		count--
		if count == 0 {
			break
		}
	}

	if count > 0 {
		c.LoggerError(logger, "couldn't get enough shares")
		return nil, types.ErrInvalidQueryGetRecoverKey
	}

	// construct a response
	retRecoverKey := types.RecoverKey{
		WalletID:     in.WalletID,
		Signatory:    recoverKey.Signatory,
		RecoverShare: recoverShare,
	}

	return &types.QueryGetRecoverKeyResponse{
		RecoverKey: retRecoverKey,
	}, nil
}

func (s *qadenaServer) QueryFindCredential(goCtx context.Context, in *types.QueryFindCredentialRequest) (*types.QueryFindCredentialResponse, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "QueryFindCredential")
	} else {
		c.LoggerDebug(logger, "QueryFindCredential "+c.PrettyPrint(in))
	}

	credential, found := s.getCredentialByPCXY(in.CredentialPC, in.CredentialType)
	if !found {
		c.LoggerDebug(logger, "can't find credential by "+hex.EncodeToString(in.CredentialPC)+"."+in.CredentialType)
		return nil, types.ErrCredentialNotExists
	}

	//  credential, found := s.getCredential(credentialID, in.CredentialType)
	//  if !found {
	//    c.LoggerDebug(logger, "can't find credential by " + credentialID)
	//		return nil, types.ErrCredentialNotExists
	//  }

	privK := s.getSSPrivK(in.SSIntervalPubKID)
	if privK == "" {
		c.LoggerError(logger, "Couldn't find privk for "+in.SSIntervalPubKID)
		return nil, types.ErrGenericEncryption
	}

	var userCredentialPubK string

	_, err := c.BDecryptAndUnmarshal(privK, in.EncUserCredentialPubKSSIntervalPubK, &userCredentialPubK)

	if err != nil {
		c.LoggerError(logger, "Couldn't decrypt the user credential pubk")
		return nil, err
	}

	c.LoggerDebug(logger, "userCredentialPubK "+userCredentialPubK)

	if s.RealEnclave {
		c.LoggerDebug(logger, "credential (redacted)")
	} else {
		c.LoggerDebug(logger, "credential "+c.PrettyPrint(credential))
	}

	var bproofPC types.BPedersenCommit

	_, err = c.BDecryptAndProtoUnmarshal(privK, in.EncProofPCSSIntervalPubK, &bproofPC)

	if err != nil {
		c.LoggerError(logger, "Couldn't decrypt the proof pc")
		return nil, err
	}

	proofPC := c.UnprotoizeBPedersenCommit(&bproofPC)

	var bcheckPC types.EncryptablePedersenCommit

	_, err = c.BDecryptAndProtoUnmarshal(privK, in.EncCheckPCSSIntervalPubK, &bcheckPC)

	checkPC := c.UnprotoizeEncryptablePedersenCommit(&bcheckPC)

	if err != nil {
		c.LoggerError(logger, "Couldn't decrypt the check pc")
		return nil, err
	}

	credentialPC := c.UnprotoizeBPedersenCommit(credential.FindCredentialPedersenCommit)

	if s.RealEnclave {
		c.LoggerDebug(logger, "credentialPC/proofPC/checkPC (redacted)")
	} else {
		c.LoggerDebug(logger, "credentialPC "+c.PrettyPrint(credentialPC))
		c.LoggerDebug(logger, "proofPC "+c.PrettyPrint(proofPC))
		c.LoggerDebug(logger, "checkPC "+c.PrettyPrint(checkPC))
	}

	if checkPC.A.Cmp(c.BigIntZero) != 0 {
		if c.Debug {
			c.LoggerError(logger, "failed to validate checkPC has amount = 0")
		}
		return nil, types.ErrGenericPedersen
	}

	if !c.ValidatePedersenCommit(checkPC) {
		if c.Debug {
			c.LoggerError(logger, "failed to validate checkPC")
		}
		return nil, types.ErrGenericPedersen
	}

	if !c.ValidateSubPedersenCommit(credentialPC, proofPC, checkPC) {
		if c.Debug {
			c.LoggerError(logger, "failed to validate checkPC - credentialPC - proofPC = 0")
		}
		return nil, types.ErrGenericPedersen
	}

	var encPersonalInfoUserCredentialPubK []byte
	unprotoCredentialInfoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
	switch in.CredentialType {
	case types.PersonalInfoCredentialType:
		// unprotoize the vsharebind
		var personalInfo types.EncryptablePersonalInfo
		err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, credential.EncCredentialInfoVShare, &personalInfo)
		if err != nil {
			c.LoggerError(logger, "couldn't get decrypt credential")
			return nil, err
		}
		encPersonalInfoUserCredentialPubK = c.ProtoMarshalAndBEncrypt(userCredentialPubK, &personalInfo)
	default:
		var p types.EncryptableSingleContactInfo
		err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, credential.EncCredentialInfoVShare, &p)
		if err != nil {
			c.LoggerError(logger, "couldn't get decrypt credential")
			return nil, err
		}

		encPersonalInfoUserCredentialPubK = c.ProtoMarshalAndBEncrypt(userCredentialPubK, &p)
	}

	return &types.QueryFindCredentialResponse{
		EncPersonalInfoUserCredentialPubK: encPersonalInfoUserCredentialPubK,
		EncCredentialIDUserCredentialPubK: c.MarshalAndBEncrypt(userCredentialPubK, credential.CredentialID),
	}, nil
}

// this is called by init_enclave when adding a new pioneer (but not necessarily a validator yet)
func (s *qadenaServer) SyncEnclave(ctx context.Context, in *types.MsgSyncEnclave) (*types.SyncEnclaveReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SyncEnclave")
	} else {
		c.LoggerDebug(logger, "SyncEnclave "+c.PrettyPrint(in))
	}

	// PERSISTED, not merely in memory.  preInitEnclave sets PioneerID early, so a sync that failed
	// afterwards (a rejected remote report, a refused broadcast) left this set with nothing on
	// disk -- and every retry then returned Status:true having done nothing, which is how a node
	// ends up "synchronized" with an empty enclave_config/ and no registration on chain.
	if s.paramsPersisted && s.getPrivateEnclaveParamsPioneerID() != "" {
		c.LoggerDebug(logger, "already synchronized")
		return &types.SyncEnclaveReply{Status: true}, nil
	}
	if s.getPrivateEnclaveParamsPioneerID() != "" {
		c.LoggerInfo(logger, "a previous sync got as far as generating keys but never persisted them -- redoing it")
	}

	pwalletID, pwalletAddr, enclaveWalletID, err := s.preInitEnclave(ctx, false, in.PioneerID, in.ExternalAddress, in.PioneerArmorPrivK, in.PioneerArmorPassPhrase)

	if err != nil {
		c.LoggerError(logger, "couldn't preInitEnclave")
		return nil, err
	}

	_ = pwalletID
	_ = pwalletAddr
	_ = enclaveWalletID

	RootCmd.Flags().Set(flags.FlagNode, in.SeedNode)
	queryClientCtx, err := client.ReadPersistentCommandFlags(clientCtx, RootCmd.Flags())

	if err != nil {
		return nil, err
	}

	queryClient := types.NewQueryClient(queryClientCtx)

	c.LoggerDebug(logger, "Calling QueryEnclaveSyncEnclave on "+in.SeedNode)

	report, err := s.getRemoteReport(strings.Join([]string{
		s.getPrivateEnclaveParamsEnclavePubK(),
	}, "|"))
	if err != nil {
		return nil, err
	}
	params := &types.QueryEnclaveSyncEnclaveRequest{
		RemoteReport: report,
		EnclavePubK:  s.getPrivateEnclaveParamsEnclavePubK(),
		// Non-zero tells the seed we understand paging.  An older seed ignores it and replies in
		// the legacy shape, which the loop below detects and handles.
		MaxBytes: syncEnclavePageTargetBytes,
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "params (redacted)")
	} else {
		c.LoggerDebug(logger, "params "+c.PrettyPrint(params))
	}

	res, err := queryClient.EnclaveSyncEnclave(context.Background(), params)
	if err != nil {
		c.LoggerError(logger, "err "+err.Error())
		return nil, err
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "SyncEnclave returned (redacted)")
		c.LoggerDebug(logger, "private enclave params (redacted)")
	} else {
		c.LoggerDebug(logger, "SyncEnclave returned", c.PrettyPrint(res))
		c.LoggerDebug(logger, "private enclave params", c.PrettyPrint(s.privateEnclaveParams))
	}

	// THE REPLY IS NOW VERIFIED, by verifySeedIsOurBuild above.  This used to be one-directional --
	// we proved ourselves to the seed, the seed proved nothing back -- and the comment here recorded
	// why: verifying an attestation establishes "a genuine SGX enclave with measurement X", and
	// deciding whether X is one of OURS needed an anchor, of which the three candidates were all
	// wrong.  The chain's EnclaveIdentity table is empty at this point in a node's life; MRSIGNER
	// admits every build the project ever signed, and the signing key ships in the repo besides.
	//
	// The third candidate -- requiring the seed's measurement to EQUAL ours -- was rejected for
	// refusing joins during an upgrade window, when old and new measurements are deliberately both
	// active.  That is now the one we take, deliberately, because it is the only anchor left that a
	// fresh enclave can actually check, and the cost turns out to be small: a joiner's trusted set
	// is empty precisely when it needs a seed, so a laxer rule buys nothing at the moment it would
	// matter.  add_full_node.sh checks the two measurements up front (QueryEnclaveMeasurement) and
	// tells the operator to rebuild or pick another seed, so the constraint surfaces as a named
	// precondition in one second rather than a rejected handshake several minutes in.
	//
	// The old deferred check still stands behind this: SetJarRegulator compares the jar->regulator
	// binding the chain records against the one this seed handed us, during the first BeginBlock.
	var fromRemoteEnclaveParams types.EncryptableSharedEnclaveParams
	allOwners := &types.EncryptableEnclaveSSOwnerMap{Pioneers: make(map[string]*types.EncryptablePioneerIDs)}

	if len(res.GetEncSyncEnclavePagePubK()) == 0 {
		// An older seed that does not page.  Everything arrives at once, as it always did.
		if !s.verifySeedIsOurBuild(res.GetRemoteReport(), res.GetEncEnclaveParamsEnclavePubK()) {
			return nil, types.ErrRemoteReportNotVerified
		}
		_, err = c.BDecryptAndProtoUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), res.GetEncEnclaveParamsEnclavePubK(), &fromRemoteEnclaveParams)
		if err != nil {
			c.LoggerError(logger, "couldn't decrypt")
			return nil, err
		}
		allOwners = fromRemoteEnclaveParams.SSIntervalOwners
	} else {
		// Paged.  Accumulate every page before installing anything: a half-applied owners map is
		// worse than none, because the missing intervals do not fail here -- they surface much
		// later as a getSSPrivK that returns "" and silently changes a state transition.
		gotParams := false
		for pages := 1; ; pages++ {
			var page types.EncryptableSyncEnclavePage
			// EVERY page, not just the first: a report certifies exactly the ciphertext bytes it
			// arrived with, so checking one page says nothing about the next.
			if !s.verifySeedIsOurBuild(res.GetRemoteReport(), res.GetEncSyncEnclavePagePubK()) {
				return nil, types.ErrRemoteReportNotVerified
			}
			_, err = c.BDecryptAndProtoUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), res.GetEncSyncEnclavePagePubK(), &page)
			if err != nil {
				c.LoggerError(logger, "couldn't decrypt sync-enclave page")
				return nil, err
			}

			if page.Params != nil {
				fromRemoteEnclaveParams = *page.Params
				gotParams = true
			}
			for k, v := range page.SSIntervalOwners {
				allOwners.Pioneers[k] = v
			}
			c.LoggerDebug(logger, "sync-enclave page "+strconv.Itoa(pages)+" owners so far "+strconv.Itoa(len(allOwners.Pioneers)))

			if page.Done {
				break
			}
			// A seed that neither finishes nor advances would loop us forever. Treat it as a failed
			// join rather than spinning: refusing here is loud and the operator can retry.
			if len(page.NextCursor) == 0 {
				c.LoggerError(logger, "sync-enclave page is not done but carries no cursor")
				return nil, types.ErrGenericEnclave
			}
			if pages >= syncEnclaveMaxPages {
				c.LoggerError(logger, "sync-enclave exceeded "+strconv.Itoa(syncEnclaveMaxPages)+" pages, refusing")
				return nil, types.ErrGenericEnclave
			}

			params.Cursor = page.NextCursor
			res, err = queryClient.EnclaveSyncEnclave(context.Background(), params)
			if err != nil {
				c.LoggerError(logger, "err "+err.Error())
				return nil, err
			}
		}
		if !gotParams {
			// The key material rides on the first page; without it we would install an owners map
			// and no jar/regulator keys at all.
			c.LoggerError(logger, "sync-enclave completed without ever receiving the params page")
			return nil, types.ErrGenericEnclave
		}
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "fromRemoteEnclaveParams (redacted)")
	} else {
		c.LoggerDebug(logger, "fromRemoteEnclaveParams", c.PrettyPrint(fromRemoteEnclaveParams))
	}

	// copy from fromRemoteEnclaveParams to enclaveParams

	s.setSharedEnclaveParamsJarInfo(fromRemoteEnclaveParams.JarID, fromRemoteEnclaveParams.JarPubK, fromRemoteEnclaveParams.JarPrivK, fromRemoteEnclaveParams.JarArmorPrivK)

	s.setSharedEnclaveParamsRegulatorInfo(fromRemoteEnclaveParams.RegulatorID, fromRemoteEnclaveParams.RegulatorPubK, fromRemoteEnclaveParams.RegulatorPrivK, fromRemoteEnclaveParams.RegulatorArmorPrivK)

	// INSTALL THE BOOTSTRAP.  Everything above arrived from an enclave running our own build, over a
	// channel it attested; this is the same evidence that justifies taking its jar and regulator
	// private keys, applied to a strictly smaller claim.
	//
	// Without it the node comes up trusting only itself: it would refuse to serve any peer, and --
	// worse -- every replayed promotion would fail to verify for want of a trusted promoter, so it
	// could never rebuild the set from history either.
	if len(fromRemoteEnclaveParams.ActiveEnclaveIdentities) == 0 {
		c.LoggerError(logger, "the seed advertised NO active enclave identities -- this node will trust only itself and cannot serve peers")
	}
	for _, id := range fromRemoteEnclaveParams.ActiveEnclaveIdentities {
		s.trustEnclaveIdentity(id, "bootstrapped from a seed running our own measurement")
	}
	c.LoggerInfo(logger, "sync-enclave: trusted set bootstrapped with "+strconv.Itoa(len(fromRemoteEnclaveParams.ActiveEnclaveIdentities))+" identities from the seed")

	// store the owners -- accumulated across every page, installed once
	s.setAllOwners(allOwners)

	// intentionally don't store the shares, they're private to a specific enclave
	// do not store the SSIntervalPrivKCache

	// Here's where we add the pioneer's public keys, the pioneer-jar binding, interval public key

	params2 := &types.QueryGetPioneerJarRequest{
		PioneerID: s.getPrivateEnclaveParamsPioneerID(),
	}

	c.LoggerDebug(logger, "Checking PioneerJar", params2)

	res2, err := queryClient.PioneerJar(context.Background(), params2)

	validNotFound := false

	st, ok := status.FromError(err)
	if ok {
		if st.Code() == codes.NotFound && strings.Contains(st.Message(), "not found") {
			c.LoggerDebug(logger, "Couldn't find jar for pioneer ", s.getPrivateEnclaveParamsPioneerID())
			validNotFound = true
		}
	}

	if err != nil && !validNotFound {
		c.LoggerError(logger, "unable to query the chain to find the jar for pioneer")
		return nil, err
	} else if err == nil {
		if res2.GetPioneerJar().JarID == s.getSharedEnclaveParamsJarID() {
			c.LoggerError(logger, "Already initialized, this is an error.")
			return nil, types.ErrGenericEnclave
		} else {
			c.LoggerError(logger, "Already initialized, and the jar is wrong! "+s.getSharedEnclaveParamsJarID()+" chain value is "+res2.GetPioneerJar().JarID)
			return nil, types.ErrGenericEnclave
		}
	}

	c.LoggerInfo(logger, "Ok, going to initialize")

	//  fmt.Println("err " + err.Error().Error())
	//  fmt.Println("res", res)

	pwalletID, pwalletAddr, _, _, err = c.GetAddressByNameNoArmor(queryClientCtx, s.getPrivateEnclaveParamsPioneerID())

	if err != nil {
		return nil, err
	}

	msgs := make([]sdk.Msg, 0)

	// enclave
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsEnclavePubK(),
		types.EnclavePubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg := types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsEnclavePubK(),
		types.EnclavePubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	// pioneer
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.CredentialPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.CredentialPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.TransactionPubKType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg = types.NewMsgPioneerAddPublicKey(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerPubK(),
		types.TransactionPubKType,
		nil,
		report,
	)
	msgs = append(msgs, msg)

	// update interval bindings

	//
	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		"",
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg2 := types.NewMsgPioneerUpdateIntervalPublicKeyID(
		pwalletAddr.String(),
		pwalletID,
		s.getPrivateEnclaveParamsPioneerID(),
		types.PioneerNodeType,
		"",
		report,
	)
	msgs = append(msgs, msg2)

	report, err = s.getRemoteReport(strings.Join([]string{
		pwalletAddr.String(),
		s.getPrivateEnclaveParamsPioneerID(),
		s.getSharedEnclaveParamsJarID(),
	}, "|"))
	if err != nil {
		return nil, err
	}
	msg4 := types.NewMsgPioneerUpdatePioneerJar(
		pwalletAddr.String(),
		s.getPrivateEnclaveParamsPioneerID(),
		s.getSharedEnclaveParamsJarID(),
		report,
	)
	msgs = append(msgs, msg4)

	flagSet := RootCmd.Flags()

	/*
		flagSet.Set(flags.FlagGas, "4000000")

		flagSet.Set(flags.FlagGasPrices, "100000aqdn")
	*/

	queryClientCtx = queryClientCtx.WithFrom(pwalletID).WithFromAddress(pwalletAddr).WithFromName(s.getPrivateEnclaveParamsPioneerID())
	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(queryClientCtx, flagSet, "broadcast various update msgs in SyncEnclave", msgs...)

	if err != nil {
		c.LoggerError(logger, "failed to broadcast "+err.Error())
		if s.RealEnclave {
			c.LoggerError(logger, "msgs (redacted)")
		} else {
			c.LoggerError(logger, "msgs "+c.PrettyPrint(msgs))
		}
		return nil, err
	}

	// commit db
	//
	// This commit deliberately gets NO qmeta/hv/ entry and NO PreparedHeight stamp: it happens
	// while seeding a new node, outside any block, so the version it consumes belongs to no chain
	// height.  This is not an omission -- it is the reason heights are MAPPED to versions instead
	// of equated with them (see enclave_height.go): the height->version index simply never
	// mentions out-of-band versions, and no rollback can ever target one.
	c.LoggerDebug(logger, "CacheCtx.Write")
	s.CacheCtxWrite()

	cms, ok := s.ServerCtx.MultiStore().(storetypes.CommitMultiStore)

	if ok {
		lastCommitID := cms.LastCommitID()
		commitID := cms.Commit()
		if string(commitID.Hash) != string(lastCommitID.Hash) {
			c.LoggerDebug(logger, "has changed")
			c.LoggerDebug(logger, "LastCommitID "+c.PrettyPrint(lastCommitID))
			c.LoggerDebug(logger, "CommitID "+c.PrettyPrint(commitID))
		}
	} else {
		c.LoggerError(logger, "Couldn't cast multistore to commitstore")
	}

	// seal it
	status := s.saveEnclaveParams()
	if !status {
		c.LoggerError(logger, "couldn't save enclave parms")
		return &types.SyncEnclaveReply{Status: false}, nil
	}

	return &types.SyncEnclaveReply{Status: true}, nil
}

// this is called by init_enclave when adding a new pioneer (but not necessarily a validator yet)
func (s *qadenaServer) UpgradeEnclave(ctx context.Context, in *types.MsgUpgradeEnclave) (*types.UpgradeEnclaveReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "UpgradeEnclave")
	} else {
		c.LoggerDebug(logger, "UpgradeEnclave "+c.PrettyPrint(in))
	}

	if !enclaveUpgradeMode {
		return nil, types.ErrUpgradeModeNotEnabled
	}

	if !s.verifyRemoteReport(
		in.RemoteReport,
		strings.Join([]string{
			string(in.EnclavePubK),
		}, "|")) {
		return nil, types.ErrRemoteReportNotVerified
		//		c.LoggerError(logger, "Couldn't verify remote report, OK FOR NOW")
	}

	ep := storedEnclaveParams{
		PrivateEnclaveParams: s.privateEnclaveParams,
		SharedEnclaveParams:  s.sharedEnclaveParams,
	}

	json, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	// encrypt
	encjson := c.MarshalAndBEncrypt(in.EnclavePubK, string(json))
	if err != nil {
		c.LoggerError(logger, "Couldn't encrypt json")
		return nil, err
	}

	report, err := s.getRemoteReport(strings.Join([]string{
		string(encjson),
	}, "|"))
	if err != nil {
		c.LoggerError(logger, "Couldn't get remote report")
		return nil, err
	}

	return &types.UpgradeEnclaveReply{RemoteReport: report, EncEnclavePrivateStateEnclavePubK: encjson}, nil
}

func (s *qadenaServer) UpdateEnclaveIdentity(ctx context.Context, in *types.PioneerUpdateEnclaveIdentity) (*types.UpdateEnclaveIdentityReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "UpdateEnclaveIdentity")
	} else {
		c.LoggerDebug(logger, "UpdateEnclaveIdentity "+c.PrettyPrint(in))
	}

	// THE ROW FIRST, UNCONDITIONALLY.  What follows decides whether to TRUST the identity, and that
	// decision legitimately differs between nodes and over time -- it depends on attestation
	// freshness, which depends on DCAP collateral.  The mirrored row must not: it is consensus
	// state, replayed identically on every node forever.  The keeper matches this by recording the
	// row whatever this call returns.
	s.setEnclaveIdentity(in.EnclaveIdentity)

	subject := in.EnclaveIdentity.UniqueID + " -> " + in.EnclaveIdentity.Status
	_, isLive, knownPos := currentChainPosition()
	c.LoggerInfo(logger, "UpdateEnclaveIdentity: attested claim "+subject+" made at height "+
		strconv.FormatInt(in.Height, 10)+" (chain is "+map[bool]string{true: "live", false: "replaying"}[isLive || !knownPos]+")")

	// TRY THE EVIDENCE FIRST; SWEEP ONLY IF IT DOES NOT HOLD.
	//
	// The age limit applies to LIVE messages only.  A peer sending us something now chooses what to
	// send, so an unbounded lifetime would let it re-submit a years-old promotion as though it were
	// current.  Replayed blocks are the opposite case: the stream is consensus-ordered and
	// immutable, the network already agreed those transitions AND their order, and nothing gets to
	// choose what we see.  Refusing history on age there throws away good evidence and forces the
	// reconcile to rebuild what we could simply have read.
	//
	// BOTH DIRECTIONS ARE APPLIED, and that is what makes replaying safe: promotions and
	// deactivations both arrive attested, so processing the stream in order converges on exactly the
	// chain's final view.  Accepting historical grants while ignoring historical revocations would
	// ratchet trust upwards and leave us trusting a measurement the network retired years ago.
	if knownPos && isLive && !attestationWithinAgeLimit(in.Height, "identity claim "+subject) {
		// Say what this MEANS, not just what was decided.  These paths run once in months, so the
		// log is the only account anyone will have -- and "ignored" leaves the reader to work out
		// whether trust moved.  It did not, in either direction.
		_, alreadyTrusted := s.trustedEnclaveIdentity(in.EnclaveIdentity.UniqueID)
		verdict := "we do NOT trust it"
		if alreadyTrusted {
			verdict = "we still trust it, from earlier evidence"
		}
		c.LoggerInfo(logger, "UpdateEnclaveIdentity: no trust change for "+in.EnclaveIdentity.UniqueID+
			" -- a live message carrying an attestation this old is a replay, so it neither grants nor revokes; "+verdict+
			". The chain row was recorded regardless.")
		return &types.UpdateEnclaveIdentityReply{Status: true}, nil
	}

	if !s.verifyRemoteReport(
		in.RemoteReport,
		strings.Join([]string{
			in.EnclaveIdentity.UniqueID,
			in.EnclaveIdentity.SignerID,
			in.EnclaveIdentity.ProductID,
			in.EnclaveIdentity.Status,
			strconv.FormatInt(in.Height, 10),
		}, "|")) {
		// NOT an error return any more.  This used to fail the transaction, which made a consensus
		// outcome depend on whether a quote still verified -- two nodes checking the same historical
		// report on different days can legitimately disagree, and a replaying node would diverge on
		// the app hash and halt.  Declining to trust is this enclave's own business.
		if knownPos && !isLive {
			// Expected on real SGX: DCAP collateral has validity windows and TCB levels are revised,
			// so a quote from another era may simply no longer check out.  Nothing is lost -- the
			// reconcile on going live diffs what the chain believes against what we hold and queues
			// the difference for a quorum that answers about NOW.
			c.LoggerInfo(logger, "could not verify the historical attestation for "+subject+
				" (its collateral has likely moved on) -- leaving it; the reconcile on going live will settle it")
		} else {
			c.LoggerError(logger, "remote report unverified for "+subject+" -- recording the row, but NOT trusting the identity")
		}
		return &types.UpdateEnclaveIdentityReply{Status: true}, nil
	}

	// THE ATTESTED ROUTE INTO THE TRUSTED SET.  verifyRemoteReport above already established that
	// the enclave vouching for this identity is one we trust -- that is what makes this different
	// from a mirror push, which carries no evidence and may only downgrade.
	//
	// This is also what rebuilds the set during a replay: each historical promotion re-derives from
	// the one before it, rooted in whatever the sync-enclave bootstrap supplied.  A verdict of
	// inactive removes rather than adds, so a deactivation propagates the same way it was decided.
	if in.EnclaveIdentity.Status == types.InactiveStatus {
		s.untrustEnclaveIdentity(in.EnclaveIdentity.UniqueID, "attested deactivation")
	} else {
		s.trustEnclaveIdentity(in.EnclaveIdentity, "attested by an enclave we trust")
	}
	return &types.UpdateEnclaveIdentityReply{Status: true}, nil
}

func (s *qadenaServer) SetEnclaveIdentity(ctx context.Context, in *types.EnclaveIdentity) (*types.SetEnclaveIdentityReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SetEnclaveIdentity")
	} else {
		c.LoggerDebug(logger, "SetEnclaveIdentity "+c.PrettyPrint(in))
	}

	// THE ROW IS ALWAYS STORED.  This used to reject any foreign identity claiming a status other
	// than inactive/unvalidated, and a rejection here is fatal on the chain side -- the keeper
	// panics.  Genesis names the launch enclave `active`, so once a chain upgraded its enclave, no
	// new node could replay its genesis again: it died at height 0 with code 1146 before CometBFT
	// ever started.  State-sync seeding (SeedStorePage) fed rows through this same handler and hit
	// it for the same reason.
	//
	// Refusing was also not optional in the other direction: the mirrored store is accumulated and
	// audited against the chain's, so a row the chain wrote and the enclave did not is a permanent
	// divergence.  Storing was never the dangerous part -- TRUSTING was, and that now lives
	// separately.  See enclave_trusted_identities.go.
	s.setEnclaveIdentity(in)

	switch {
	case isSelf(in.UniqueID, in.SignerID):
		// NOT STORED, deliberately.  Self-trust is unconditional in trusts(), so recording it buys
		// nothing -- while costing the meaning of bootstrapped(), which asks "has anyone granted me
		// trust I could not derive alone".
		//
		// Storing it made that true for every enclave whose own measurement appears in genesis,
		// which on a chain that has NOT upgraded includes every joiner.  Such a node would believe
		// itself bootstrapped while holding only {self}, and voting on that set counts zero
		// confirmations against real peers -- concluding `inactive` for a perfectly good measurement
		// and broadcasting it if it happened to be proposing.  Exactly what the guard in
		// validateEnclaveIdentities exists to prevent, re-entering behind it.
		c.LoggerDebug(logger, "SetEnclaveIdentity: the chain named our own measurement "+in.UniqueID+
			"; trust in ourselves is implicit and is not recorded in the trusted set")
	case in.Status == types.InactiveStatus:
		// A mirror push may REMOVE trust but never add it -- governance or a quorum deactivation
		// flowing in.  The asymmetry is the point: a hostile node can only ever reduce what it is
		// trusted with.
		//
		// APPLIED DURING REPLAY TOO, in order with everything else.
		//
		// This was once deferred while catching up, on the reasoning that a historical deactivation
		// should not disturb a trusted set describing NOW.  That was wrong in company: replayed
		// PROMOTIONS are applied (they are attested and the stream is consensus-ordered), so
		// skipping only the revocations would ratchet trust upwards and leave us trusting something
		// the network retired.  Applying the whole history in order converges on the chain's final
		// view, which is the only view worth having.
		//
		// The `active -> inactive -> active` case that motivated the deferral resolves by itself:
		// the final promotion is attested, so it restores trust as it replays.  If its attestation
		// no longer verifies, the reconcile on going live sees the disagreement and asks a quorum.
		s.untrustEnclaveIdentity(in.UniqueID, "chain reports it inactive")
	default:
		// Stored, not trusted.  A foreign identity becomes trusted only through an attested route:
		// UpdateEnclaveIdentity with a report from an enclave we already trust, our own quorum
		// verdict, or the sync-enclave bootstrap.
		if _, known := s.trustedEnclaveIdentity(in.UniqueID); !known {
			c.LoggerDebug(logger, "SetEnclaveIdentity stored "+in.UniqueID+" ("+in.Status+") without trusting it -- no attestation accompanies a mirrored row")
		}
	}
	return &types.SetEnclaveIdentityReply{Status: true}, nil
}

// QueryEnclaveMeasurement answers "which build are you, and can you bootstrap a joiner".
//
// Unauthenticated on purpose.  A measurement is not a secret -- it is written into genesis and
// published on chain as an EnclaveIdentity -- and the caller needs it BEFORE it can attest anything,
// which is the entire point: add_full_node.sh compares the seed's build with the joiner's before
// minting keys or funding anything, so a mismatch is reported in one second instead of surfacing as
// a refused handshake several minutes in.
//
// It deliberately carries no report.  A report here would prove the answer came from a genuine
// enclave, but the joiner cannot act on that either way: this is a precondition check whose only
// consequence is a clearer error message.  The real authentication happens in the handshake itself.
func (s *qadenaServer) QueryEnclaveMeasurement(ctx context.Context, in *types.QueryEnclaveMeasurementRequest) (*types.QueryEnclaveMeasurementResponse, error) {
	c.LoggerDebug(logger, "QueryEnclaveMeasurement")
	return &types.QueryEnclaveMeasurementResponse{
		UniqueID: uniqueID,
		SignerID: signerID,
		// ProductID is left empty: the enclave keeps no notion of its own product id.  It appears in
		// identity records only because it travels with them from whoever registered them.  Empty is
		// honest here; inventing a value would make the precondition check compare fiction.
		Version:      version,
		Bootstrapped: s.bootstrapped(),
	}, nil
}

func (s *qadenaServer) SetWallet(ctx context.Context, in *types.Wallet) (*types.SetWalletReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SetWallet")
	} else {
		c.LoggerDebug(logger, "SetWallet "+c.PrettyPrint(in))
	}
	s.setWalletNoNotify(*in)
	return &types.SetWalletReply{Status: true}, nil
}

func (s *qadenaServer) SetRecoverKey(ctx context.Context, in *types.RecoverKey) (*types.SetRecoverKeyReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SetRecoverKey")
	} else {
		c.LoggerDebug(logger, "SetRecoverKey "+c.PrettyPrint(in))
	}
	unprotoNewWalletIDVShareBind := c.UnprotoizeVShareBindData(in.NewWalletIDVShareBind)
	privK := s.getSSPrivK(unprotoNewWalletIDVShareBind.GetSSIntervalPubKID())
	if privK == "" {
		c.LoggerError(logger, "Couldn't find privk for "+unprotoNewWalletIDVShareBind.GetSSIntervalPubKID())
		return nil, types.ErrGenericEncryption
	}
	var newWalletID types.EncryptableString
	err := c.VShareBDecryptAndProtoUnmarshal(privK, s.getPubK(unprotoNewWalletIDVShareBind.GetSSIntervalPubKID()), unprotoNewWalletIDVShareBind, in.EncNewWalletIDVShare, &newWalletID)
	if err != nil {
		c.LoggerError(logger, "Couldn't decrypt newWalletID")
		return nil, err
	}
	s.setRecoverKeyByOriginalWalletIDNoNotify(in.WalletID, in) // [in.WalletID] = in
	s.setRecoverOriginalWalletIDByNewWalletID(newWalletID.Value, in.WalletID)

	return &types.SetRecoverKeyReply{Status: true}, nil
}

func (s *qadenaServer) SetProtectKey(ctx context.Context, in *types.ProtectKey) (*types.SetProtectKeyReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SetProtectKey")
	} else {
		c.LoggerDebug(logger, "SetProtectKey "+c.PrettyPrint(in))
	}

	subWallet, found := s.getWallet(in.WalletID)

	if !found {
		return nil, types.ErrWalletNotExists
	}

	if subWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
		// can't protect a real wallet
		return nil, types.ErrInvalidWallet
	}

	c.LoggerDebug(logger, "EncWalletVShare: ")

	unprotoSubWalletCreateWalletVShareBind := c.UnprotoizeVShareBindData(subWallet.CreateWalletVShareBind)
	// decrypt the destination wallet id
	var vShareWallet types.EncryptableCreateWallet

	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoSubWalletCreateWalletVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoSubWalletCreateWalletVShareBind.GetSSIntervalPubKID()), unprotoSubWalletCreateWalletVShareBind, subWallet.EncCreateWalletVShare, &vShareWallet)
	if err != nil {
		return nil, err
	}

	// find the real wallet
	mainEWalletID := vShareWallet.DstEWalletID

	if s.RealEnclave {
		c.LoggerDebug(logger, "mainEWalletID (redacted)")
	} else {
		c.LoggerDebug(logger, "mainEWalletID "+c.PrettyPrint(mainEWalletID))
	}

	s.setProtectKeyNoNotify(in)
	s.setProtectSubWalletIDByOriginalWalletID(mainEWalletID.WalletID, in.WalletID)
	return &types.SetProtectKeyReply{Status: true}, nil
}

func (s *qadenaServer) ClaimCredential(ctx context.Context, in *types.MsgClaimCredential) (*types.MsgClaimCredentialResponse, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "ClaimCredential")
	} else {
		c.LoggerDebug(logger, "ClaimCredential "+c.PrettyPrint(in))
	}

	unprotoClaimCredentialExtraParmsVShareBind := c.UnprotoizeVShareBindData(in.ClaimCredentialExtraParmsVShareBind)

	//var claimCredentialExtraParms c.ClaimCredentialExtraParms
	var encryptableClaimCredentialExtraParms types.EncryptableClaimCredentialExtraParms
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoClaimCredentialExtraParmsVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoClaimCredentialExtraParmsVShareBind.GetSSIntervalPubKID()), unprotoClaimCredentialExtraParmsVShareBind, in.EncClaimCredentialExtraParmsVShare, &encryptableClaimCredentialExtraParms)
	if err != nil {
		c.LoggerDebug(logger, "Can't decrypt claimCredentialExtraParms")
		return nil, err
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "claimCredentialExtraParms (redacted)")
	} else {
		c.LoggerDebug(logger, "claimCredentialExtraParms "+c.PrettyPrint(encryptableClaimCredentialExtraParms))
	}

	// validate vshare here for the double-encrypted claimCredentialExtraParms
	wallet, found := s.getWallet(encryptableClaimCredentialExtraParms.WalletID)

	if !found {
		return nil, types.ErrWalletNotExists
	}

	requiredChainCCPubK := make([]c.VSharePubKInfo, 0)
	requiredChainCCPubK, err = s.enclaveAppendRequiredChainCCPubK(requiredChainCCPubK, "", false)
	if err != nil {
		c.LoggerError(logger, "RequiredChainCCPubK err "+err.Error())
		return nil, err
	}
	optionalServiceProvidersCCPubK := make([]c.VSharePubKInfo, 0)
	optionalServiceProvidersCCPubK, err = s.enclaveAppendOptionalServiceProvidersCCPubK(optionalServiceProvidersCCPubK, wallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		c.LoggerError(logger, "OptionalServiceProvidersCCPubK err "+err.Error())
		return nil, err
	}

	credentialCCPubK := make([]c.VSharePubKInfo, 0)
	credentialCCPubK = append(credentialCCPubK, requiredChainCCPubK...)
	credentialCCPubK = append(credentialCCPubK, optionalServiceProvidersCCPubK...)

	var sdkctx sdk.Context = sdk.Context{}.WithLogger(logger)

	if s.RealEnclave {
		c.LoggerDebug(logger, "credentialCCPubK (redacted)")
		c.LoggerDebug(logger, "credentialInfoVShare (redacted)")
	} else {
		c.LoggerDebug(logger, "credentialCCPubK "+c.PrettyPrint(credentialCCPubK))
		c.LoggerDebug(logger, "encryptableClaimCredentialExtraParms.GetCredentialInfoVShareBind() "+c.PrettyPrint(encryptableClaimCredentialExtraParms.CredentialInfoVShareBind))
		c.LoggerDebug(logger, "encryptableClaimCredentialExtraParms.EncCredentialInfoVShare "+c.PrettyPrint(encryptableClaimCredentialExtraParms.CredentialInfoVShareBind))
	}

	if !c.ValidateVShare(sdkctx, encryptableClaimCredentialExtraParms.GetCredentialInfoVShareBind(), encryptableClaimCredentialExtraParms.EncCredentialInfoVShare, credentialCCPubK) {
		c.LoggerError(logger, "invalid credential info vshare")
		return nil, types.ErrInvalidVShare
	}

	if !c.ValidateVShare(sdkctx, encryptableClaimCredentialExtraParms.CredentialHashVShareBind, encryptableClaimCredentialExtraParms.EncCredentialHashVShare, credentialCCPubK) {
		c.LoggerError(logger, "invalid credential hash vshare")
		return nil, types.ErrInvalidVShare
	}

	//	findCredentialXY := claimCredentialExtraParms.FindCredentialPC.C.X.String() + "." + claimCredentialExtraParms.FindCredentialPC.C.Y.String()
	findCredentialXY_C_Bytes := c.UnprotoizeBPedersenCommit(encryptableClaimCredentialExtraParms.FindCredentialPC).C.Bytes()

	// find the identity provider credential
	ipCredential, found := s.getCredentialByPCXY(findCredentialXY_C_Bytes, in.CredentialType)
	if !found {
		c.LoggerDebug(logger, "can't find identity provider credential by", hex.EncodeToString(findCredentialXY_C_Bytes))
		return nil, types.ErrCredentialNotExists
	}

	//  ipCredential, found := s.getCredential(ipCredentialID, in.CredentialType)
	//  if !found {
	//    c.LoggerDebug(logger, "can't find ipCredential by " + ipCredentialID)
	//		return nil, types.ErrCredentialNotExists
	//  }

	if ipCredential.WalletID != "" {
		c.LoggerDebug(logger, "already claimed "+ipCredential.WalletID)
		return nil, types.ErrCredentialClaimed
	}

	privK := s.getSSPrivK(unprotoClaimCredentialExtraParmsVShareBind.GetSSIntervalPubKID())
	if privK == "" {
		c.LoggerError(logger, "Couldn't find privk for "+unprotoClaimCredentialExtraParmsVShareBind.GetSSIntervalPubKID())
		return nil, types.ErrGenericEncryption
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "ipCredential (redacted)")
	} else {
		c.LoggerDebug(logger, "ipCredential "+c.PrettyPrint(ipCredential))
	}

	// do validations

	// check ZeroPC
	zeroPC := c.UnprotoizeEncryptablePedersenCommit(encryptableClaimCredentialExtraParms.ZeroPC)
	if zeroPC.A.Cmp(c.BigIntZero) != 0 {
		c.LoggerError(logger, "ZeroPC does not have zero amount")
		return nil, types.ErrGenericPedersen
	}

	if !c.ValidatePedersenCommit(zeroPC) {
		if c.Debug {
			c.LoggerError(logger, "failed to validate ZeroPC")
		}
		return nil, types.ErrGenericPedersen
	}

	unprotoCredentialPC := c.UnprotoizeBPedersenCommit(ipCredential.CredentialPedersenCommit)

	if !c.ValidateSubPedersenCommit(unprotoCredentialPC, c.UnprotoizeBPedersenCommit(encryptableClaimCredentialExtraParms.NewCredentialPC), c.UnprotoizeEncryptablePedersenCommit(encryptableClaimCredentialExtraParms.ZeroPC)) {
		c.LoggerError(logger, in.CredentialType, "failed to validate credentialPC (", unprotoCredentialPC.C.B64Address(), ") - newCredentialPC (", c.UnprotoizeBPedersenCommit(encryptableClaimCredentialExtraParms.NewCredentialPC).C.B64Address(), ") - zeroPC (", c.UnprotoizeEncryptablePedersenCommit(encryptableClaimCredentialExtraParms.ZeroPC).C.B64Address(), ") = 0")
		return nil, types.ErrGenericPedersen
	}

	// validate that the client changed the credential's CredentialPC, but the hash is still the same
	c.LoggerDebug(logger, "validated ZeroPC")

	// check ClaimPC

	if wallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] != types.QadenaRealWallet {
		c.LoggerError(logger, "can't claim ipCredential on subwallet")
		return nil, types.ErrInvalidWallet
	}

	unprotoWalletAmountPC := c.UnprotoizeBPedersenCommit(wallet.WalletAmount[types.QadenaTokenDenom].WalletAmountPedersenCommit)

	if !c.ValidateAddPedersenCommit(unprotoWalletAmountPC, c.UnprotoizeBPedersenCommit(encryptableClaimCredentialExtraParms.NewCredentialPC), c.UnprotoizeBPedersenCommit(encryptableClaimCredentialExtraParms.ClaimPC)) {
		c.LoggerError(logger, "failed to validate ClaimPC")
		return nil, types.ErrGenericPedersen
	}

	c.LoggerDebug(logger, "validated ClaimPC")

	var checkPC *c.PedersenCommit
	var pin string

	// still need to find a way to prove that an what's encrypted is the same as what the Identity Provider encrypted
	// for now, decrypt the credentials

	var checkCredentialHash string

	unprotoCredentialInfoVShareBind := c.UnprotoizeVShareBindData(encryptableClaimCredentialExtraParms.CredentialInfoVShareBind)

	var all []byte
	switch in.CredentialType {
	case types.PersonalInfoCredentialType:
		var p types.EncryptablePersonalInfo
		err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, encryptableClaimCredentialExtraParms.EncCredentialInfoVShare, &p)
		if err != nil {
			c.LoggerError(logger, "couldn't get decrypt credential")
			return nil, err
		}
		// the hash below is the chain's permanent identity key, so the fields going into it must be
		// canonical and separator-free no matter what the identity provider or the client sent
		if err := c.ValidatePersonalInfoDetails(p.Details); err != nil {
			c.LoggerError(logger, "invalid personal info details "+err.Error())
			return nil, types.ErrInvalidPersonalInfo
		}

		all, _ = proto.Marshal(p.Details)
		pin = p.PIN

		checkCredentialHash = c.CreateCredentialHash(p.Details)
	default:
		var p types.EncryptableSingleContactInfo
		err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, encryptableClaimCredentialExtraParms.EncCredentialInfoVShare, &p)
		if err != nil {
			c.LoggerError(logger, "couldn't get decrypt credential")
			return nil, err
		}
		all, _ = proto.Marshal(p.Details)
		pin = p.PIN
	}
	pinInt, ok := big.NewInt(0).SetString(pin, 10)
	if !ok {
		return nil, types.ErrGenericPedersen
	}

	checkPC = c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(all)), pinInt)

	newCredentialPC := c.UnprotoizeBPedersenCommit(encryptableClaimCredentialExtraParms.NewCredentialPC)

	if s.RealEnclave {
		c.LoggerDebug(logger, "checkPC/newCredentialPC (redacted)")
	} else {
		c.LoggerDebug(logger, "checkPC "+c.PrettyPrint(checkPC))
		c.LoggerDebug(logger, "newCredentialPC "+c.PrettyPrint(newCredentialPC))
	}

	if !c.ComparePedersenCommit(checkPC, newCredentialPC) {
		c.LoggerError(logger, "checkPC != NewCredentialPC")
		return nil, types.ErrGenericPedersen
	}

	c.LoggerDebug(logger, "all is well, create new credential")

	protoNewCredentialPC := encryptableClaimCredentialExtraParms.NewCredentialPC

	protoVShareBind := encryptableClaimCredentialExtraParms.CredentialInfoVShareBind

	newCredential := types.Credential{
		CredentialID:                 in.CredentialID,
		CredentialType:               in.CredentialType,
		WalletID:                     encryptableClaimCredentialExtraParms.WalletID,
		CredentialPedersenCommit:     protoNewCredentialPC,
		EncCredentialInfoVShare:      encryptableClaimCredentialExtraParms.EncCredentialInfoVShare,
		CredentialInfoVShareBind:     protoVShareBind,
		EncCredentialHashVShare:      encryptableClaimCredentialExtraParms.EncCredentialHashVShare,
		CredentialHashVShareBind:     encryptableClaimCredentialExtraParms.CredentialHashVShareBind,
		FindCredentialPedersenCommit: nil,
	}

	// if personal-info, we need to check uniqueness in the chain

	if in.CredentialType == types.PersonalInfoCredentialType {
		var credentialHash types.EncryptableString
		err := c.VShareBDecryptAndProtoUnmarshal(privK, s.getPubK(unprotoClaimCredentialExtraParmsVShareBind.GetSSIntervalPubKID()), c.UnprotoizeVShareBindData(encryptableClaimCredentialExtraParms.CredentialHashVShareBind), encryptableClaimCredentialExtraParms.EncCredentialHashVShare, &credentialHash)
		if err != nil {
			c.LoggerError(logger, "couldn't decrypt credential hash "+err.Error())
			return nil, err
		}

		c.LoggerDebug(logger, "credentialHash "+credentialHash.Value)

		if credentialHash.Value != checkCredentialHash {
			c.LoggerError(logger, "credentialHash != checkCredentialHash")
			return nil, types.ErrGenericPedersen
		}

		// TODO, improve detection of "credentialExists", this is simple for now

		_, credentialExists := s.getCredentialByHash(credentialHash.Value)

		if in.RecoverKey {
			if !credentialExists {
				c.LoggerError(logger, "trying to recover key but credential does not exist")
				return nil, types.ErrCredentialNotExists
			} else {
				// store the newCredential
				s.setCredential(newCredential.CredentialID, newCredential.CredentialType, newCredential)

				c.LoggerDebug(logger, "Calling RecoverKeyByCredential")
				_, err = s.recoverKeyByCredential(ctx, &newCredential, encryptableClaimCredentialExtraParms.EncWalletIDVShare, encryptableClaimCredentialExtraParms.WalletIDVShareBind)

				if err != nil {
					c.LoggerError(logger, "error recovering key "+err.Error())
					return nil, err
				}
				c.LoggerDebug(logger, "recover key ok")
				return &types.MsgClaimCredentialResponse{}, nil
			}
		} else {
			if credentialExists {
				c.LoggerError(logger, "credential hash already exists "+credentialHash.Value)
				return nil, types.ErrCredentialExists
			}

			s.setCredentialByHash(credentialHash.Value, newCredential.CredentialID)
		}
	}

	// store the newCredential
	s.setCredential(newCredential.CredentialID, newCredential.CredentialType, newCredential)

	// update the wallet with the CredentialID
	wallet.CredentialID = in.CredentialID
	s.setWallet(wallet)

	// invalidate the claimed credential
	ipCredential.WalletID = types.ClaimedCredentialWalletID
	s.setCredential(ipCredential.CredentialID, ipCredential.CredentialType, ipCredential)

	return &types.MsgClaimCredentialResponse{}, nil
}

func (s *qadenaServer) ValidateAuthorizedSigner(ctx context.Context, in *types.ValidateAuthorizedSignerRequest) (*types.ValidateAuthorizedSignerReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "ValidateAuthorizedSigner")
	} else {
		c.LoggerDebug(logger, "ValidateAuthorizedSigner "+c.PrettyPrint(in))
	}

	// basic algorithm:
	//   1. get the eph wallet
	//   2. get the eph wallet's real wallet ID
	//   3. check if the real wallet ID's authorized signatory is the eph wallet

	// now get the eph wallet
	// 1.
	wallet, found := s.getWallet(in.Creator)

	if !found {
		return nil, types.ErrWalletNotExists
	}

	if wallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
		c.LoggerError(logger, "wallet is not an ephemeral wallet")
		return nil, types.ErrInvalidWallet
	}

	var vShareCreateWallet types.EncryptableCreateWallet

	unprotoCreateWalletVShareBind := c.UnprotoizeVShareBindData(wallet.CreateWalletVShareBind)
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCreateWalletVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCreateWalletVShareBind.GetSSIntervalPubKID()), unprotoCreateWalletVShareBind, wallet.EncCreateWalletVShare, &vShareCreateWallet)

	if err != nil {
		c.LoggerError(logger, "couldn't decrypt vShareCreateWallet "+err.Error())
		return nil, err
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "vShareCreateWallet (redacted)")
	} else {
		c.LoggerDebug(logger, "vShareCreateWallet "+c.PrettyPrint(vShareCreateWallet))
	}

	// 2.
	realWalletID := vShareCreateWallet.DstEWalletID.WalletID

	c.LoggerDebug(logger, "realWalletID "+realWalletID)

	// 3.
	authorizedSignatory, found := s.GetAuthorizedSignatory(ctx, realWalletID)

	if !found {
		return nil, types.ErrUnauthorizedSigner
	}

	eas := s.decryptAuthorizedSignatory(authorizedSignatory, true)

	if eas == nil {
		return nil, types.ErrUnauthorizedSigner
	}

	// if the wallet ID is not in the authorized signatory, return error
	if !s.containsWalletID(eas.WalletID, in.Creator) {
		return nil, types.ErrUnauthorizedSigner
	}

	completedSignatory := s.decryptSignatory(in.RequestingSignatory, false)

	if completedSignatory == nil {
		return nil, types.ErrUnauthorizedSigner
	}

	// check email credential
	// now check that we have a valid email credential
	realWallet, found := s.getWallet(realWalletID)

	if !found {
		return nil, types.ErrWalletNotExists
	}

	emailCredential, foundEmail := s.getCredential(realWallet.CredentialID, types.EmailContactCredentialType)

	if !foundEmail {
		return nil, types.ErrCredentialNotExists
	}

	// decrypt credential
	var emailSCI types.EncryptableSingleContactInfo
	unprotoEmailCredentialVShareBind := c.UnprotoizeVShareBindData(emailCredential.CredentialInfoVShareBind)
	err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoEmailCredentialVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoEmailCredentialVShareBind.GetSSIntervalPubKID()), unprotoEmailCredentialVShareBind, emailCredential.EncCredentialInfoVShare, &emailSCI)
	if err != nil {
		c.LoggerError(logger, "couldn't get decrypt email credential")
		return nil, err
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "emailSCI (redacted)")
	} else {
		c.LoggerDebug(logger, "emailSCI "+c.PrettyPrint(emailSCI))
	}

	if emailSCI.Details.Contact != completedSignatory.Email {
		return nil, types.ErrUnauthorizedSigner
	}

	// loop through the completed signers to see if we're trying to sign again

	for _, cs := range in.CompletedSignatory {
		cSignatory := s.decryptSignatory(cs, true)
		if cSignatory == nil {
			return nil, types.ErrUnauthorizedSigner
		}

		if cSignatory.Email == completedSignatory.Email {
			return nil, types.ErrAlreadySigned
		}
	}

	// loop through the required signatory to see if we're the one trying to sign

	for _, rs := range in.RequiredSignatory {
		rSignatory := s.decryptSignatory(rs, true)
		if rSignatory == nil {
			return nil, types.ErrUnauthorizedSigner
		}

		if rSignatory.Email == completedSignatory.Email {
			return &types.ValidateAuthorizedSignerReply{Status: true}, nil
		}
	}

	return &types.ValidateAuthorizedSignerReply{Status: false}, types.ErrUnauthorizedSigner
}

func (s *qadenaServer) containsWalletID(d []string, creator string) bool {
	for _, walletID := range d {
		if walletID == creator {
			return true
		}
	}
	return false
}

// resolveSSIntervalPubKIDForBind picks the SS interval key a bind was actually encrypted to.
//
// This is the SECOND place a rotation can bite, and the grace in FindVSharePubKInfo does not reach
// it: the untrusted decrypt path looks up the CURRENT SS key and insists the bind names it, so a
// bind built moments before a rotation would be refused here even after the validator accepted it.
// Trying the previous key too keeps the two in agreement.
//
// Returns found=false when the bind names neither key, which is the same refusal as before.
func (s *qadenaServer) resolveSSIntervalPubKIDForBind(bindData *c.VShareBindData) (b64Address string, ssIntervalPubKID string, found bool) {
	current, previous, _, ok := s.getIntervalPublicKeyId(types.SSNodeID, types.SSNodeType)
	if !ok {
		return "", "", false
	}

	if addr := bindData.FindB64Address(current); addr != "" {
		return addr, current, true
	}

	// The grace window.  getSSPrivK is keyed by pubKID and interval private keys are never
	// discarded, so the old key is still usable for decryption.
	if previous != "" {
		if addr := bindData.FindB64Address(previous); addr != "" {
			c.LoggerDebug(logger, "bind names the previous ss interval key "+previous+", still within the rotation grace")
			return addr, previous, true
		}
	}

	return "", "", false
}

func (s *qadenaServer) decryptSignatory(in *types.VShareSignatory, trusted bool) *types.EncryptableSignatory {
	if s.RealEnclave {
		c.LoggerDebug(logger, "decryptSignatory")
	} else {
		c.LoggerDebug(logger, "decryptSignatory "+c.PrettyPrint(in))
	}

	bindData := c.UnprotoizeVShareBindData(in.SignatoryVShareBind)

	var b64Address string
	var ssIntervalPubKID string
	var found bool

	if trusted {
		// find the ss interval pubk in the bind data
		b64Address, ssIntervalPubKID = bindData.FindB64AddressAndBech32AddressByNodeIDAndType(types.SSNodeID, types.SSNodeType)
		c.LoggerDebug(logger, "trustedssIntervalPubKID "+b64Address+" "+ssIntervalPubKID)
	} else {
		// get ss interval public key id, accepting the one it replaced if this bind was built just
		// before a rotation
		b64Address, ssIntervalPubKID, found = s.resolveSSIntervalPubKIDForBind(bindData)

		if !found {
			c.LoggerError(logger, "bindData does not contain the current or previous ssIntervalPubKID")
			return nil
		}
	}

	// decrypt
	privK := s.getSSPrivK(ssIntervalPubKID)

	var es types.EncryptableSignatory
	err := c.VShareBDecryptAndProtoUnmarshal(privK, b64Address, bindData, in.EncSignatoryVShare, &es)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt authorized signatory "+err.Error())
		return nil
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "es (redacted)")
	} else {
		c.LoggerDebug(logger, "es "+c.PrettyPrint(es))
	}

	return &es
}

func (s *qadenaServer) decryptAuthorizedSignatory(in *types.VShareSignatory, trusted bool) *types.EncryptableAuthorizedSignatory {
	if s.RealEnclave {
		c.LoggerDebug(logger, "decryptAuthorizedSignatory")
	} else {
		c.LoggerDebug(logger, "decryptAuthorizedSignatory "+c.PrettyPrint(in)+" "+strconv.FormatBool(trusted))
	}

	bindData := c.UnprotoizeVShareBindData(in.SignatoryVShareBind)

	var b64Address string
	var ssIntervalPubKID string
	var found bool

	if trusted {
		// find the ss interval pubk in the bind data
		b64Address, ssIntervalPubKID = bindData.FindB64AddressAndBech32AddressByNodeIDAndType(types.SSNodeID, types.SSNodeType)
		c.LoggerDebug(logger, "trustedssIntervalPubKID "+b64Address+" "+ssIntervalPubKID)
	} else {
		// get ss interval public key id, accepting the one it replaced if this bind was built just
		// before a rotation
		b64Address, ssIntervalPubKID, found = s.resolveSSIntervalPubKIDForBind(bindData)

		if !found {
			c.LoggerError(logger, "bindData does not contain the current or previous ssIntervalPubKID")
			return nil
		}
	}

	// decrypt
	privK := s.getSSPrivK(ssIntervalPubKID)

	var eas types.EncryptableAuthorizedSignatory
	err := c.VShareBDecryptAndProtoUnmarshal(privK, b64Address, bindData, in.EncSignatoryVShare, &eas)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt authorized signatory "+err.Error())
		return nil
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "eas (redacted)")
	} else {
		c.LoggerDebug(logger, "eas "+c.PrettyPrint(eas))
	}

	return &eas
}

func (s *qadenaServer) ValidateAuthorizedSignatory(ctx context.Context, in *types.ValidateAuthorizedSignatoryRequest) (*types.ValidateAuthorizedSignatoryReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "ValidateAuthorizedSignatory")
	} else {
		c.LoggerDebug(logger, "ValidateAuthorizedSignatory "+c.PrettyPrint(in))
	}

	// get the creator wallet
	creatorWallet, found := s.getWallet(in.Creator)

	if !found {
		return nil, types.ErrWalletNotExists
	}

	if creatorWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] != types.QadenaRealWallet {
		c.LoggerError(logger, "wallet is not a real wallet")
		return nil, types.ErrInvalidWallet
	}

	eas := s.decryptAuthorizedSignatory(in.Signatory, false)

	if eas == nil {
		return nil, types.ErrUnauthorized
	}

	// for each item in eas.WalletID, get the wallet and check if it's an eph wallet
	for _, currentWalletID := range eas.WalletID {
		// now get the eph ephWallet
		ephWallet, found := s.getWallet(currentWalletID)

		if !found {
			return nil, types.ErrWalletNotExists
		}

		if ephWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
			c.LoggerError(logger, "wallet is not an eph wallet")
			return nil, types.ErrInvalidWallet
		}

		var vShareCreateWallet types.EncryptableCreateWallet

		unprotoCreateWalletVShareBind := c.UnprotoizeVShareBindData(ephWallet.CreateWalletVShareBind)

		err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCreateWalletVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCreateWalletVShareBind.GetSSIntervalPubKID()), unprotoCreateWalletVShareBind, ephWallet.EncCreateWalletVShare, &vShareCreateWallet)

		if err != nil {
			c.LoggerError(logger, "couldn't decrypt vShareCreateWallet "+err.Error())
			return nil, err
		}

		if s.RealEnclave {
			c.LoggerDebug(logger, "vShareCreateWallet (redacted)")
		} else {
			c.LoggerDebug(logger, "vShareCreateWallet "+c.PrettyPrint(vShareCreateWallet))
		}

		if vShareCreateWallet.DstEWalletID.WalletID != in.Creator {
			c.LoggerError(logger, "vShareCreateWallet.DstEWalletID.WalletID != Creator")
			return nil, types.ErrUnauthorized
		}

		// now check that we have a valid email credential
		_, foundEmail := s.getCredential(creatorWallet.CredentialID, types.EmailContactCredentialType)

		if !foundEmail {
			return nil, types.ErrCredentialNotExists
		}

		_, foundPhone := s.getCredential(creatorWallet.CredentialID, types.PhoneContactCredentialType)

		if !foundPhone {
			return nil, types.ErrCredentialNotExists
		}

		// now go through the current signatories and check if the new signatory is already there
		if in.CurrentSignatory != nil {
			// loop through the current signatories
			for _, currentSignatory := range in.CurrentSignatory {
				checkEAS := s.decryptAuthorizedSignatory(currentSignatory, true) // we are decrypting something that's already been checked

				if checkEAS == nil {
					return nil, types.ErrUnauthorized
				}

				for _, checkEASWalletID := range checkEAS.WalletID {
					if checkEASWalletID == currentWalletID {
						return nil, types.ErrSignatoryAlreadyExists
					}
				}
			}
		}
	}

	var dsvsAuthorizedSignatory dsvstypes.AuthorizedSignatory
	dsvsAuthorizedSignatory.WalletID = in.Creator

	if in.Signatory != nil {
		var bindPtr *dsvstypes.VShareBindData
		if in.Signatory.SignatoryVShareBind != nil {
			unprotoVShareBindData := c.UnprotoizeVShareBindData(in.Signatory.SignatoryVShareBind)
			dsvsProtoVShareBindData := c.DSVSProtoizeVShareBindData(unprotoVShareBindData)
			bindPtr = dsvsProtoVShareBindData
		}
		dsvsAuthorizedSignatory.Signatory = append(dsvsAuthorizedSignatory.Signatory, &dsvstypes.VShareAuthorizedSignatory{
			EncAuthorizedSignatoryVShare:  in.Signatory.EncSignatoryVShare,
			AuthorizedSignatoryVShareBind: bindPtr,
			Time:                          in.Signatory.Time,
		})
	}

	if in.CurrentSignatory != nil {
		for _, currentSignatory := range in.CurrentSignatory {
			if currentSignatory == nil {
				continue
			}
			var bindPtr *dsvstypes.VShareBindData
			if currentSignatory.SignatoryVShareBind != nil {
				unprotoVShareBindData := c.UnprotoizeVShareBindData(currentSignatory.SignatoryVShareBind)
				dsvsProtoVShareBindData := c.DSVSProtoizeVShareBindData(unprotoVShareBindData)
				bindPtr = dsvsProtoVShareBindData
			}
			dsvsAuthorizedSignatory.Signatory = append(dsvsAuthorizedSignatory.Signatory, &dsvstypes.VShareAuthorizedSignatory{
				EncAuthorizedSignatoryVShare:  currentSignatory.EncSignatoryVShare,
				AuthorizedSignatoryVShareBind: bindPtr,
				Time:                          currentSignatory.Time,
			})
		}
	}

	s.SetDSVSAuthorizedSignatory(ctx, &dsvsAuthorizedSignatory)

	return &types.ValidateAuthorizedSignatoryReply{Status: true}, nil
}

// we'll store the request in DSVS "format"
func (s *qadenaServer) SetDSVSAuthorizedSignatory(ctx context.Context, in *dsvstypes.AuthorizedSignatory) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SetDSVSAuthorizedSignatory")
	} else {
		c.LoggerDebug(logger, "SetDSVSAuthorizedSignatory "+c.PrettyPrint(in))
	}

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(dsvstypes.AuthorizedSignatoryKeyPrefix))

	b := s.Cdc.MustMarshal(in)

	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(dsvstypes.AuthorizedSignatoryKeyPrefix, EnclaveKeyKey(in.WalletID), b)
	store.Set(EnclaveKeyKey(in.WalletID), b)
	c.LoggerDebug(logger, "Stored authorized signatory")
}

func (s *qadenaServer) GetAuthorizedSignatory(ctx context.Context, creator string) (*types.VShareSignatory, bool) {
	c.LoggerDebug(logger, "GetAuthorizedSignatory "+creator)

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(dsvstypes.AuthorizedSignatoryKeyPrefix))

	bz := store.Get(EnclaveKeyKey(creator))
	if bz == nil {
		return nil, false
	}

	var in dsvstypes.AuthorizedSignatory
	s.Cdc.MustUnmarshal(bz, &in)

	// convert the top-most one
	top := in.Signatory[0]
	var bindPtr *types.VShareBindData
	if in.Signatory[0].AuthorizedSignatoryVShareBind != nil {
		unprotoDSVSVShareBindData := c.DSVSUnprotoizeVShareBindData(in.Signatory[0].AuthorizedSignatoryVShareBind)
		protoVShareBindData := c.ProtoizeVShareBindData(unprotoDSVSVShareBindData)
		bindPtr = protoVShareBindData
	}
	ret := types.VShareSignatory{
		EncSignatoryVShare:  top.EncAuthorizedSignatoryVShare,
		SignatoryVShareBind: bindPtr,
		Time:                top.Time,
		WalletID:            in.WalletID,
	}

	return &ret, true
}

// SetAuthorizedSignatory writes a row the chain has ALREADY validated.  SEEDING ONLY.
//
// enclaveSynchronizeStores replays chain state into a fresh enclave, and every other store does it
// through a setter.  AuthorizedSignatory was the exception -- it seeded through
// ValidateAuthorizedSignatory, which applies the live-path freshness rule: the vshare bind must name
// the CURRENT or PREVIOUS ss interval key (resolveSSIntervalPubKIDForBind).  Rows being replayed are
// old by construction, so on a state-synced joiner every one was refused with
//
//	bindData does not contain the current or previous ssIntervalPubKID
//	error returned by SetAuthorizedSignatory ... code 1141: Unauthorized
//
// and the node ran with none of them.  252 blocks later a signer check disagreed with the network
// and it forked: ValidateAuthorizedSigner returned 1137 "Unauthorized signer" for a transaction the
// primary accepted, which is a different app hash.
//
// THE FRESHNESS RULE IS NOT RELAXED.  It still guards the live path, where a user submits a
// signatory and the check does real work; only the replay of already-validated chain state bypasses
// it, which is what every other store already does.
func (s *qadenaServer) SetAuthorizedSignatory(ctx context.Context, in *types.ValidateAuthorizedSignatoryRequest) (*types.SetAuthorizedSignatoryReply, error) {
	c.LoggerDebug(logger, "SetAuthorizedSignatory "+c.PrettyPrint(in))

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(dsvstypes.AuthorizedSignatoryKeyPrefix))

	b := s.Cdc.MustMarshal(in)

	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(dsvstypes.AuthorizedSignatoryKeyPrefix, EnclaveKeyKey(in.Creator), b)
	store.Set(EnclaveKeyKey(in.Creator), b)
	c.LoggerDebug(logger, "Stored authorized signatory")

	return &types.SetAuthorizedSignatoryReply{Status: true}, nil
}

/*

func (s *qadenaServer) GetAuthorizedSignatory(ctx context.Context, creator string) (*types.VShareSignatory, bool) {
	c.LoggerDebug(logger, "GetAuthorizedSignatory "+creator)

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(dsvstypes.AuthorizedSignatoryKeyPrefix))

	bz := store.Get(EnclaveKeyKey(creator))
	if bz == nil {
		return nil, false
	}

	var in types.ValidateAuthorizedSignatoryRequest
	s.Cdc.MustUnmarshal(bz, &in)

	return in.Signatory, true
}
*/

func (s *qadenaServer) SetCredential(ctx context.Context, in *types.Credential) (*types.SetCredentialReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SetCredential")
	} else {
		c.LoggerDebug(logger, "SetCredential "+c.PrettyPrint(in))
	}
	//	credentialMap[CredentialKey{in.CredentialID, in.CredentialType}] = *in
	if s.credentialByPCXYExists(in) {
		c.LoggerError(logger, "credential already exists")
		return &types.SetCredentialReply{Status: false}, types.ErrCredentialExists
	}

	s.setCredentialNoNotify(in.CredentialID, in.CredentialType, *in)

	if in.WalletID == "" {
		//credentialIDByPCXYMap[in.FindCredentialPedersenCommit.C.X + "." + in.FindCredentialPedersenCommit.C.Y + "." + in.CredentialType] = in.CredentialID
		s.setCredentialByPCXY(in)
	}

	return &types.SetCredentialReply{Status: true}, nil
}

func (s *qadenaServer) RemoveCredential(ctx context.Context, in *types.EnclaveRemoveCredentialRequest) (*types.RemoveCredentialReply, error) {

	if s.RealEnclave {
		c.LoggerDebug(logger, "RemoveCredential")
	} else {
		c.LoggerDebug(logger, "RemoveCredential "+c.PrettyPrint(in))
	}

	if in.Credential == nil {
		return &types.RemoveCredentialReply{Status: false}, types.ErrCredentialNotExists
	}

	// get the credential
	credential, found := s.getCredential(in.Credential.CredentialID, in.Credential.CredentialType)
	if !found {
		c.LoggerError(logger, "credential does not exist")
		return &types.RemoveCredentialReply{Status: false}, types.ErrCredentialNotExists
	}

	if in.RequesterWalletID == "" {
		// the identity provider path: ownerless credentials only, unchanged
		if credential.WalletID != "" {
			c.LoggerError(logger, "credential is already claimed: "+credential.WalletID)
			return &types.RemoveCredentialReply{Status: false}, types.ErrCredentialClaimed
		}
	} else if credential.WalletID != in.RequesterWalletID {
		// the owner path: the requester must be exactly who the row says owns it
		c.LoggerError(logger, "credential is owned by "+credential.WalletID+", not "+in.RequesterWalletID)
		return &types.RemoveCredentialReply{Status: false}, types.ErrCredentialUpdateNotOwner
	}

	s.removeCredentialByPCXY(&credential)
	// Drop the identity hashes too, otherwise they keep blocking the uniqueness check for an
	// identity that no longer exists.  Only the personal-info row carries any; the sub-credentials
	// share its credentialID, so this is guarded on type to avoid a sub-credential removal taking
	// the whole identity's aliases with it.
	if credential.CredentialType == types.PersonalInfoCredentialType {
		s.removeAllCredentialHashAliases(credential.CredentialID)
	}
	s.removeCredentialNoNotify(credential.CredentialID, credential.CredentialType)

	return &types.RemoveCredentialReply{Status: true}, nil
}

func (s *qadenaServer) SignRecoverKey(ctx context.Context, in *types.MsgSignRecoverPrivateKey) (*types.SignRecoverKeyReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SignRecoverKey")
	} else {
		c.LoggerDebug(logger, "SignRecoverKey "+c.PrettyPrint(in))
	}

	unprotoDestinationEWalletIDVShareBind := c.UnprotoizeVShareBindData(in.DestinationEWalletIDVShareBind)
	privK := s.getSSPrivK(unprotoDestinationEWalletIDVShareBind.GetSSIntervalPubKID())
	if privK != "" {
		var dstEWalletID types.EncryptableSignRecoverKeyEWalletID
		err := c.VShareBDecryptAndProtoUnmarshal(privK, s.getPubK(unprotoDestinationEWalletIDVShareBind.GetSSIntervalPubKID()), unprotoDestinationEWalletIDVShareBind, in.EncDestinationEWalletIDVShare, &dstEWalletID)
		if err != nil {
			return nil, err
		}

		if s.RealEnclave {
			c.LoggerDebug(logger, "SignRecoverKey: dstEWalletID (redacted)")
		} else {
			c.LoggerDebug(logger, "SignRecoverKey: dstEWalletID "+c.PrettyPrint(dstEWalletID))
		}

		recoverKey, found := s.getRecoverKeyByOriginalWalletID(dstEWalletID.WalletID)

		if !found {
			c.LoggerDebug(logger, "SignRecoverKey: Couldn't find recover key "+dstEWalletID.WalletID)
			return nil, types.ErrInvalidSignRecoverKey
		}

		if s.RealEnclave {
			c.LoggerDebug(logger, "SignRecoverKey: recoverKey (redacted)")
		} else {
			c.LoggerDebug(logger, "SignRecoverKey: recoverKey "+c.PrettyPrint(recoverKey))
		}

		protectKey, found := s.getProtectKey(dstEWalletID.WalletID)

		if !found {
			c.LoggerDebug(logger, "SignRecoverKey: Couldn't find protect key "+dstEWalletID.WalletID)
			return nil, types.ErrInvalidSignRecoverKey
		}

		if s.RealEnclave {
			c.LoggerDebug(logger, "SignRecoverKey: protectKey (redacted)")
		} else {
			c.LoggerDebug(logger, "SignRecoverKey: protectKey "+c.PrettyPrint(protectKey))
		}

		// find the canonical name of the signer
		var signerName string
		for _, recoverShare := range protectKey.RecoverShare {
			// check if recoverShare.WalletID is a bech32 address
			if !c.IsBech32Address(recoverShare.WalletID) {
				walletID, _, _, foundPioneerID := s.getIntervalPublicKeyId(recoverShare.WalletID, types.PioneerNodeType)
				if foundPioneerID {
					// it's a canonical name
					if walletID == in.Creator {
						signerName = recoverShare.WalletID
						break
					}
				} else {
					// check if service provider
					walletID, _, _, foundServiceProviderID := s.getIntervalPublicKeyId(recoverShare.WalletID, types.ServiceProviderNodeType)
					if foundServiceProviderID {
						// it's a canonical name
						if walletID == in.Creator {
							signerName = recoverShare.WalletID
							break
						}
					}
				}
			} else {
				// it's a canonical name
				if recoverShare.WalletID == in.Creator {
					signerName = recoverShare.WalletID
				}
			}
		}

		if signerName == "" {
			c.LoggerDebug(logger, "SignRecoverKey: Couldn't find signer name")
			return nil, types.ErrInvalidSignRecoverKey
		}

		c.LoggerDebug(logger, "SignRecoverKey: signerName "+signerName)

		for _, signature := range recoverKey.Signatory {
			if signature == signerName {
				c.LoggerDebug(logger, "SignRecoverKey: already signed")
				return nil, types.ErrAlreadySignedSignRecoverKey
			}
		}

		recoverKey.Signatory = append(recoverKey.Signatory, signerName)
		if in.RecoverShare != nil && in.RecoverShare.WalletID != "" {
			recoverKey.RecoverShare = append(recoverKey.RecoverShare, in.RecoverShare)
		}
		s.setRecoverKeyByOriginalWalletID(dstEWalletID.WalletID, &recoverKey)
		return &types.SignRecoverKeyReply{Status: true}, nil
	}

	return nil, types.ErrInvalidSignRecoverKey
}

func (s *qadenaServer) recoverKeyByCredential(ctx context.Context, in *types.Credential, encWalletIDVShare []byte, walletIDVShareBind *types.VShareBindData) (*types.RecoverKeyReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "RecoverKey")
	} else {
		c.LoggerDebug(logger, "RecoverKey "+c.PrettyPrint(in))
	}

	if in.CredentialType == types.PersonalInfoCredentialType && in.WalletID != "" {
		if s.RealEnclave {
			c.LoggerDebug(logger, "recovering key wallet ID (redacted)")
			c.LoggerDebug(logger, "recovering key credential ID (redacted)")
		} else {
			c.LoggerDebug(logger, "recovering key wallet ID "+in.WalletID)
			c.LoggerDebug(logger, "recovering key credential ID "+in.CredentialID)
		}
		unprotoCredentialHashVShareBind := c.UnprotoizeVShareBindData(in.CredentialHashVShareBind)
		credentialHashPrivK := s.getSSPrivK(unprotoCredentialHashVShareBind.GetSSIntervalPubKID())
		if credentialHashPrivK != "" {
			var credentialHash types.EncryptableString
			err := c.VShareBDecryptAndProtoUnmarshal(credentialHashPrivK, s.getPubK(unprotoCredentialHashVShareBind.GetSSIntervalPubKID()), unprotoCredentialHashVShareBind, in.EncCredentialHashVShare, &credentialHash)
			if err == nil {
				if s.RealEnclave {
					c.LoggerDebug(logger, "credentialHash (redacted)")
				} else {
					c.LoggerDebug(logger, "credentialHash "+credentialHash.Value)
				}
				credential, exists := s.getCredentialByHash(credentialHash.Value)
				if exists {
					if s.RealEnclave {
						c.LoggerError(logger, "credential hash exists (redacted)")
						c.LoggerDebug(logger, "credential ID (redacted)")
						c.LoggerDebug(logger, "credential's wallet ID (redacted)")
					} else {
						c.LoggerError(logger, "credential hash exists "+credentialHash.Value)
						c.LoggerDebug(logger, "credential ID "+credential.CredentialID)
						c.LoggerDebug(logger, "credential's wallet ID "+credential.WalletID)
					}
					subWalletID, found := s.getProtectSubWalletIDByOriginalWalletID(credential.WalletID)
					if s.RealEnclave {
						c.LoggerDebug(logger, "sub wallet ID (redacted)")
					} else {
						c.LoggerDebug(logger, "sub wallet ID "+subWalletID)
					}
					if !found {
						c.LoggerError(logger, "there is no prior protect key for this credential")
						return nil, types.ErrInvalidRecoverKey
					}
					recoverKey := types.RecoverKey{
						WalletID:              subWalletID,
						EncNewWalletIDVShare:  encWalletIDVShare,
						NewWalletIDVShareBind: walletIDVShareBind,
						Signatory:             []string{},
						RecoverShare:          []*types.RecoverShare{},
					}
					_, found = s.getRecoverOriginalWalletIDByNewWalletID(in.WalletID)
					if found {
						c.LoggerError(logger, "recover map already exists")
						return nil, types.ErrInvalidRecoverKey
					}
					_, found = s.getRecoverKeyByOriginalWalletID(credential.WalletID)
					if found {
						c.LoggerError(logger, "recover key already exists")
						return nil, types.ErrInvalidRecoverKey
					}
					s.setRecoverOriginalWalletIDByNewWalletID(in.WalletID, subWalletID)

					s.setRecoverKeyByOriginalWalletID(subWalletID, &recoverKey)
					//					changedRecoverKeys = append(changedRecoverKeys, subWalletID)

					// mark the credential used to initiate recovery so it can't be mistaken for an owned credential
					newCredential, exists := s.getCredential(in.CredentialID, in.CredentialType)
					if exists {
						newCredential.WalletID = types.RecoverKeyCredentialWalletID
						c.LoggerDebug(logger, "Setting WalletID to "+types.RecoverKeyCredentialWalletID)
						s.setCredential(newCredential.CredentialID, newCredential.CredentialType, newCredential)
					}
				} else {
					return nil, types.ErrInvalidRecoverKey
				}
			} else {
				c.LoggerError(logger, "couldn't decrypt credential hash "+err.Error())
				return nil, types.ErrGenericEncryption
			}
		} else {
			return nil, types.ErrGenericEncryption
		}
	} else {
		return nil, types.ErrInvalidRecoverKey
	}
	return &types.RecoverKeyReply{Status: true}, nil
}

func (s *qadenaServer) getOwners(pubKID string) (owners types.EncryptablePioneerIDs, found bool) {
	store := s.secrets(EnclaveSSIntervalOwnersKeyPrefix)

	b := store.Get(EnclaveKeyKey(
		pubKID))

	var ownersArray types.EncryptablePioneerIDs
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find owners "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &ownersArray)

		if s.RealEnclave {
			c.LoggerDebug(logger, "ownersArray (redacted)")
		} else {
			c.LoggerDebug(logger, "ownersArray "+c.PrettyPrint(ownersArray))
		}
		found = true
		owners = ownersArray
	}

	return
}

func (s *qadenaServer) getAllOwners() (ownersMap *types.EncryptableEnclaveSSOwnerMap) {
	store := s.secrets(EnclaveSSIntervalOwnersKeyPrefix)

	ownersMap = new(types.EncryptableEnclaveSSOwnerMap)
	// init Pioneers
	ownersMap.Pioneers = make(map[string]*types.EncryptablePioneerIDs)

	// Keys() is a snapshot, so getOwners below re-acquires the secrets lock safely
	for _, key := range store.Keys() {
		fixedKey := string(key[:len(key)-1])
		c.LoggerDebug(logger, "key "+fixedKey)
		var found bool
		owners, found := s.getOwners(fixedKey)
		if !found {
			c.LoggerDebug(logger, "couldn't find in owners db")
		} else {
			ownersMap.Pioneers[fixedKey] = &owners
		}
	}

	return
}

func (s *qadenaServer) getShare(pubKID string) (share string, found bool) {
	store := s.secrets(EnclaveSSIntervalSharesKeyPrefix)

	b := store.Get(s.MustSealStable(EnclaveKeyKey(pubKID)))

	var shareString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find share "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(s.MustUnseal(b), &shareString)

		if s.RealEnclave {
			c.LoggerDebug(logger, "shareString (redacted)")
		} else {
			c.LoggerDebug(logger, "shareString "+c.PrettyPrint(shareString))
		}
		found = true
		share = shareString.GetS()
	}

	return
}

func (s *qadenaServer) setAllOwners(ownersMap *types.EncryptableEnclaveSSOwnerMap) {
	store := s.secrets(EnclaveSSIntervalOwnersKeyPrefix)
	for key, value := range ownersMap.Pioneers {
		ownerArray := value
		b := s.Cdc.MustMarshal(ownerArray)
		store.Set(EnclaveKeyKey(key), b)
	}
}

func (s *qadenaServer) setOwnersAndShare(pubKID string, owners []string, share string) {
	c.LoggerDebug(logger, "setOwnersAndShare", pubKID)
	ownerArray := types.EnclaveStoreStringArray{A: owners}
	shareString := types.EnclaveStoreString{S: share}
	store := s.secrets(EnclaveSSIntervalOwnersKeyPrefix)
	b := s.Cdc.MustMarshal(&ownerArray)
	store.Set(EnclaveKeyKey(pubKID), b)
	store = s.secrets(EnclaveSSIntervalSharesKeyPrefix)
	b = s.Cdc.MustMarshal(&shareString)
	store.Set(s.MustSealStable(EnclaveKeyKey(pubKID)), s.MustSeal(b))
}

func (s *qadenaServer) SetPublicKey(ctx context.Context, in *types.PublicKey) (*types.SetPublicKeyReply, error) {
	c.LoggerDebug(logger, "SetPublicKey")

	s.setPublicKeyNoNotify(*in)
	p, _ := s.getPublicKey(in.PubKID, in.PubKType)
	c.LoggerDebug(logger, "get public key "+p)

	owners := make([]string, 0)
	var myShare string
	for _, share := range in.Shares {
		owners = append(owners, share.PioneerID)
		if share.PioneerID == s.getPrivateEnclaveParamsPioneerID() {
			if s.RealEnclave {
				c.LoggerDebug(logger, "received a share (redacted)")
			} else {
				c.LoggerDebug(logger, "received a share "+c.PrettyPrint(share))
			}
			_, err := c.BDecryptAndUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), share.EncEnclaveShare, &myShare)
			if err != nil {
				c.LoggerError(logger, "couldn't decrypt")
				return nil, err
			}
		}
	}

	if len(owners) > 0 {
		s.setOwnersAndShare(in.PubKID, owners, myShare)

		oldPrivK, found := s.getPrivKCache(in.PubKID)
		if found {
			if oldPrivK != myShare {
				c.LoggerError(logger, "inconsistency")
				c.LoggerError(logger, "oldPrivK "+oldPrivK)
				c.LoggerError(logger, "myShare "+myShare)
			}
		} else {
			s.setPrivKCache(in.PubKID, myShare)
		}

		oldPubK, found := s.getPubKCache(in.PubKID)
		if found {
			if oldPubK != in.PubK {
				c.LoggerError(logger, "inconsistency")
				c.LoggerDebug(logger, "oldPubK "+oldPubK)
				c.LoggerDebug(logger, "current pubK "+in.PubK)
			}
		} else {
			s.setPubKCache(in.PubKID, in.PubK)
		}
	}

	return &types.SetPublicKeyReply{Status: true}, nil
}

func (s *qadenaServer) getPublicKey(pubKID string, pubKType string) (publicKey string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PublicKeyKeyPrefix))

	b := store.Get(types.PublicKeyKey(
		pubKID,
		pubKType,
	))
	var pk types.PublicKey
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find pubk "+pubKID+" "+pubKType)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &pk)

		if s.RealEnclave {
			c.LoggerDebug(logger, "publicKey (redacted)")
		} else {
			c.LoggerDebug(logger, "publicKey "+c.PrettyPrint(pk))
		}
		found = true
		publicKey = pk.PubK
	}

	return
}

func (s *qadenaServer) getAllPublicKeys() (arr []types.PublicKey) {
	arr = make([]types.PublicKey, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PublicKeyKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.PublicKey
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) setPublicKeyNoNotify(in types.PublicKey) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PublicKeyKeyPrefix))

	b := s.Cdc.MustMarshal(&in)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.PublicKeyKeyPrefix, types.PublicKeyKey(in.PubKID, in.PubKType), b)
	store.Set(types.PublicKeyKey(in.PubKID, in.PubKType), b)
}

// previousKeyID is the key this record replaced at the last rotation, empty when there has not been
// one.  The record is mirrored from the chain verbatim, so both sides read the same value -- which
// is what lets the enclave and the chain agree about a VShare that straddles a rotation.
func (s *qadenaServer) getIntervalPublicKeyId(nodeID string, nodeType string) (keyID string, previousKeyID string, serviceProviderType string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))

	b := store.Get(types.IntervalPublicKeyIDKey(
		nodeID,
		nodeType,
	))
	var ipki types.IntervalPublicKeyID
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find intervalPublicKeyId", nodeID, nodeType)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &ipki)

		c.LoggerDebug(logger, "getIntervalPublicKeyId", c.PrettyPrint(ipki))
		found = true
		keyID = ipki.PubKID
		previousKeyID = ipki.PreviousPubKID
		serviceProviderType = ipki.ServiceProviderType
	}

	return
}

func (s *qadenaServer) getIntervalPublicKeyIdByPubKID(pubKID string) (keyID string, serviceProviderType string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDByPubKIDKeyPrefix))
	b := store.Get(types.IntervalPublicKeyIDByPubKIDKey(pubKID))
	var ipki types.IntervalPublicKeyID
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find intervalpublickeyidbypubkid"+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &ipki)

		c.LoggerDebug(logger, "publicKey "+c.PrettyPrint(ipki))
		found = true
		keyID = ipki.PubKID
		serviceProviderType = ipki.ServiceProviderType
	}

	return
}

func (s *qadenaServer) getAllIntervalPublicKeyIds() (arr []types.IntervalPublicKeyID) {
	arr = make([]types.IntervalPublicKeyID, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.IntervalPublicKeyID
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) setIntervalPublicKeyIdNoNotify(in types.IntervalPublicKeyID) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))
	storeByPubKID := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDByPubKIDKeyPrefix))

	current := store.Get(types.IntervalPublicKeyIDKey(in.NodeID, in.NodeType))
	if current != nil {
		var currentIntervalPublicKeyID types.IntervalPublicKeyID
		s.Cdc.MustUnmarshal(current, &currentIntervalPublicKeyID)
		// Remove the old one by PubKID, so we don't keep growing the kvstore.
		//
		// This passed in.PubKID -- the NEW key, which is not in the index yet and gets written back
		// at the end of this function -- so it was a no-op and every rotated-away entry stayed
		// forever.  The chain's copy had the mirror-image mistake (correct key, wrong store), which
		// is why the two sides leaked in step and never diverged.  They must be fixed together; see
		// the matching note in x/qadena/keeper/interval_public_key_i_d.go.
		storeByPubKID.Delete(types.IntervalPublicKeyIDByPubKIDKey(currentIntervalPublicKeyID.PubKID))
	} else {
		// make sure we don't have a duplicate one stored by PubKID
		current = storeByPubKID.Get(types.IntervalPublicKeyIDByPubKIDKey(in.PubKID))
		if current != nil {
			c.LoggerError(logger, "setIntervalPublicKeyIdNoNotify err, duplicate PubKID")
			panic("setIntervalPublicKeyIdNoNotify err, duplicate PubKID")
		}
	}

	b := s.Cdc.MustMarshal(&in)
	c.LoggerDebug(logger, "setIntervalPublicKeyIdNoNotify "+c.PrettyPrint(in))
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.IntervalPublicKeyIDKeyPrefix, types.IntervalPublicKeyIDKey(in.NodeID, in.NodeType), b)
	store.Set(types.IntervalPublicKeyIDKey(in.NodeID, in.NodeType), b)
	storeByPubKID.Set(types.IntervalPublicKeyIDByPubKIDKey(in.PubKID), b)
}

func (s *qadenaServer) getAllPioneers() (pioneers []string) {
	pioneers = make([]string, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.IntervalPublicKeyID
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		if val.NodeType == types.PioneerNodeType && val.ExternalIPAddress != "" {
			pioneers = append(pioneers, val.NodeID)
		}
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) SetSecretSharePrivateKey(ctx context.Context, in *types.SecretSharePrivK) (*types.SetSecretSharePrivateKeyReply, error) {
	c.LoggerDebug(logger, "SetSecretSharePrivateKey")
	var ssIDAndPrivK types.EncryptableSSIDAndPrivK

	_, err := c.BDecryptAndProtoUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), in.EncEnclaveSSIDAndPrivK, &ssIDAndPrivK)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt")
		return nil, err
	}

	if s.RealEnclave {
		c.LoggerDebug(logger, "SetSecretSharePrivateKey ssIDAndPrivK (redacted)")
	} else {
		c.LoggerDebug(logger, "SetSecretSharePrivateKey ssIDAndPrivK "+c.PrettyPrint(ssIDAndPrivK))
	}

	s.setPrivKCache(ssIDAndPrivK.PubKID, ssIDAndPrivK.PrivK)
	s.setPubKCache(ssIDAndPrivK.PubKID, ssIDAndPrivK.PubK)

	return &types.SetSecretSharePrivateKeyReply{Status: true}, nil
}

func (s *qadenaServer) setPrivKCache(pubKID string, privK string) {
	privKString := types.EnclaveStoreString{S: privK}
	store := s.secrets(EnclaveSSIntervalPrivKKeyPrefix)
	b := s.Cdc.MustMarshal(&privKString)
	key := s.MustSealStable(EnclaveKeyKey(pubKID))
	c.LoggerDebug(logger, "setPrivkCache key "+hex.EncodeToString(key))
	store.Set(key, s.MustSeal(b))
	c.LoggerDebug(logger, "setPrivkCache "+pubKID)
}

func (s *qadenaServer) removePrivKCache(pubKID string) {
	store := s.secrets(EnclaveSSIntervalPrivKKeyPrefix)
	store.Delete(s.MustSealStable(EnclaveKeyKey(pubKID)))
}

func (s *qadenaServer) getPrivKCache(pubKID string) (privK string, found bool) {
	c.LoggerDebug(logger, "getPrivKCache "+pubKID)
	if pubKID == "" {
		return "", false
	}

	store := s.secrets(EnclaveSSIntervalPrivKKeyPrefix)

	key := s.MustSealStable(EnclaveKeyKey(pubKID))
	c.LoggerDebug(logger, "getPrivKCache key "+hex.EncodeToString(key))
	b := store.Get(key)

	var privKString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find privk "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(s.MustUnseal(b), &privKString)

		if s.RealEnclave {
			c.LoggerDebug(logger, "privKString (redacted)")
		} else {
			c.LoggerDebug(logger, "privKString "+c.PrettyPrint(privKString))
		}
		found = true
		privK = privKString.GetS()
	}

	return
}

func (s *qadenaServer) setPubKCache(pubKID string, pubK string) {
	pubKString := types.EnclaveStoreString{S: pubK}
	store := s.secrets(EnclaveSSIntervalPubKKeyPrefix)
	b := s.Cdc.MustMarshal(&pubKString)
	store.Set(EnclaveKeyKey(pubKID), b)
}

func (s *qadenaServer) getPubKCache(pubKID string) (pubK string, found bool) {
	store := s.secrets(EnclaveSSIntervalPubKKeyPrefix)

	b := store.Get(EnclaveKeyKey(
		pubKID))

	var pubKString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find pubk "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &pubKString)

		if s.RealEnclave {
			c.LoggerDebug(logger, "pubKString (redacted)")
		} else {
			c.LoggerDebug(logger, "pubKString "+c.PrettyPrint(pubKString))
		}
		found = true
		pubK = pubKString.GetS()
	}

	return
}

func (s *qadenaServer) setAllPubKCache(pubKCacheMap EnclavePubKCacheMap) {
	store := s.secrets(EnclaveSSIntervalPubKKeyPrefix)
	for key, value := range pubKCacheMap {
		pubKString := types.EnclaveStoreString{S: value}
		b := s.Cdc.MustMarshal(&pubKString)
		store.Set(EnclaveKeyKey(key), b)
	}
}

func (s *qadenaServer) setCredentialByHash(credentialHash string, credentialID string) {
	credentialIDString := types.EnclaveStoreString{S: credentialID}
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashKeyPrefix))
	b := s.Cdc.MustMarshal(&credentialIDString)
	store.Set(s.MustSealStable(EnclaveKeyKey(credentialHash)), s.MustSeal(b))
}

func (s *qadenaServer) getCredentialByHash(credentialHash string) (credential types.Credential, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashKeyPrefix))

	b := store.Get(s.MustSealStable(EnclaveKeyKey(credentialHash)))

	var credentialIDString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find credential by hash "+credentialHash)
		found = false
	} else {
		s.Cdc.MustUnmarshal(s.MustUnseal(b), &credentialIDString)

		c.LoggerDebug(logger, "credentialIDString "+c.PrettyPrint(credentialIDString))
		found = true
		credentialID := credentialIDString.GetS()
		credential, found = s.getCredential(credentialID, types.PersonalInfoCredentialType)
	}

	return
}

func (s *qadenaServer) removeCredentialByHash(credentialHash string) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashKeyPrefix))
	store.Delete(s.MustSealStable(EnclaveKeyKey(credentialHash)))
	c.LoggerDebug(logger, "Removed credentialByHash "+credentialHash)
}

func (s *qadenaServer) setCredentialIdentityHistory(credentialID string, history types.EncryptableCredentialIdentityHistory) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashesByCredentialIDKeyPrefix))
	b := s.Cdc.MustMarshal(&history)
	store.Set(s.MustSealStable(EnclaveKeyKey(credentialID)), s.MustSeal(b))
}

func (s *qadenaServer) getCredentialIdentityHistory(credentialID string) (history types.EncryptableCredentialIdentityHistory, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashesByCredentialIDKeyPrefix))

	b := store.Get(s.MustSealStable(EnclaveKeyKey(credentialID)))
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find credential identity history "+credentialID)
		return types.EncryptableCredentialIdentityHistory{}, false
	}

	s.Cdc.MustUnmarshal(s.MustUnseal(b), &history)
	return history, true
}

// exportScanTransferHistoryTable walks the whole AML window, one entry per sender.
//
// It cannot use exportSealedTable: that helper decodes every value as an EnclaveStoreString, and
// this table's value is a repeated proto message.  Feeding it here would not fail loudly, it would
// decode to an empty string and quietly report an empty window -- the exact wrong answer for the
// one table a fork diagnosis depends on.
func (s *qadenaServer) exportScanTransferHistoryTable() map[string][]*types.EncryptableScanTransfer {
	out := make(map[string][]*types.EncryptableScanTransfer)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveScanTransferHistoryKeyPrefix))
	itr := store.Iterator(nil, nil)
	defer itr.Close()
	for ; itr.Valid(); itr.Next() {
		key := s.MustUnsealStable(itr.Key())
		srcWalletID := string(key[:len(key)-1]) // strip EnclaveKeyKey's trailing separator
		var history types.EncryptableScanTransferHistory
		s.Cdc.MustUnmarshal(s.MustUnseal(itr.Value()), &history)
		out[srcWalletID] = history.Transfers
	}
	return out
}

func (s *qadenaServer) setScanTransferHistory(srcWalletID string, history types.EncryptableScanTransferHistory) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveScanTransferHistoryKeyPrefix))
	b := s.Cdc.MustMarshal(&history)
	store.Set(s.MustSealStable(EnclaveKeyKey(srcWalletID)), s.MustSeal(b))
}

// getScanTransferHistory returns the rolling window for one sender.  A wallet that has never sent
// gets an empty history rather than a "not found" -- there is nothing for a caller to do
// differently, and every call site would otherwise repeat the same branch.
func (s *qadenaServer) getScanTransferHistory(srcWalletID string) types.EncryptableScanTransferHistory {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveScanTransferHistoryKeyPrefix))

	b := store.Get(s.MustSealStable(EnclaveKeyKey(srcWalletID)))
	if b == nil {
		return types.EncryptableScanTransferHistory{}
	}

	var history types.EncryptableScanTransferHistory
	s.Cdc.MustUnmarshal(s.MustUnseal(b), &history)
	return history
}

// addCredentialHashAlias points one more identity hash at an existing credential.  The old hash
// is deliberately left in place: key recovery resolves hash -> credentialID -> live row, so
// leaving the old hash mapped is exactly what lets a user recover with their pre-update name,
// and it also stops the abandoned identity from being claimed by somebody else.
func (s *qadenaServer) addCredentialHashAlias(credentialHash string, credentialID string, history types.EncryptableCredentialIdentityHistory) types.EncryptableCredentialIdentityHistory {
	s.setCredentialByHash(credentialHash, credentialID)

	if !slices.Contains(history.Hashes, credentialHash) {
		history.Hashes = append(history.Hashes, credentialHash)
	}
	s.setCredentialIdentityHistory(credentialID, history)

	c.LoggerDebug(logger, "Added credential hash alias "+credentialHash+" -> "+credentialID)

	return history
}

// removeAllCredentialHashAliases drops every hash that resolves to this credential, plus the
// history record itself.  Without it, removing a credential would leave its hashes poisoning the
// uniqueness check forever.
func (s *qadenaServer) removeAllCredentialHashAliases(credentialID string) {
	history, found := s.getCredentialIdentityHistory(credentialID)
	if !found {
		return
	}

	for _, hash := range history.Hashes {
		s.removeCredentialByHash(hash)
	}

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialHashesByCredentialIDKeyPrefix))
	store.Delete(s.MustSealStable(EnclaveKeyKey(credentialID)))

	c.LoggerDebug(logger, "Removed all credential hash aliases for "+credentialID)
}

func (s *qadenaServer) setProtectSubWalletIDByOriginalWalletID(originalWalletID string, subWalletID string) {
	subWalletIDString := types.EnclaveStoreString{S: subWalletID}
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix))
	b := s.Cdc.MustMarshal(&subWalletIDString)
	store.Set(s.MustSealStable(EnclaveKeyKey(originalWalletID)), s.MustSeal(b))
}

func (s *qadenaServer) getProtectSubWalletIDByOriginalWalletID(originalWalletID string) (subWalletID string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix))

	b := store.Get(s.MustSealStable(EnclaveKeyKey(originalWalletID)))

	var subWalletIDString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find protectsubwalletidbyoriginalwalletid "+originalWalletID)
		found = false
	} else {
		found = true
		s.Cdc.MustUnmarshal(s.MustUnseal(b), &subWalletIDString)

		c.LoggerDebug(logger, "subWalletIDString "+c.PrettyPrint(subWalletIDString))
		subWalletID = subWalletIDString.GetS()
	}

	return
}

func (s *qadenaServer) setRecoverOriginalWalletIDByNewWalletID(newWalletID string, originalWalletID string) {
	originalWalletIDString := types.EnclaveStoreString{S: originalWalletID}
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix))
	b := s.Cdc.MustMarshal(&originalWalletIDString)
	store.Set(s.MustSealStable(EnclaveKeyKey(newWalletID)), s.MustSeal(b))
}

func (s *qadenaServer) getRecoverOriginalWalletIDByNewWalletID(newWalletID string) (originalWalletID string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix))

	b := store.Get(s.MustSealStable(EnclaveKeyKey(newWalletID)))

	var originalWalletIDString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find recoveroriginalwalletidbynewwalletid "+newWalletID)
		found = false
	} else {
		found = true
		s.Cdc.MustUnmarshal(s.MustUnseal(b), &originalWalletIDString)

		c.LoggerDebug(logger, "originalWalletIDString "+c.PrettyPrint(originalWalletIDString))
		originalWalletID = originalWalletIDString.GetS()
	}

	return
}

// check if the credential exists by PCXY

func (s *qadenaServer) credentialByPCXYExists(credential *types.Credential) bool {
	// make sure credentialPCXY is not empty
	if credential.FindCredentialPedersenCommit == nil || credential.FindCredentialPedersenCommit.C == nil || credential.FindCredentialPedersenCommit.C.Compressed == nil {
		return false
	}

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialPCXYKeyPrefix))

	credentialPCXY := credential.FindCredentialPedersenCommit.C.Compressed

	b := store.Get(EnclaveKeyBKeyCredentialType(credentialPCXY, credential.CredentialType))

	if b == nil {
		return false
	}

	return true
}

func (s *qadenaServer) setCredentialByPCXY(credential *types.Credential) {
	// make sure credentialPCXY is not empty
	if credential.FindCredentialPedersenCommit == nil || credential.FindCredentialPedersenCommit.C == nil || credential.FindCredentialPedersenCommit.C.Compressed == nil {
		return
	}
	credentialIDString := types.EnclaveStoreString{S: credential.CredentialID}
	//findCredentialPedersenCommit := c.UnprotoizeBPedersenCommit(*credential.FindCredentialPedersenCommit)
	//credentialPCXY := findCredentialPedersenCommit.C.X.String() + "." + findCredentialPedersenCommit.C.Y.String() + "." + credential.CredentialType
	credentialPCXY := credential.FindCredentialPedersenCommit.C.Compressed
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialPCXYKeyPrefix))
	b := s.Cdc.MustMarshal(&credentialIDString)
	store.Set(EnclaveKeyBKeyCredentialType(credentialPCXY, credential.CredentialType), b)
	c.LoggerDebug(logger, "Stored credentialByPCXY", hex.EncodeToString(credentialPCXY), credential.CredentialType)
}

func (s *qadenaServer) removeCredentialByPCXY(credential *types.Credential) {
	// make sure credentialPCXY is not empty
	if credential.FindCredentialPedersenCommit == nil || credential.FindCredentialPedersenCommit.C == nil || credential.FindCredentialPedersenCommit.C.Compressed == nil {
		return
	}

	credentialPCXY := credential.FindCredentialPedersenCommit.C.Compressed
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialPCXYKeyPrefix))
	store.Delete(EnclaveKeyBKeyCredentialType(credentialPCXY, credential.CredentialType))
	c.LoggerDebug(logger, "Removed credentialByPCXY", hex.EncodeToString(credentialPCXY), credential.CredentialType)
}

// credentialIDByPCXY returns the credentialID the index holds for a commitment, without following
// it to the credential itself.
//
// Split out of getCredentialByPCXY because the seeding path needs to distinguish "this exact row
// is already indexed" from "a DIFFERENT credential claims this commitment", and the former must
// not be treated as a collision.  getCredentialByPCXY cannot answer that: it resolves the ID and
// returns found=false when the credential behind it is missing, which conflates an absent index
// entry with a dangling one.
func (s *qadenaServer) credentialIDByPCXY(pcXY []byte, credentialType string) (string, bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialPCXYKeyPrefix))
	b := store.Get(EnclaveKeyBKeyCredentialType(pcXY, credentialType))
	if b == nil {
		return "", false
	}
	var credentialIDString types.EnclaveStoreString
	s.Cdc.MustUnmarshal(b, &credentialIDString)
	return credentialIDString.GetS(), true
}

// SeedCredential replays a credential from chain state into a fresh enclave.  See the RPC comment
// in enclave.proto for why this is not SetCredential.
func (s *qadenaServer) SeedCredential(ctx context.Context, in *types.Credential) (*types.SetCredentialReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "SeedCredential")
	} else {
		c.LoggerDebug(logger, "SeedCredential "+c.PrettyPrint(in))
	}

	hasCommit := in.FindCredentialPedersenCommit != nil &&
		in.FindCredentialPedersenCommit.C != nil &&
		in.FindCredentialPedersenCommit.C.Compressed != nil

	// A commitment already held by a DIFFERENT credential is a real collision and must not be
	// silently overwritten -- the index would then point at one of two identities arbitrarily.
	// The same credentialID is this row arriving twice, which a bulk re-push does by construction.
	if hasCommit {
		if existingID, found := s.credentialIDByPCXY(in.FindCredentialPedersenCommit.C.Compressed, in.CredentialType); found && existingID != in.CredentialID {
			c.LoggerError(logger, "SeedCredential: commitment already held by credential "+existingID+", refusing to seed "+in.CredentialID)
			return &types.SetCredentialReply{Status: false}, types.ErrCredentialExists
		}
	}

	s.setCredentialNoNotify(in.CredentialID, in.CredentialType, *in)

	// INDEXED ON THE INTRINSIC PROPERTY, not on the current walletID.  Every credential an identity
	// provider issued carries a findCredentialPedersenCommit and belongs in the index for life; the
	// ones minted for a user by ClaimCredential are created with that field nil (enclave.go, the
	// claim path) and are excluded here by the same test that excludes them live.  A consumed row
	// stays indexed on purpose -- the sentinel walletID is what makes it unusable, and
	// findOwnerlessIPCredential rejects on it.
	if hasCommit {
		s.setCredentialByPCXY(in)
	}

	return &types.SetCredentialReply{Status: true}, nil
}

func (s *qadenaServer) getCredentialByPCXY(pcXY []byte, credentialType string) (credential types.Credential, found bool) {
	//	key := pcXY + "." + credentialType

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialPCXYKeyPrefix))

	b := store.Get(EnclaveKeyBKeyCredentialType(pcXY, credentialType))

	var credentialIDString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find credentialByPCXY", hex.EncodeToString(pcXY), credential.CredentialType)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &credentialIDString)

		c.LoggerDebug(logger, "credentialIDString "+c.PrettyPrint(credentialIDString))
		credentialID := credentialIDString.GetS()
		found = true
		credential, found = s.getCredential(credentialID, credentialType)
	}

	return
}

func (s *qadenaServer) getPioneerIPAddress(pioneerID string) (pioneerIP string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.IntervalPublicKeyIDKeyPrefix))

	b := store.Get(types.IntervalPublicKeyIDKey(
		pioneerID,
		types.PioneerNodeType,
	))
	var ipki types.IntervalPublicKeyID
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find pioneeripaddress "+pioneerID+" "+types.PioneerNodeType)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &ipki)

		c.LoggerDebug(logger, "interval public key id "+c.PrettyPrint(ipki))
		found = true
		pioneerIP = ipki.ExternalIPAddress
	}

	return
}

func (s *qadenaServer) SetIntervalPublicKeyID(ctx context.Context, in *types.IntervalPublicKeyID) (*types.SetIntervalPublicKeyIdReply, error) {
	c.LoggerDebug(logger, "SetIntervalPublicKeyID "+c.PrettyPrint(in))
	s.setIntervalPublicKeyIdNoNotify(*in)
	//	intervalPublicKeyIdMap[IntervalPublicKeyIdKey{in.NodeID, in.NodeType}] = in.PubKID
	//	if in.NodeType == types.PioneerNodeType {
	//		s.setPioneerIPAddress(in.NodeID, in.ExternalIPAddress)
	//	}
	return &types.SetIntervalPublicKeyIdReply{Status: true}, nil
}

func (s *qadenaServer) SetPioneerJar(ctx context.Context, in *types.PioneerJar) (*types.SetPioneerJarReply, error) {
	c.LoggerDebug(logger, "SetPioneerJar "+c.PrettyPrint(in))
	s.setPioneerJarNoNotify(*in)
	return &types.SetPioneerJarReply{Status: true}, nil
}

func (s *qadenaServer) getPioneerJar(pioneerID string) (pioneerJar string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PioneerJarKeyPrefix))

	b := store.Get(types.PioneerJarKey(
		pioneerID,
	))
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find pioneerjar "+pioneerID)
		found = false
	} else {
		var pj types.PioneerJar
		s.Cdc.MustUnmarshal(b, &pj)

		c.LoggerDebug(logger, "pioneerJar "+c.PrettyPrint(pj))
		found = true
		pioneerJar = pj.JarID
	}

	return
}

func (s *qadenaServer) SetJarRegulator(ctx context.Context, in *types.JarRegulator) (*types.SetJarRegulatorReply, error) {
	c.LoggerDebug(logger, "SetJarRegulator "+c.PrettyPrint(in))

	// CHECK THE PARAMS WE WERE HANDED AT SYNC TIME AGAINST CONSENSUS.
	//
	// SyncEnclave accepts the jar and regulator identities from a seed it cannot authenticate --
	// there is no usable trust anchor at that point in a node's life, which is argued at length in
	// that function.  This is where that debt is settled: a JarRegulator row is chain state, and it
	// arrives here during the mirror push while we still hold what the seed told us.  If the seed
	// invented a jar or pointed it at a regulator the chain does not agree with, the two disagree
	// right here, and this is the earliest moment anything can notice.
	//
	// Scope, stated plainly: this catches FABRICATED IDENTIFIERS, not fabricated key material.  A
	// MITM that supplied the real jarID and regulatorID with keys of its own passes this check and
	// is caught later and less clearly, when the first VShare fails to decrypt.  Catching that
	// would need the jar's public half on chain in a form comparable to what we hold, and it is
	// not stored that way.
	if ourJarID := s.getSharedEnclaveParamsJarID(); ourJarID != "" && in.JarID == ourJarID {
		if ourRegulatorID := s.getSharedEnclaveParamsRegulatorID(); ourRegulatorID != "" && in.RegulatorID != ourRegulatorID {
			c.LoggerError(logger, "SetJarRegulator: chain says jar "+in.JarID+" is regulated by "+in.RegulatorID+
				", but this enclave was told "+ourRegulatorID)
			return nil, fmt.Errorf(
				"enclave params disagree with chain state: this enclave holds jar %q bound to regulator %q, but the chain records regulator %q for that jar.\n"+
					"\n"+
					"The params were supplied by whatever answered the sync-enclave query during add_full_node, over an\n"+
					"unauthenticated chain RPC endpoint named by an operator-typed IP.  Treat this as a wrong seed address\n"+
					"or an interposed one: re-run the join against a seed you can verify, rather than continuing with keys\n"+
					"of unknown origin.",
				ourJarID, ourRegulatorID, in.RegulatorID)
		}
	}

	s.setJarRegulatorNoNotify(*in)
	return &types.SetJarRegulatorReply{Status: true}, nil
}

func (s *qadenaServer) getJarRegulator(jarID string) (regulatorID string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.JarRegulatorKeyPrefix))

	b := store.Get(types.JarRegulatorKey(
		jarID,
	))
	var jarReg types.JarRegulator
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find jarregulator "+jarID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &jarReg)

		c.LoggerDebug(logger, "jarReg "+c.PrettyPrint(jarReg))
		found = true
		regulatorID = jarReg.RegulatorID
	}

	return
}

func (s *qadenaServer) getAllJarRegulators() (arr []types.JarRegulator) {
	arr = make([]types.JarRegulator, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.JarRegulatorKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.JarRegulator
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) getAllPioneerJars() (arr []types.PioneerJar) {
	arr = make([]types.PioneerJar, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PioneerJarKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.PioneerJar
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) setJarRegulatorNoNotify(in types.JarRegulator) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.JarRegulatorKeyPrefix))

	b := s.Cdc.MustMarshal(&in)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.JarRegulatorKeyPrefix, types.JarRegulatorKey(in.JarID), b)
	store.Set(types.JarRegulatorKey(in.JarID), b)
}

func (s *qadenaServer) setPioneerJarNoNotify(in types.PioneerJar) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PioneerJarKeyPrefix))

	// KEYED BY PIONEER-ID, matching both the chain (pioneer_jar.go stores by PioneerID) and this
	// file's own reader (getPioneerJar takes a pioneerID).  This used to key by JarID, which made
	// the same row live under "jar1/" here and "pioneer1/" on the chain: identical VALUE, different
	// KEY, so the store hashes could never agree.  Every restart reported PioneerJar OUT-OF-SYNC,
	// the seed "repaired" it back into the same mismatched pair, and DIVERGED AT AN AGREED HEIGHT
	// fired on a chain where nothing had diverged.  It was also data loss waiting to happen: two
	// pioneers sharing a jar would overwrite each other's row.
	//
	// The legacy JarID-keyed row is deleted in passing, so an enclave that stored under the old key
	// self-heals on the next write instead of carrying a permanent extra row that keeps the hashes
	// apart.  Guarded, because a network where someone named the jar after the pioneer would
	// otherwise delete the row it just wrote.
	if in.JarID != in.PioneerID {
		if legacy := store.Get(types.PioneerJarKey(in.JarID)); legacy != nil {
			s.accumulateWrite(types.PioneerJarKeyPrefix, types.PioneerJarKey(in.JarID), nil)
			store.Delete(types.PioneerJarKey(in.JarID))
		}
	}

	b := s.Cdc.MustMarshal(&in)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.PioneerJarKeyPrefix, types.PioneerJarKey(in.PioneerID), b)
	store.Set(types.PioneerJarKey(in.PioneerID), b)
}

// broadcast false means "decide, do not tell anyone": update our own trusted set from what peers
// attest, and leave the on-chain record to whichever node is proposing.  See the call site.
func (s *qadenaServer) validateEnclaveIdentities(broadcast bool) {
	// get the unvalidated identities
	unvalidated := s.getUnvalidatedEnclaveIdentities()
	c.LoggerDebug(logger, "unvalidateEnclaveIdentities "+c.PrettyPrint(unvalidated))
	// validate the identities
	pioneers := s.getAllPioneers()

	// AN ENCLAVE THAT CANNOT EVALUATE PEERS MUST NOT VOTE ON THEM.  The verdict below counts how
	// many pioneers WE TRUST confirmed the identity, so an enclave with no trust beyond itself
	// counts zero against a network of peers, concludes `inactive` for a perfectly good measurement,
	// and -- if it happens to be proposing -- broadcasts that to everyone.
	//
	// The test is "are there peers I cannot evaluate", NOT "is my trusted set empty".  Those differ
	// exactly where it matters: the FIRST node of a chain has no peers and never will have a
	// bootstrap, and it is the node that must promote the next enclave during an upgrade.  Gating on
	// the set alone deadlocked precisely that case -- the upgrade suite sat for 180s watching
	// unique048 stay `unvalidated`, because the only node able to promote it had ruled itself out.
	// With no other pioneers the existing branch below marks the identity valid on its own
	// authority, which is right: there is nobody else to ask.
	c.LoggerDebug(logger, "getAllPioneers "+c.PrettyPrint(pioneers))
	// randomize the array
	pioneers = randomizePioneerIDs(pioneers, s.getPrivateEnclaveParamsPioneerID())
	c.LoggerDebug(logger, "randomizePioneerIDs "+c.PrettyPrint(pioneers))
	threshold := getThreshold(len(pioneers))

	// deep copy unvalidated into tmp
	newUnvalidated := types.EnclaveEnclaveIdentityArray{Identity: make([]*types.EnclaveIdentity, 0)}
	for _, identity := range unvalidated.Identity {
		tmp := *identity
		newUnvalidated.Identity = append(newUnvalidated.Identity, &tmp)
	}
	for _, identity := range unvalidated.Identity {
		activeCount := 0
		// answers we could VERIFY -- see the abstention below; unverifiable is not a vote
		answered := 0
		for _, pioneer := range pioneers {
			pioneerIP, found := s.getPioneerIPAddress(pioneer)
			if !found {
				continue
			}
			node := "tcp://" + pioneerIP + ":26657"
			RootCmd.Flags().Set(flags.FlagNode, node)
			queryClientCtx, err := client.ReadPersistentCommandFlags(clientCtx, RootCmd.Flags())

			if err != nil {
				continue
			}

			queryClient := types.NewQueryClient(queryClientCtx)

			c.LoggerDebug(logger, "Calling QueryEnclaveValidateEnclaveIdentity "+pioneer+" "+identity.UniqueID+" "+identity.SignerID+" "+identity.ProductID)

			report, err := s.getRemoteReport(strings.Join([]string{
				identity.UniqueID,
				identity.SignerID,
				identity.ProductID,
			}, "|"))
			if err != nil {
				continue
			}

			params := &types.QueryEnclaveValidateEnclaveIdentityRequest{
				RemoteReport: report,
				UniqueID:     identity.UniqueID,
				SignerID:     identity.SignerID,
				ProductID:    identity.ProductID,
			}

			c.LoggerDebug(logger, "params "+c.PrettyPrint(params))

			// A DEADLINE, because this poll is the one place the enclave depends on peers being
			// reachable.  context.Background() has none, so a pioneer whose node accepts the
			// connection and then never answers -- wedged, paused, half-partitioned -- stalls the
			// whole pass, and with it every other identity waiting in the queue.  Unreachable peers
			// are already handled correctly (they do not count as a vote, and too few verified
			// answers means abstain rather than condemn); an UNRESPONSIVE one has to be turned into
			// an unreachable one for that handling to apply at all.
			peerCtx, peerCancel := context.WithTimeout(context.Background(), validatePeerTimeout)
			res, err := queryClient.EnclaveValidateEnclaveIdentity(peerCtx, params)
			peerCancel()
			if err != nil {
				c.LoggerError(logger, "err "+err.Error())
				continue
			}

			// need to verify remote report

			if !s.verifyRemoteReport(
				res.GetRemoteReport(),
				strings.Join([]string{
					res.Status,
				}, "|")) {
				// UNVERIFIABLE IS NOT A "NO".  Counting it as one is how an enclave that cannot
				// evaluate its peers ends up voting `inactive` on a perfectly good measurement.
				c.LoggerError(logger, "could not verify "+pioneer+"'s answer about "+identity.UniqueID+
					" -- its enclave is not one we trust; not counting this as a vote either way")
				continue
			}
			answered++

			if res.Status == types.ActiveStatus {
				activeCount++
				if activeCount >= threshold {
					c.LoggerDebug(logger, "enclave identity validated by", pioneer)
					break
				}
			}
		}

		// ABSTAIN RATHER THAN CONDEMN.  A verdict needs enough answers we could actually verify; if
		// fewer than the threshold came back verifiable, we have learned nothing about this identity
		// and must not say otherwise.  Leaving it queued means we try again later, when peers are
		// reachable or our trusted set has grown.
		//
		// This replaces a blunter guard that skipped validation whenever the trusted set was empty.
		// That was wrong in both directions: it stopped the FIRST node of a multi-node chain from
		// ever promoting anything (its set is empty by construction, and one live peer was enough to
		// trip it), while doing nothing about the real hazard, which is not an empty set but an
		// unverifiable answer being counted as a rejection.  Deciding here, where the answers
		// actually arrive, distinguishes "my peers say no" from "I cannot tell what my peers say".
		if len(pioneers) > 0 && answered < threshold {
			c.LoggerInfo(logger, "abstaining on "+identity.UniqueID+": only "+strconv.Itoa(answered)+
				" of "+strconv.Itoa(len(pioneers))+" pioneers gave an answer this enclave could verify (threshold "+
				strconv.Itoa(threshold)+") -- leaving it unvalidated to retry rather than calling it inactive")
			continue
		}

		if len(pioneers) == 0 || activeCount >= threshold {
			if len(pioneers) == 0 {
				c.LoggerInfo(logger, "no pioneers (except self), will mark it as valid")
			} else {
				c.LoggerInfo(logger, "Active count", activeCount, "threshold", threshold, "total pioneers", len(pioneers))
			}
			// mark as valid
			identity.Status = types.ActiveStatus
			c.LoggerDebug(logger, "enclave identity is valid", identity)
			// Our own quorum verdict is evidence we gathered ourselves, so it is one of the four
			// routes into the trusted set.  Recorded before the broadcast: if the broadcast fails we
			// still hold the judgement we reached, and every other node reaches its own.
			s.trustEnclaveIdentity(identity, "our own quorum confirmed it")
		} else {
			// mark as inactive
			identity.Status = types.InactiveStatus
			c.LoggerDebug(logger, "enclave identity is INVALID", identity)
			s.untrustEnclaveIdentity(identity.UniqueID, "our own quorum could not confirm it")
		}

		pwalletID, pwalletAddr, _, _, err := c.GetAddressByNameNoArmor(clientCtx, s.getPrivateEnclaveParamsPioneerID())

		// The height goes INSIDE the certified data, so the receiving enclave can measure the
		// report's age instead of guessing it.  Restating it in the message forges the report.
		attestHeight, _, _ := currentChainPosition()
		report, err := s.getRemoteReport(strings.Join([]string{
			identity.UniqueID,
			identity.SignerID,
			identity.ProductID,
			identity.Status,
			strconv.FormatInt(attestHeight, 10),
		}, "|"))
		if err != nil {
			c.LoggerError(logger, "couldn't getRemoteReport "+err.Error())
			continue
		}
		c.LoggerInfo(logger, "broadcasting identity verdict "+identity.UniqueID+" -> "+identity.Status+
			" attested at height "+strconv.FormatInt(attestHeight, 10)+
			" (confirmed by "+strconv.Itoa(activeCount)+" of "+strconv.Itoa(len(pioneers))+" pioneers, threshold "+strconv.Itoa(threshold)+")")
		msg := types.NewMsgPioneerUpdateEnclaveIdentity(
			pwalletAddr.String(),
			identity.UniqueID,
			identity.SignerID,
			identity.ProductID,
			identity.Status,
			report,
			attestHeight,
		)

		if !broadcast {
			// Decided, not announced.  Our trusted set is already updated above; the on-chain record
			// is the proposer's job, and every node reaches this verdict independently anyway.
			c.LoggerInfo(logger, "not the proposer: keeping the verdict for "+identity.UniqueID+" local, not broadcasting it")
			continue
		}

		msgs := make([]sdk.Msg, 0)
		msgs = append(msgs, msg)

		flagSet := RootCmd.Flags()

		/*
			flagSet.Set(flags.FlagGas, "4000000")

			flagSet.Set(flags.FlagGasPrices, "100000aqdn")
		*/

		c.LoggerDebug(logger, "msgs "+c.PrettyPrint(msgs))

		clientCtx = clientCtx.WithFrom(pwalletID).WithFromAddress(pwalletAddr).WithFromName(s.getPrivateEnclaveParamsPioneerID())
		err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "update enclave identity", msgs...)

		if err != nil {
			c.LoggerError(logger, "failed to broadcast "+err.Error())
			continue
		}

		// remove identity from newUnvalidated

		for i, id := range newUnvalidated.Identity {
			if id.UniqueID == identity.UniqueID {
				newUnvalidated.Identity = append(newUnvalidated.Identity[:i], newUnvalidated.Identity[i+1:]...)
				break
			}
		}
	}

	s.setUnvalidatedEnclaveIdentities(newUnvalidated)
	if len(newUnvalidated.Identity) > 0 {
		c.LoggerDebug(logger, "unvalidatedEnclaveIdentities "+c.PrettyPrint(newUnvalidated))
		unvalidatedEnclaveIdentitiesCheckCounter = 5
	} else {
		c.LoggerDebug(logger, "no unvalidated enclave identities")
	}
}

func (s *qadenaServer) getUnvalidatedEnclaveIdentities() (arr types.EnclaveEnclaveIdentityArray) {
	store := s.secrets(EnclaveUnvalidatedEnclaveIdentityKeyPrefix)
	b := store.Get(EnclaveKeyKey("unvalidated"))
	if b == nil {
		c.LoggerDebug(logger, "unvalidatedEnclaveIdentities nil")
		return
	}
	s.Cdc.MustUnmarshal(b, &arr)
	c.LoggerDebug(logger, "unvalidatedEnclaveIdentities "+c.PrettyPrint(arr))
	return
}

func (s *qadenaServer) setUnvalidatedEnclaveIdentities(arr types.EnclaveEnclaveIdentityArray) {
	store := s.secrets(EnclaveUnvalidatedEnclaveIdentityKeyPrefix)
	b := s.Cdc.MustMarshal(&arr)
	store.Set(EnclaveKeyKey("unvalidated"), b)
	c.LoggerDebug(logger, "setUnvalidatedEnclaveIdentities "+c.PrettyPrint(arr))
}

func (s *qadenaServer) setEnclaveIdentity(in *types.EnclaveIdentity) {
	c.LoggerDebug(logger, "setEnclaveIdentity "+c.PrettyPrint(in))
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	b := s.Cdc.MustMarshal(in)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.EnclaveIdentityKeyPrefix, types.EnclaveIdentityKey(in.UniqueID), b)
	store.Set(types.EnclaveIdentityKey(in.UniqueID), b)

	if in.Status == types.UnvalidatedStatus {
		// get the list of unvalidated enclave identities
		unvalidatedEnclaveIdentities := s.getUnvalidatedEnclaveIdentities()

		unvalidatedEnclaveIdentities.Identity = append(unvalidatedEnclaveIdentities.Identity, in)
		s.setUnvalidatedEnclaveIdentities(unvalidatedEnclaveIdentities)
		unvalidatedEnclaveIdentitiesCheckCounter = 2 // wait a few blocks before validating
		c.LoggerDebug(logger, "setUnvalidatedEnclaveIdentities "+c.PrettyPrint(unvalidatedEnclaveIdentities))
	}
}

// getEnclaveIdentity answers "may this measurement have secrets?", not "is this row present".
//
// It reads the TRUSTED SET, not the mirrored store.  The mirrored row is the chain's opinion,
// delivered by the node, and a node replaying a genesis or snapshot it was handed can put anything
// in it -- see enclave_trusted_identities.go for what that made possible.  The name is unchanged
// because every caller already means the trust question: verifyRemoteReport gates every peer-facing
// handler on it, and QueryEnclaveValidateEnclaveIdentity reports our judgement to a peer asking.
func (s *qadenaServer) getEnclaveIdentity(uniqueID string, signerID string, includeUnvalidated bool) (found bool) {
	return s.trusts(uniqueID, signerID, includeUnvalidated)
}

func (s *qadenaServer) getEnclaveIdentityByUniqueID(uniqueID string) (found bool, id types.EnclaveIdentity) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))

	b := store.Get(types.EnclaveIdentityKey(
		uniqueID,
	))
	if b == nil {
		found = false
		return
	}

	found = true

	s.Cdc.MustUnmarshal(b, &id)
	return
}

func (s *qadenaServer) getWallet(walletID string) (wallet types.Wallet, found bool) {
	//	wallet, found := walletMap[walletID]
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))

	b := store.Get(types.WalletKey(
		walletID,
	))
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find wallet "+walletID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &wallet)

		c.LoggerDebug(logger, "wallet "+c.PrettyPrint(wallet))
		found = true
	}

	return
}

func (s *qadenaServer) getAllWallets() (arr []types.Wallet) {
	arr = make([]types.Wallet, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.Wallet
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) setWalletNoNotify(in types.Wallet) {
	//	walletMap[in.WalletID] = in

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.WalletKeyPrefix))

	var sw types.StableWallet
	c.SetStableWallet(in, &sw)
	b := s.Cdc.MustMarshal(&sw)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.WalletKeyPrefix, types.WalletKey(in.WalletID), b)
	store.Set(types.WalletKey(in.WalletID), b)
}

func (s *qadenaServer) setWallet(in types.Wallet) {
	s.setWalletNoNotify(in)
	outboxAppend(s, outboxWalletsKey, in.WalletID)
}

func (s *qadenaServer) setCredentialNoNotify(credID string, credType string, credential types.Credential) {
	//  credKey := CredentialKey{credID, credType}
	//	credentialMap[credKey] = credential

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.CredentialKeyPrefix))
	b := s.Cdc.MustMarshal(&credential)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.CredentialKeyPrefix, types.CredentialKey(credID, credType), b)
	store.Set(types.CredentialKey(
		credID,
		credType,
	), b)
}

func (s *qadenaServer) removeCredentialNoNotify(credID string, credType string) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.CredentialKeyPrefix))
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Delete lands.
	s.accumulateWrite(types.CredentialKeyPrefix, types.CredentialKey(credID, credType), nil)
	store.Delete(types.CredentialKey(
		credID,
		credType,
	))
	// Note the removal so SyncCredentials can mirror it to the chain.  Unlike setCredential there is
	// no NoNotify/notify pair here: a deletion that the chain never hears about leaves the two
	// copies permanently disagreeing, and no caller wants that.
	outboxAppend(s, outboxRemovedCredentialsKey, outboxCredentialKey{CredentialID: credID, CredentialType: credType})
}

func (s *qadenaServer) setCredential(credID string, credType string, credential types.Credential) {
	s.setCredentialNoNotify(credID, credType, credential)
	outboxAppend(s, outboxChangedCredentialsKey, outboxCredentialKey{CredentialID: credID, CredentialType: credType})
}

func (s *qadenaServer) getCredential(credentialID string, credentialType string) (types.Credential, bool) {
	//	credential, found := credentialMap[CredentialKey{credentialID, credentialType}]

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.CredentialKeyPrefix))

	b := store.Get(types.CredentialKey(
		credentialID,
		credentialType,
	))
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find credential "+credentialID)
		return types.Credential{}, false
	}

	var credential types.Credential

	s.Cdc.MustUnmarshal(b, &credential)

	c.LoggerDebug(logger, "credential "+c.PrettyPrint(credential))

	return credential, true
}

func (s *qadenaServer) getAllCredentials() (arr []types.Credential) {
	arr = make([]types.Credential, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.CredentialKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.Credential
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) getProtectKey(walletID string) (protectKey types.ProtectKey, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.ProtectKeyKeyPrefix))

	b := store.Get(types.ProtectKeyKey(
		walletID,
	))
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find protect key for "+walletID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &protectKey)

		c.LoggerDebug(logger, "protectKey "+c.PrettyPrint(protectKey))
		found = true
	}

	return
}

func (s *qadenaServer) getAllProtectKeys() (arr []types.ProtectKey) {
	arr = make([]types.ProtectKey, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.ProtectKeyKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.ProtectKey
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) getAllDSVSAuthorizedSignatories() (arr []dsvstypes.AuthorizedSignatory) {
	arr = make([]dsvstypes.AuthorizedSignatory, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(dsvstypes.AuthorizedSignatoryKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val dsvstypes.AuthorizedSignatory
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) getAllEnclaveIdentities() (arr []types.EnclaveIdentity) {
	arr = make([]types.EnclaveIdentity, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.EnclaveIdentity
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) setProtectKeyNoNotify(in *types.ProtectKey) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.ProtectKeyKeyPrefix))

	b := s.Cdc.MustMarshal(in)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.ProtectKeyKeyPrefix, types.ProtectKeyKey(in.WalletID), b)
	store.Set(types.ProtectKeyKey(in.WalletID), b)
}

func (s *qadenaServer) getRecoverKeyByOriginalWalletID(walletID string) (recoverKey types.RecoverKey, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.RecoverKeyKeyPrefix))

	b := store.Get(types.RecoverKeyKey(walletID))
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find recoverkey for "+walletID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &recoverKey)

		c.LoggerDebug(logger, "recoverKey "+c.PrettyPrint(recoverKey))
		found = true
	}

	return
}

func (s *qadenaServer) getAllRecoverKeyByOriginalWalletIDs() (arr []types.RecoverKey) {
	arr = make([]types.RecoverKey, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.RecoverKeyKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.RecoverKey
		s.Cdc.MustUnmarshal(itr.Value(), &val)
		arr = append(arr, val)
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) setRecoverKeyByOriginalWalletIDNoNotify(walletID string, in *types.RecoverKey) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.RecoverKeyKeyPrefix))

	b := s.Cdc.MustMarshal(in)
	// Maintain the shadow accumulator BEFORE the write: an overwrite has to subtract the
	// row's previous value, which is gone once this store.Set lands.
	s.accumulateWrite(types.RecoverKeyKeyPrefix, types.RecoverKeyKey(walletID), b)
	store.Set(types.RecoverKeyKey(walletID), b)
}

func (s *qadenaServer) setRecoverKeyByOriginalWalletID(walletID string, in *types.RecoverKey) {
	s.setRecoverKeyByOriginalWalletIDNoNotify(walletID, in)
	outboxAppend(s, outboxRecoverKeysKey, walletID)
}

// called from various Qadena MsgServer
// previousPubK is the key this one replaced, and is what the rotation grace period is built on: a
// VShare bound moments before a rotation still names the old key, and refusing it would fail a
// well-formed transaction over timing alone.  A previous id with no PublicKey row behind it is not
// an error -- previousPubK comes back empty and the caller simply gets no grace.
//
// The chain's Keeper.GetIntervalPublicKeyWithPrevious does exactly this; the two must stay in step,
// because they validate the same VShares and a disagreement is a fork.
func (s *qadenaServer) enclaveGetIntervalPublicKey(intervalNodeID string, intervalNodeType string) (pubKID string, pubK string, previousPubK string, serviceProviderType string, err error) {
	// find the interval ss pubk
	intervalPubKID, previousPubKID, spType, found := s.getIntervalPublicKeyId(intervalNodeID, intervalNodeType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	intervalPubK, found := s.getPublicKey(intervalPubKID, types.TransactionPubKType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	if previousPubKID != "" {
		if prev, prevFound := s.getPublicKey(previousPubKID, types.TransactionPubKType); prevFound {
			previousPubK = prev
		}
	}

	pubKID = intervalPubKID
	pubK = intervalPubK
	serviceProviderType = spType
	return
}

func (s *qadenaServer) enclaveGetJarForPioneer(pioneerID string) (jarID string, err error) {
	// find the interval ss pubk
	pioneerJar, found := s.getPioneerJar(pioneerID)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	jarID = pioneerJar
	return
}

func (s *qadenaServer) enclaveAppendRequiredChainCCPubK(ccPubK []c.VSharePubKInfo, pioneerID string, excludeSSIntervalPubK bool) ([]c.VSharePubKInfo, error) {
	if excludeSSIntervalPubK && pioneerID == "" {
		c.LoggerError(logger, "Logic error")
		return nil, fmt.Errorf("Logic error")
	}
	if !excludeSSIntervalPubK {
		// AltPubK carries the key this one replaced, so a VShare bound just before a rotation still
		// satisfies the expectation.  See common.VSharePubKInfo.
		ssIntervalPubKID, ssIntervalPubK, ssPreviousPubK, _, err := s.enclaveGetIntervalPublicKey(types.SSNodeID, types.SSNodeType)

		if err != nil {
			c.LoggerError(logger, "Couldn't get interval public key")
			return nil, err
		}

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     ssIntervalPubK,
			AltPubK:  ssPreviousPubK,
			NodeID:   types.SSNodeID,
			NodeType: types.SSNodeType,
		})

		c.LoggerDebug(logger, "ssIntervalPubKID", ssIntervalPubKID, "ssIntervalPubK", ssIntervalPubK)
	}

	if pioneerID != "" {
		jarID, err := s.enclaveGetJarForPioneer(pioneerID)

		if err != nil {
			c.LoggerError(logger, "Couldn't get jar for pioneer", pioneerID)
			return nil, err
		}

		c.LoggerDebug(logger, "jarID", jarID)

		jarIntervalPubKID, jarIntervalPubK, jarPreviousPubK, _, err := s.enclaveGetIntervalPublicKey(jarID, types.JarNodeType)

		if err != nil {
			c.LoggerError(logger, "Couldn't get jar interval public key", jarID, types.JarNodeType)
			return nil, err
		}

		c.LoggerDebug(logger, "jarIntervalPubKID", jarIntervalPubKID, "jarIntervalPubK", jarIntervalPubK)

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     jarIntervalPubK,
			AltPubK:  jarPreviousPubK,
			NodeID:   jarID,
			NodeType: types.JarNodeType,
		})
	}

	return ccPubK, nil
}

// find any service providers that are optional
func (s *qadenaServer) enclaveAppendOptionalServiceProvidersCCPubK(ccPubK []c.VSharePubKInfo, serviceProviderID []string, optionalServiceProviderType []string) ([]c.VSharePubKInfo, error) {
	for i := range serviceProviderID {
		_, pubK, previousPubK, serviceProviderType, err := s.enclaveGetIntervalPublicKey(serviceProviderID[i], types.ServiceProviderNodeType)
		if err != nil {
			c.LoggerError(logger, "Couldn't get service provider interval public key", serviceProviderID[i], types.ServiceProviderNodeType)
			return nil, err
		}

		// check if serviceProviderType is in array requiredServiceProviderType
		for j := range optionalServiceProviderType {
			if serviceProviderType == optionalServiceProviderType[j] {
				ccPubK = append(ccPubK, c.VSharePubKInfo{
					PubK:     pubK,
					AltPubK:  previousPubK,
					NodeID:   serviceProviderID[i],
					NodeType: types.ServiceProviderNodeType,
				})
			}
		}
	}

	return ccPubK, nil
}

func (s *qadenaServer) SyncWallets(ctx context.Context, in *types.MsgSyncWallets) (*types.SyncWalletsReply, error) {
	//  c.LoggerDebug(logger, "SyncWallets " + c.PrettyPrint(in))

	queue := outboxGet[string](s, outboxWalletsKey)

	wallets, consumed, more := outboxDrainPage(queue, outboxPageBudget(in.GetMaxBytes()),
		func(id string) (*types.Wallet, int, bool) {
			c.LoggerDebug(logger, "Wallet changed "+id)
			wallet, found := s.getWallet(id)
			if !found {
				return nil, 0, false
			}
			return &wallet, wallet.Size(), true
		})

	// The clear goes through the transaction cache (outboxSet), so it becomes durable exactly
	// when the block that consumed these rows commits at EndBlock -- a crash before that commit
	// leaves the queue intact for the block's re-execution.  That is also why the caller must
	// finish paging WITHIN one block: every page's clear commits together with the chain's writes.
	more = outboxCommitPage(s, outboxWalletsKey, queue, consumed, in.Clear && len(wallets) > 0, more)

	return &types.SyncWalletsReply{Wallets: wallets, More: more}, nil
}

/*
func (s *qadenaServer) SyncEnclaveIdentities(ctx context.Context, in *types.MsgSyncEnclaveIdentities) (*types.SyncEnclaveIdentitiesReply, error) {
	//  c.LoggerDebug(logger, "SyncWallets " + c.PrettyPrint(in))

	enclaveIdentities := []*types.EnclaveIdentity{}

	for _, changedEnclaveIdentity := range s.changedEnclaveIdentities {
		c.LoggerDebug(logger, "EnclaveIdentity changed uniqueid "+changedEnclaveIdentity)
		found, enclaveIdentity := s.getEnclaveIdentityByUniqueID(changedEnclaveIdentity)
		if found {
			enclaveIdentities = append(enclaveIdentities, &enclaveIdentity)
		}
	}

	if in.Clear && len(enclaveIdentities) > 0 {
		c.LoggerDebug(logger, "Clearing s.changedEnclaveIdentities")
		s.changedEnclaveIdentities = nil
	}

	return &types.SyncEnclaveIdentitiesReply{EnclaveIdentities: enclaveIdentities}, nil
}
*/

func (s *qadenaServer) SyncCredentials(ctx context.Context, in *types.MsgSyncCredentials) (*types.SyncCredentialsReply, error) {
	//  c.LoggerDebug(logger, "SyncCredentials " + c.PrettyPrint(in))

	budget := outboxPageBudget(in.GetMaxBytes())

	changedQueue := outboxGet[outboxCredentialKey](s, outboxChangedCredentialsKey)

	credentials, changedConsumed, changedMore := outboxDrainPage(changedQueue, budget,
		func(k outboxCredentialKey) (*types.Credential, int, bool) {
			c.LoggerDebug(logger, "Credential changed "+c.PrettyPrint(k))
			credential, found := s.getCredential(k.CredentialID, k.CredentialType)
			if !found {
				return nil, 0, false
			}
			return &credential, credential.Size(), true
		})

	// The two queues share one reply, so they share one budget: whatever the changed credentials
	// did not use is what the removals get.  Removals are tiny -- an ID and a type -- so in
	// practice they fit in the remainder of any page, but the floor keeps a full changed page from
	// starving them entirely and stalling removals behind a long backlog.
	removedBudget := budget - sizeOfCredentials(credentials)
	if removedBudget < budget/8 {
		removedBudget = budget / 8
	}

	removedQueue := outboxGet[outboxCredentialKey](s, outboxRemovedCredentialsKey)

	removed, removedConsumed, removedMore := outboxDrainPage(removedQueue, removedBudget,
		func(k outboxCredentialKey) (*types.CredentialRef, int, bool) {
			// Re-check the store rather than trusting the note we made.  Now that the queue lives
			// in the transaction cache a rolled-back removal discards its own entry, so this guard
			// should never fire -- it stays as defence in depth, because reporting a deletion the
			// enclave no longer believes in would delete it on chain for good.
			//
			// A rolled-back removal resolves to `false`, which drops it from the queue.  That is
			// the intent: the removal did not happen, so there is nothing left to report.
			if _, found := s.getCredential(k.CredentialID, k.CredentialType); found {
				c.LoggerDebug(logger, "Credential removal was rolled back "+c.PrettyPrint(k))
				return nil, 0, false
			}
			ref := &types.CredentialRef{CredentialID: k.CredentialID, CredentialType: k.CredentialType}
			return ref, ref.Size(), true
		})

	changedMore = outboxCommitPage(s, outboxChangedCredentialsKey, changedQueue, changedConsumed, in.Clear && len(credentials) > 0, changedMore)
	removedMore = outboxCommitPage(s, outboxRemovedCredentialsKey, removedQueue, removedConsumed, in.Clear && len(removedQueue) > 0, removedMore)

	return &types.SyncCredentialsReply{
		Credentials:        credentials,
		RemovedCredentials: removed,
		More:               changedMore || removedMore,
	}, nil
}

func sizeOfCredentials(credentials []*types.Credential) int {
	n := 0
	for _, credential := range credentials {
		n += credential.Size()
	}
	return n
}

func (s *qadenaServer) SyncRecoverKeys(ctx context.Context, in *types.MsgSyncRecoverKeys) (*types.SyncRecoverKeysReply, error) {
	//  c.LoggerDebug(logger, "SyncRecoverKeys " + c.PrettyPrint(in))

	queue := outboxGet[string](s, outboxRecoverKeysKey)

	recoverKeys, consumed, more := outboxDrainPage(queue, outboxPageBudget(in.GetMaxBytes()),
		func(walletID string) (*types.RecoverKey, int, bool) {
			c.LoggerDebug(logger, "RecoverKey changed "+walletID)
			recoverKey, found := s.getRecoverKeyByOriginalWalletID(walletID)
			if !found {
				return nil, 0, false
			}
			return &recoverKey, recoverKey.Size(), true
		})

	more = outboxCommitPage(s, outboxRecoverKeysKey, queue, consumed, in.Clear && len(recoverKeys) > 0, more)

	return &types.SyncRecoverKeysReply{RecoverKeys: recoverKeys, More: more}, nil
}

func (s *qadenaServer) SyncSuspiciousTransactions(ctx context.Context, in *types.MsgSyncSuspiciousTransactions) (*types.SyncSuspiciousTransactionsReply, error) {
	c.LoggerDebug(logger, "SyncSuspiciousTransactions "+c.PrettyPrint(in))

	// display count of new suspicious transactions

	queue := outboxGet[types.SuspiciousTransaction](s, outboxSuspiciousKey)
	c.LoggerDebug(logger, "# suspicious outbox "+strconv.Itoa(len(queue)))

	// This queue carries the ROWS, not IDs, so nothing has to be resolved and no entry can fail to
	// resolve.  It is also the one queue whose entries are attacker-influenced in size, which is
	// the strongest case for a bound.
	//
	// The index is taken rather than the loop variable: these pointers outlive the walk.
	suspiciousTransactions, consumed, more := outboxDrainPage(queue, outboxPageBudget(in.GetMaxBytes()),
		func(st types.SuspiciousTransaction) (*types.SuspiciousTransaction, int, bool) {
			row := st
			return &row, row.Size(), true
		})

	more = outboxCommitPage(s, outboxSuspiciousKey, queue, consumed, in.Clear && len(queue) > 0, more)

	return &types.SyncSuspiciousTransactionsReply{SuspiciousTransactions: suspiciousTransactions, More: more}, nil
}

func slicesEqual(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

func (s *qadenaServer) ValidateDestinationWallet(ctx context.Context, msg *types.MsgCreateWallet) (*types.ValidateDestinationWalletReply, error) {

	walletID := msg.Creator

	c.LoggerDebug(logger, "validate destination wallet of "+walletID)

	// decrypt the destination wallet id
	var vShareCreateWallet types.EncryptableCreateWallet

	c.LoggerDebug(logger, "EncCreateWalletVShare: ")

	unprotoMsgCreateWalletVShareBind := c.UnprotoizeVShareBindData(msg.CreateWalletVShareBind)

	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoMsgCreateWalletVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoMsgCreateWalletVShareBind.GetSSIntervalPubKID()), unprotoMsgCreateWalletVShareBind, msg.EncCreateWalletVShare, &vShareCreateWallet)
	if err != nil {
		return &types.ValidateDestinationWalletReply{Status: types.WalletTypeUnknown}, err
	}

	dstEWalletID := vShareCreateWallet.DstEWalletID

	c.LoggerDebug(logger, "dstEWalletID "+c.PrettyPrint(dstEWalletID))

	if walletID == dstEWalletID.WalletID {
		c.LoggerDebug(logger, "Nothing to validate, it is a real wallet "+dstEWalletID.WalletID)
		return &types.ValidateDestinationWalletReply{Status: types.WalletTypeReal}, nil
	}

	dstWallet, found := s.getWallet(dstEWalletID.WalletID)

	if found {
		if dstWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
			// need to validate that the submitted pioneerID is the same as what's on the eph wallet
			if dstWallet.HomePioneerID != msg.HomePioneerID {
				c.LoggerDebug(logger, "home pioneer id mismatch "+dstWallet.HomePioneerID+" "+msg.HomePioneerID)
				return nil, types.ErrInvalidWallet
			}

			// need to validate that the submitted serviceProviderID is the same as what's on the eph wallet
			// compare the service provider id

			if !slicesEqual(dstWallet.ServiceProviderID, msg.ServiceProviderID) {
				c.LoggerDebug(logger, "service provider id mismatch "+c.PrettyPrint(dstWallet.ServiceProviderID)+" "+c.PrettyPrint(msg.ServiceProviderID))
				return nil, types.ErrInvalidWallet
			}

			// WE NEED TO VALIDATE THAT THE ONE WHO CREATED THE EPH WALLET HAS A KEY TO THE REAL WALLET!

			c.LoggerDebug(logger, "Validating submitted Proof PC")

			if _, ok := dstWallet.WalletAmount[types.QadenaTokenDenom]; ok {
				cwExtraParms := dstEWalletID.ExtraParms

				if cwExtraParms == nil {
					c.LoggerDebug(logger, "create wallet extra parms is nil")
					return &types.ValidateDestinationWalletReply{Status: types.WalletTypeUnknown}, types.ErrInvalidCreateWallet
				}

				c.LoggerDebug(logger, "create wallet extra parms "+c.PrettyPrint(cwExtraParms))
				unProtoPC := c.UnprotoizeBPedersenCommit(dstWallet.WalletAmount[types.QadenaTokenDenom].WalletAmountPedersenCommit)
				hashPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(walletID))), big.NewInt(0))
				if !c.ValidateAddPedersenCommit(hashPC, unProtoPC, c.UnprotoizeBPedersenCommit(cwExtraParms.ProofPC)) {
					return &types.ValidateDestinationWalletReply{Status: types.WalletTypeUnknown}, types.ErrGenericPedersen
				}
				c.LoggerDebug(logger, "ProofPC accepted!")
			}

			c.LoggerDebug(logger, "ephemeral wallet "+walletID+" mapped to real wallet "+dstEWalletID.WalletID)

			if msg.EncAcceptValidatedCredentialsVShare != nil {
				// need to validate any "accept credentials"
				c.LoggerDebug(logger, "Validating accept-credentials")
				var vcs types.EncryptableValidatedCredentials
				unprotoAcceptValidatedCredentialsVShareBind := c.UnprotoizeVShareBindData(msg.AcceptValidatedCredentialsVShareBind)
				err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoAcceptValidatedCredentialsVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoAcceptValidatedCredentialsVShareBind.GetSSIntervalPubKID()), unprotoAcceptValidatedCredentialsVShareBind, msg.EncAcceptValidatedCredentialsVShare, &vcs)
				if err != nil {
					return &types.ValidateDestinationWalletReply{Status: types.WalletTypeUnknown}, err
				}
				c.LoggerDebug(logger, "no error decrypting")
				c.LoggerDebug(logger, "going through each credential "+c.PrettyPrint(vcs))
				for i := range vcs.Credentials {
					vc := vcs.Credentials[i]
					credential, found := s.getCredential(dstWallet.CredentialID, vc.CredentialType)
					if !found {
						c.LoggerDebug(logger, "could not find credential "+dstWallet.CredentialID+" "+vc.CredentialType)
						return nil, types.ErrCredentialNotExists
					}
					c.LoggerDebug(logger, "credential "+c.PrettyPrint(credential))
					credentialPC := c.UnprotoizeBPedersenCommit(credential.CredentialPedersenCommit)
					if !c.ComparePedersenCommit(c.UnprotoizeBPedersenCommit(vc.CredentialPC), credentialPC) {
						c.LoggerError(logger, "failed comparing check "+c.PrettyPrint(vc.CredentialPC)+" stored "+c.PrettyPrint(credentialPC))
						return nil, types.ErrInvalidCredential
					}
					c.LoggerDebug(logger, "Accepted credential "+vc.CredentialType)
				}
			}

			return &types.ValidateDestinationWalletReply{Status: types.WalletTypeEphemeral}, nil
		} else {
			c.LoggerError(logger, "cannot bind an ephemeral wallet to another ephemeral wallet")
			return &types.ValidateDestinationWalletReply{Status: types.WalletTypeUnknown}, types.ErrInvalidDstEWalletID
		}
	}

	c.LoggerError(logger, "unable to find wallet "+dstEWalletID.WalletID)
	return &types.ValidateDestinationWalletReply{Status: types.WalletTypeUnknown}, types.ErrWalletNotExists
}

// ValidatePersonalInfo checks a credential at CREATE time, which is the only point where the
// identity provider that submitted it is still the party being told about the result.
//
// Without this the chain cannot check anything: the details arrive sealed in a VShare and the
// keeper has no key, so a malformed name is only discovered when someone tries to claim it -- at
// which point the claimant, who never typed it, gets an unexplained rejection and the credential is
// permanently unclaimable.  ClaimCredential still repeats the check; this one is about telling the
// right party at the right time, not about trust.
//
// The reason travels back as a code, never as text.  Only the enclave can read these fields, and a
// transaction error is public: returning "birthdate is not canonical, expected 1970-Feb-02" would
// publish the birthdate that the VShare exists to protect.  The detailed message goes to the
// enclave log; the keeper turns the code into a fixed sentence naming the rule.
func (s *qadenaServer) ValidatePersonalInfo(ctx context.Context, msg *types.MsgCreateCredential) (*types.ValidatePersonalInfoReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "ValidatePersonalInfo")
	} else {
		c.LoggerDebug(logger, "ValidatePersonalInfo "+c.PrettyPrint(msg))
	}

	// Only personal-info carries the fields the identity hash is built from.  Contact credentials
	// have no such invariants, so they pass untouched rather than being rejected for lacking them.
	if msg.CredentialType != types.PersonalInfoCredentialType {
		return &types.ValidatePersonalInfoReply{Status: true}, nil
	}

	unprotoCredentialInfoVShareBind := c.UnprotoizeVShareBindData(msg.CredentialInfoVShareBind)

	var p types.EncryptablePersonalInfo
	err := c.VShareBDecryptAndProtoUnmarshal(
		s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()),
		s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()),
		unprotoCredentialInfoVShareBind, msg.EncCredentialInfoVShare, &p)
	if err != nil {
		// Undecryptable is not the same as invalid: the enclave may simply not hold this interval
		// key.  Report it as an error rather than a validation verdict, so the keeper can tell the
		// difference between "this credential is bad" and "this node could not check it".
		c.LoggerError(logger, "ValidatePersonalInfo couldn't decrypt credential info "+err.Error())
		return nil, types.ErrGenericEncryption
	}

	reason := c.PersonalInfoReasonOf(p.Details)
	if reason != c.PersonalInfoOK {
		// the detailed message stops here, in the log
		c.LoggerError(logger, "ValidatePersonalInfo rejected "+msg.CredentialID+": "+
			c.ValidatePersonalInfoDetails(p.Details).Error())
		return &types.ValidatePersonalInfoReply{Status: false, Reason: int32(reason)}, nil
	}

	return &types.ValidatePersonalInfoReply{Status: true}, nil
}

func (s *qadenaServer) ValidateCredential(ctx context.Context, msg *types.MsgBindCredential) (*types.ValidateCredentialReply, error) {
	ephWalletID := msg.Creator
	credentialType := msg.CredentialType
	credentialInfo := msg.CredentialInfo
	proofPedersenCommit := c.UnprotoizeBPedersenCommit(msg.ProofPedersenCommit)

	c.LoggerDebug(logger, "validate credential "+ephWalletID+" "+credentialType+" "+credentialInfo+" "+c.PrettyPrint(proofPedersenCommit))

	ephWallet, found := s.getWallet(ephWalletID)
	if !found {
		return &types.ValidateCredentialReply{Status: false}, types.ErrWalletNotExists
	}

	if ephWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
		// can't bind to a real wallet, has to be an ephemeral wallet
		return &types.ValidateCredentialReply{Status: false}, types.ErrInvalidWallet
	}

	c.LoggerDebug(logger, "EncWalletVShare: ")

	unprotoEphCreateWalletVShareBind := c.UnprotoizeVShareBindData(ephWallet.CreateWalletVShareBind)
	// decrypt the destination wallet id
	var vShareWallet types.EncryptableCreateWallet

	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoEphCreateWalletVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoEphCreateWalletVShareBind.GetSSIntervalPubKID()), unprotoEphCreateWalletVShareBind, ephWallet.EncCreateWalletVShare, &vShareWallet)
	if err != nil {
		return nil, err
	}

	// find the real wallet
	srcEWalletID := vShareWallet.DstEWalletID

	c.LoggerDebug(logger, "srcEWalletID "+c.PrettyPrint(srcEWalletID))

	srcWallet, found := s.getWallet(srcEWalletID.WalletID)
	if !found {
		return &types.ValidateCredentialReply{Status: false}, types.ErrWalletNotExists
	}

	c.LoggerDebug(logger, "srcWallet "+c.PrettyPrint(srcWallet))

	credential, found := s.getCredential(srcWallet.CredentialID, credentialType)
	if !found {
		return &types.ValidateCredentialReply{Status: false}, types.ErrCredentialNotExists
	}

	c.LoggerDebug(logger, "credential "+c.PrettyPrint(credential))

	details := new(types.EncryptableSingleContactInfoDetails)
	details.Contact = credentialInfo
	credBytes, _ := proto.Marshal(details)

	hashInt := big.NewInt(0).SetBytes(tmhash.Sum([]byte(credBytes)))
	pc := c.NewPedersenCommit(hashInt, c.BigIntZero)

	pinPC := c.UnprotoizeBPedersenCommit(credential.CredentialPedersenCommit)

	c.LoggerDebug(logger, "pc "+c.PrettyPrint(pc))
	c.LoggerDebug(logger, "pinPC "+c.PrettyPrint(pinPC))
	c.LoggerDebug(logger, "proofPC "+c.PrettyPrint(proofPedersenCommit))

	if c.ValidateSubPedersenCommit(pc, pinPC, proofPedersenCommit) {
		c.LoggerDebug(logger, "validated proofPedersenCommit")
		return &types.ValidateCredentialReply{Status: true}, nil
	}
	c.LoggerError(logger, "invalid proofPedersenCommit")

	return &types.ValidateCredentialReply{Status: false}, types.ErrInvalidCredential
}

func findPINAndPC(vcs types.EncryptableValidatedCredentials, credentialType string) (string, *c.PedersenCommit) {
	for i := range vcs.Credentials {
		if vcs.Credentials[i].CredentialType == credentialType {
			return vcs.Credentials[i].PIN, c.UnprotoizeBPedersenCommit(vcs.Credentials[i].CredentialPC)
		}
	}
	return "", nil
}

func (s *qadenaServer) ValidateAuthenticateServiceProvider(ctx context.Context, ValidateAuthenticateServiceProviderRequest *types.ValidateAuthenticateServiceProviderRequest) (*types.ValidateAuthenticateServiceProviderReply, error) {
	c.LoggerDebug(logger, "ValidateAuthenticateServiceProvider pubKID: "+ValidateAuthenticateServiceProviderRequest.PubKID+" serviceProviderType: "+ValidateAuthenticateServiceProviderRequest.ServiceProviderType)

	wallet, found := s.getWallet(ValidateAuthenticateServiceProviderRequest.PubKID)

	if !found {
		return &types.ValidateAuthenticateServiceProviderReply{Status: false}, types.ErrWalletNotExists
	}

	if wallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
		c.LoggerError(logger, "wallet is not an ephemeral wallet")
		return &types.ValidateAuthenticateServiceProviderReply{Status: false}, types.ErrInvalidWallet
	}

	var vShareCreateWallet types.EncryptableCreateWallet

	unprotoCreateWalletVShareBind := c.UnprotoizeVShareBindData(wallet.CreateWalletVShareBind)
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCreateWalletVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCreateWalletVShareBind.GetSSIntervalPubKID()), unprotoCreateWalletVShareBind, wallet.EncCreateWalletVShare, &vShareCreateWallet)

	if err != nil {
		c.LoggerError(logger, "couldn't decrypt vShareCreateWallet "+err.Error())
		return &types.ValidateAuthenticateServiceProviderReply{Status: false}, err
	}

	c.LoggerDebug(logger, "vShareCreateWallet "+c.PrettyPrint(vShareCreateWallet))

	realWalletID := vShareCreateWallet.DstEWalletID.WalletID

	c.LoggerDebug(logger, "realWalletID "+realWalletID)

	// find the interval by pubkid
	keyID, serviceProviderType, found := s.getIntervalPublicKeyIdByPubKID(realWalletID)
	if !found {
		c.LoggerError(logger, "couldn't find interval public key ID")
		return &types.ValidateAuthenticateServiceProviderReply{Status: false}, types.ErrIntervalPublicKeyIDNotExists
	}

	c.LoggerDebug(logger, "keyID "+keyID+" serviceProviderType "+serviceProviderType)

	if serviceProviderType != ValidateAuthenticateServiceProviderRequest.ServiceProviderType {
		c.LoggerError(logger, "service provider type doesn't match")
		return &types.ValidateAuthenticateServiceProviderReply{Status: false}, types.ErrServiceProviderUnauthorized
	}

	return &types.ValidateAuthenticateServiceProviderReply{Status: true}, nil
}

func (s *qadenaServer) ValidateTransferPrime(ctx context.Context, msg *types.MsgTransferFunds) (*types.ValidateTransferPrimeReply, error) {
	c.LoggerDebug(logger, "validate transfer prime, update ephemeral wallet")

	unprotoMsgTransferFundsVShareBind := c.UnprotoizeVShareBindData(msg.TransferFundsVShareBind)

	if unprotoMsgTransferFundsVShareBind.GetJarID() != s.getSharedEnclaveParamsJarID() {
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrGenericEncryption
	}

	//	accountAddress, err := sdk.AccAddressFromBech32(msg.Creator)
	//	if err != nil {
	//		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrInvalidCreator
	//	}

	c.LoggerDebug(logger, "it's mine, we can decode")

	var anonTransferFunds types.EncryptableAnonTransferFunds

	//  var zeroPrimePC c.PedersenCommit
	// bankPC := c.UnprotoizePedersenCommit(*msg.BankPC)

	unprotoMsgAnonTransferFundsVShareBind := c.UnprotoizeVShareBindData(msg.AnonTransferFundsVShareBind)
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoMsgAnonTransferFundsVShareBind, msg.EncAnonTransferFundsVShare, &anonTransferFunds)
	if err != nil {
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrGenericEncryption
	}

	transparentTransferBF := anonTransferFunds.TransparentTransferBF

	totalTransferPrimePC := anonTransferFunds.TotalTransferPrimePC

	transparentTransferAmount := c.UnprotoizeBInt(msg.TransparentAmount)

	transparentTransferPC := c.NewPedersenCommit(transparentTransferAmount, c.UnprotoizeBInt(transparentTransferBF)) // random blinding factor

	c.LoggerDebug(logger, "transparentTransferPC "+c.PrettyPrint(transparentTransferPC))

	var vShareTransferFunds types.EncryptableTransferFunds

	c.LoggerDebug(logger, "EncTransferFundsVShare: ")

	err = c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoMsgTransferFundsVShareBind, msg.EncTransferFundsVShare, &vShareTransferFunds)
	if err != nil {
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrGenericEncryption
	}

	dstEWalletID := vShareTransferFunds.DstEWalletID

	if !c.ValidatePedersenCommit(transparentTransferPC) {
		if c.Debug {
			c.LoggerError(logger, "transparentTransferPC is invalid"+c.PrettyPrint(transparentTransferPC))
		}
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrGenericPedersen
	}

	if transparentTransferPC.A.Cmp(c.BigIntZero) < 0 {
		if c.Debug {
			c.LoggerError(logger, "transparentTransferPC.A < 0 "+c.PrettyPrint(transparentTransferPC.A)+" "+c.PrettyPrint(c.BigIntZero))
		}
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrGenericPedersen
	}

	unprotoHiddenTransferPC := c.UnprotoizeBPedersenCommit(msg.HiddenTransferPC)

	// validate that bank + transfer = transferprime
	if c.ValidateAddPedersenCommit(transparentTransferPC, unprotoHiddenTransferPC, c.UnprotoizeEncryptablePedersenCommit(totalTransferPrimePC)) {
		if c.Debug {
			c.LoggerDebug(logger, "validated transparentTransferPC + transferPC == transferPrimePC")
		}
	} else {
		if c.Debug {
			c.LoggerError(logger, "transparentTransferPC", c.PrettyPrint(transparentTransferPC))
			c.LoggerError(logger, "hiddenTransferPC", c.PrettyPrint(unprotoHiddenTransferPC))
			c.LoggerError(logger, "totalTransferPrimePC", c.PrettyPrint(c.UnprotoizeEncryptablePedersenCommit(totalTransferPrimePC)))
			c.LoggerError(logger, "INVALID transparentTransferPC + transferPC != transferPrimePC")
		}
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrGenericPedersen
	}

	dstWallet, found := s.getWallet(dstEWalletID.WalletID)

	if !found {
		c.LoggerError(logger, "unable to find wallet", dstEWalletID.WalletID)
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrWalletNotExists
	}

	c.LoggerDebug(logger, "dstWallet "+c.PrettyPrint(dstWallet))

	token := msg.TokenDenom

	if token == types.AQadenaTokenDenom {
		token = types.QadenaTokenDenom
	}

	if dstWallet.EphemeralWalletAmountCount[token] == types.QadenaRealWallet {
		c.LoggerError(logger, "the destination wallet is a real wallet, not an ephemeral wallet")
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrInvalidWallet
	}

	tfExtraParms := dstEWalletID.ExtraParms

	if tfExtraParms == nil {
		c.LoggerDebug(logger, "transfer funds extra parms is nil")
		return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrInvalidTransfer
	}

	c.LoggerDebug(logger, "transfer funds extra parms "+c.PrettyPrint(tfExtraParms))

	requiredSenderCheckPCs := []*types.BPedersenCommit{}

	if dstWallet.SenderOptions != "" {
		senderOptions := strings.Split(dstWallet.SenderOptions, ",")

		c.LoggerDebug(logger, "senderOptions"+c.PrettyPrint(senderOptions))

		if findSenderOption(senderOptions, types.RequireSenderFirstNamePersonalInfoSenderOption) {
			srcWallet, found := s.getWallet(msg.Creator)
			if !found {
				c.LoggerDebug(logger, "Couldn't find srcWallet "+msg.Creator)
				return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrWalletNotExists
			}

			c.LoggerDebug(logger, "srcWallet", c.PrettyPrint(srcWallet))
			credential, found := s.getCredential(srcWallet.CredentialID, types.FirstNamePersonalInfoCredentialType)
			if !found {
				c.LoggerDebug(logger, "Couldn't find credential "+srcWallet.CredentialID)
				return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrCredentialNotExists
			}

			// validate
			credentialPC := c.UnprotoizeBPedersenCommit(credential.CredentialPedersenCommit)
			c.LoggerDebug(logger, "requiredSenderCheckPC "+c.PrettyPrint(tfExtraParms.RequiredSenderFirstNameCheckPC))
			c.LoggerDebug(logger, "credentialPC "+c.PrettyPrint(credential.CredentialPedersenCommit))
			c.LoggerDebug(logger, "proofPC "+c.PrettyPrint(tfExtraParms.RequiredSenderFirstNameProofPC))

			if !c.ValidPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderFirstNameCheckPC)) || !c.ValidPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderFirstNameProofPC)) {
				c.LoggerDebug(logger, "First name not supplied")
				return nil, types.ErrInvalidTransfer
			}

			if !c.ValidateSubPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderFirstNameCheckPC), credentialPC, c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderFirstNameProofPC)) {
				if c.Debug {
					c.LoggerError(logger, "failed to validate checkPC - credentialPC - proofPC = 0")
				}
				return nil, types.ErrGenericPedersen
			}
			c.LoggerDebug(logger, "Credential passed validation")
			protoCheckPC := tfExtraParms.RequiredSenderFirstNameCheckPC
			requiredSenderCheckPCs = append(requiredSenderCheckPCs, protoCheckPC)
		}

		if findSenderOption(senderOptions, types.RequireSenderMiddleNamePersonalInfoSenderOption) {
			srcWallet, found := s.getWallet(msg.Creator)
			if !found {
				c.LoggerDebug(logger, "Couldn't find srcWallet "+msg.Creator)
				return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrWalletNotExists
			}

			c.LoggerDebug(logger, "srcWallet", c.PrettyPrint(srcWallet))
			credential, found := s.getCredential(srcWallet.CredentialID, types.MiddleNamePersonalInfoCredentialType)
			if !found {
				c.LoggerDebug(logger, "Couldn't find credential "+srcWallet.CredentialID)
				return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrCredentialNotExists
			}

			// validate
			credentialPC := c.UnprotoizeBPedersenCommit(credential.CredentialPedersenCommit)
			c.LoggerDebug(logger, "requiredSenderCheckPC "+c.PrettyPrint(tfExtraParms.RequiredSenderMiddleNameCheckPC))
			c.LoggerDebug(logger, "credentialPC "+c.PrettyPrint(credential.CredentialPedersenCommit))
			c.LoggerDebug(logger, "proofPC "+c.PrettyPrint(tfExtraParms.RequiredSenderMiddleNameProofPC))

			if !c.ValidPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderMiddleNameCheckPC)) || !c.ValidPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderMiddleNameProofPC)) {
				c.LoggerDebug(logger, "Middle name not supplied")
				return nil, types.ErrInvalidTransfer
			}

			if !c.ValidateSubPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderMiddleNameCheckPC), credentialPC, c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderMiddleNameProofPC)) {
				if c.Debug {
					c.LoggerError(logger, "failed to validate checkPC - credentialPC - proofPC = 0")
				}
				return nil, types.ErrGenericPedersen
			}
			c.LoggerDebug(logger, "Credential passed validation")
			protoCheckPC := tfExtraParms.RequiredSenderMiddleNameCheckPC
			requiredSenderCheckPCs = append(requiredSenderCheckPCs, protoCheckPC)
		}

		if findSenderOption(senderOptions, types.RequireSenderLastNamePersonalInfoSenderOption) {
			srcWallet, found := s.getWallet(msg.Creator)
			if !found {
				c.LoggerDebug(logger, "Couldn't find srcWallet "+msg.Creator)
				return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrWalletNotExists
			}

			c.LoggerDebug(logger, "srcWallet", c.PrettyPrint(srcWallet))
			credential, found := s.getCredential(srcWallet.CredentialID, types.LastNamePersonalInfoCredentialType)
			if !found {
				c.LoggerDebug(logger, "Couldn't find credential "+srcWallet.CredentialID)
				return &types.ValidateTransferPrimeReply{UpdateSourceWallet: false}, types.ErrCredentialNotExists
			}

			// validate
			credentialPC := c.UnprotoizeBPedersenCommit(credential.CredentialPedersenCommit)
			c.LoggerDebug(logger, "requiredSenderCheckPC "+c.PrettyPrint(tfExtraParms.RequiredSenderLastNameCheckPC))
			c.LoggerDebug(logger, "credentialPC "+c.PrettyPrint(credential.CredentialPedersenCommit))
			c.LoggerDebug(logger, "proofPC "+c.PrettyPrint(tfExtraParms.RequiredSenderLastNameProofPC))

			if !c.ValidPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderLastNameCheckPC)) || !c.ValidPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderLastNameProofPC)) {
				c.LoggerDebug(logger, "Last name not supplied")
				return nil, types.ErrInvalidTransfer
			}

			if !c.ValidateSubPedersenCommit(c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderLastNameCheckPC), credentialPC, c.UnprotoizeBPedersenCommit(tfExtraParms.RequiredSenderLastNameProofPC)) {
				if c.Debug {
					c.LoggerError(logger, "failed to validate checkPC - credentialPC - proofPC = 0")
				}
				return nil, types.ErrGenericPedersen
			}
			c.LoggerDebug(logger, "Credential passed validation")
			protoCheckPC := tfExtraParms.RequiredSenderLastNameCheckPC
			requiredSenderCheckPCs = append(requiredSenderCheckPCs, protoCheckPC)
		}
	}

	if dstWallet.AcceptPasswordPedersenCommit != nil && dstWallet.AcceptPasswordPedersenCommit.C != nil {
		c.LoggerDebug(logger, "validating required password")
		// need to validate that the source knew the acceptPassword
		unProtoPC := c.UnprotoizeBPedersenCommit(dstWallet.AcceptPasswordPedersenCommit)
		if !c.ValidateAddPedersenCommit(c.UnprotoizeEncryptablePedersenCommit(totalTransferPrimePC), unProtoPC, c.UnprotoizeBPedersenCommit(tfExtraParms.AcceptPasswordPC)) {
			return nil, types.ErrGenericPedersen
		}
		c.LoggerDebug(logger, "password accepted!")
	}

	if tfExtraParms.MatchFirstNameHashHex != nil || tfExtraParms.MatchMiddleNameHashHex != nil || tfExtraParms.MatchLastNameHashHex != nil {
		var vcs types.EncryptableValidatedCredentials
		unprotoDstWalletValidatedCredentialsVShareBind := c.UnprotoizeVShareBindData(dstWallet.AcceptValidatedCredentialsVShareBind)
		err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoDstWalletValidatedCredentialsVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoDstWalletValidatedCredentialsVShareBind.GetSSIntervalPubKID()), unprotoDstWalletValidatedCredentialsVShareBind, dstWallet.EncAcceptValidatedCredentialsVShare, &vcs)
		if err != nil {
			return nil, err
		}

		if tfExtraParms.MatchFirstNameHashHex != nil {
			// decode hash
			b := tfExtraParms.MatchFirstNameHashHex

			pin, credPC := findPINAndPC(vcs, types.FirstNamePersonalInfoCredentialType)
			if pin == "" {
				return nil, types.ErrCredentialNotExists
			}
			pinInt, ok := big.NewInt(0).SetString(pin, 10)
			if !ok {
				return nil, types.ErrGenericTransaction
			}
			pinPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(b), pinInt)
			if !c.ComparePedersenCommit(pinPC, credPC) {
				c.LoggerError(logger, "failed comparing check "+c.PrettyPrint(pinPC), "stored "+c.PrettyPrint(credPC))
				return nil, status.Error(codes.Unauthenticated, "ErrInvalidCredential")
			}
		}

		if tfExtraParms.MatchMiddleNameHashHex != nil {
			// decode hash
			b := tfExtraParms.MatchMiddleNameHashHex
			if err != nil {
				return nil, err
			}
			pin, credPC := findPINAndPC(vcs, types.MiddleNamePersonalInfoCredentialType)
			if pin == "" {
				return nil, types.ErrCredentialNotExists
			}
			pinInt, ok := big.NewInt(0).SetString(pin, 10)
			if !ok {
				return nil, types.ErrGenericTransaction
			}
			pinPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(b), pinInt)
			if !c.ComparePedersenCommit(pinPC, credPC) {
				c.LoggerError(logger, "failed comparing check "+c.PrettyPrint(pinPC), "stored "+c.PrettyPrint(credPC))
				return nil, status.Error(codes.Unauthenticated, "ErrInvalidCredential")
			}
		}

		if tfExtraParms.MatchLastNameHashHex != nil {
			// decode hash
			b := tfExtraParms.MatchLastNameHashHex

			pin, credPC := findPINAndPC(vcs, types.LastNamePersonalInfoCredentialType)
			if pin == "" {
				return nil, types.ErrCredentialNotExists
			}
			pinInt, ok := big.NewInt(0).SetString(pin, 10)
			if !ok {
				return nil, types.ErrGenericTransaction
			}
			pinPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(b), pinInt)
			if !c.ComparePedersenCommit(pinPC, credPC) {
				c.LoggerError(logger, "failed comparing check "+c.PrettyPrint(pinPC), "stored "+c.PrettyPrint(credPC))
				return nil, status.Error(codes.Unauthenticated, "ErrInvalidCredential")
			}
		}
	}

	// this is where we used to lockCoin...

	sameWallet := false

	if msg.Creator == dstEWalletID.WalletID {
		c.LoggerDebug(logger, "src & dst are the same")
		sameWallet = true
	}

	mustUpdateSrcWallet := true

	protoTotalTransferPrimePC := c.ProtoizeBPedersenCommit(c.UnprotoizeEncryptablePedersenCommit(totalTransferPrimePC))

	// check whether the wallet already supports the new token
	if _, ok := dstWallet.EphemeralWalletAmountCount[token]; !ok {
		// let's add the unsupported token into the wallet
		if dstWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
			dstWallet.EphemeralWalletAmountCount[token] = types.QadenaRealWallet
		} else {
			dstWallet.EphemeralWalletAmountCount[token] = 0
		}

		dstWallet.QueuedWalletAmount[token] = &types.ListWalletAmount{WalletAmounts: []*types.WalletAmount{}}
	}

	// create the WalletAmount that we'll insert "somewhere"
	wa := types.WalletAmount{
		WalletAmountPedersenCommit: protoTotalTransferPrimePC,
		EncWalletAmountVShare:      msg.EncNewDestinationWalletAmountVShare,
		WalletAmountVShareBind:     msg.NewDestinationWalletAmountVShareBind,
		RequiredSenderCheckPC:      requiredSenderCheckPCs,
	}

	// validate the wallet is not "full" and is an ephemeral wallet
	if dstWallet.EphemeralWalletAmountCount[token] == 0 {
		// Nothing pending, so this transfer becomes the head and the wallet's own creation
		// commitment moves to the TAIL of the queue, where the branch below keeps it.
		if _, ok := dstWallet.WalletAmount[token]; ok {
			dstWallet.QueuedWalletAmount[token].WalletAmounts = append(
				dstWallet.QueuedWalletAmount[token].WalletAmounts,
				dstWallet.WalletAmount[token],
			)
		}

		// put the new value so that it comes out first
		dstWallet.WalletAmount[token] = &wa

		if sameWallet {
			mustUpdateSrcWallet = false
		}

	} else {
		// count >= 1, so the queue already holds the wallet's own creation commitment as its LAST
		// entry -- put there by the branch above, when the first transfer displaced it from the
		// head.  It has to stay last.  Transfers are inserted immediately before it, which gives
		// two properties at once:
		//
		//   - receive-funds hands transfers back in the order they arrived, because the head is
		//     always the oldest transfer and the queue runs oldest-to-newest ahead of the
		//     commitment;
		//   - the creation commitment is what remains once every transfer has been collected, so
		//     an ephemeral wallet always holds a commitment and never becomes empty.  It is not
		//     itself receivable -- EphemeralWalletAmountCount counts transfers only -- but it is
		//     spendable, so its value is never out of reach.
		//
		// Appending to the very end instead lets the commitment drift into the middle of the
		// queue, where a receive consumes it and delivers nothing while a real transfer is left
		// behind that receive-funds then refuses.
		//
		// Built as a fresh slice rather than the tempting
		//     append(queued[:len(queued)-1], &wa, queued[len(queued)-1])
		// which writes through the original backing array.  That form happens to be correct, since
		// the trailing element is evaluated as an argument before the append overwrites its slot,
		// but it mutates the slice in place and is a trap for whoever edits it next.
		queued := dstWallet.QueuedWalletAmount[token].WalletAmounts

		if len(queued) == 0 {
			// defensive: with the invariant above this cannot happen, since count >= 1 implies the
			// commitment was displaced into the queue
			dstWallet.QueuedWalletAmount[token].WalletAmounts = []*types.WalletAmount{&wa}
		} else {
			reordered := make([]*types.WalletAmount, 0, len(queued)+1)
			reordered = append(reordered, queued[:len(queued)-1]...)
			reordered = append(reordered, &wa)
			reordered = append(reordered, queued[len(queued)-1])
			dstWallet.QueuedWalletAmount[token].WalletAmounts = reordered
		}
	}

	c.LoggerDebug(logger, "sameWallet::", sameWallet)
	c.LoggerDebug(logger, "mustUpdateSrcWallet::", mustUpdateSrcWallet)

	dstWallet.EphemeralWalletAmountCount[token]++

	c.LoggerDebug(logger, "new dst wallet "+c.PrettyPrint(dstWallet))

	s.setWallet(dstWallet)

	return &types.ValidateTransferPrimeReply{UpdateSourceWallet: mustUpdateSrcWallet}, nil
}

func (s *qadenaServer) ValidateTransferDoublePrime(ctx context.Context, msg *types.MsgReceiveFunds) (*types.ValidateTransferDoublePrimeReply, error) {
	c.LoggerDebug(logger, "validate transfer double prime, update ephemeral wallet")

	unprotoMsgReceiveFundsVShareBind := c.UnprotoizeVShareBindData(msg.ReceiveFundsVShareBind)

	if unprotoMsgReceiveFundsVShareBind.GetJarID() != s.getSharedEnclaveParamsJarID() {
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrGenericEncryption
	}

	c.LoggerDebug(logger, "it's mine, we can decode")

	c.LoggerDebug(logger, "EncAnonymizerBankTransferBlindingFactor ")
	var bankTransferBFProto types.BInt
	unprotoMsgAnonBankTransferBF := c.UnprotoizeVShareBindData(msg.AnonReceiveFundsVShareBind)
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoMsgAnonBankTransferBF, msg.EncAnonReceiveFundsVShare, &bankTransferBFProto)
	if err != nil {
		c.LoggerError(logger, "failed to decrypt EncAnonymizerBankTransferBlindingFactor")
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, err
	}
	bankTransferBF := c.UnprotoizeBInt(&bankTransferBFProto)
	bankTransparentAmount := c.UnprotoizeBInt(msg.TransparentAmount)

	bankPC := c.NewPedersenCommit(bankTransparentAmount, bankTransferBF) // random blinding factor

	c.LoggerDebug(logger, "bankPC "+c.PrettyPrint(bankPC))

	// decrypt the ephemeral wallet ID
	var vShareReceiveFunds types.EncryptableReceiveFunds
	c.LoggerDebug(logger, "EncReceiveFundsVShare ")

	err = c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoMsgReceiveFundsVShareBind, msg.EncReceiveFundsVShare, &vShareReceiveFunds)
	if err != nil {
		return nil, err
	}

	c.LoggerDebug(logger, "EncJarSrcEWalletID ")
	srcEWalletID := vShareReceiveFunds.EphEWalletID

	srcWallet, found := s.getWallet(srcEWalletID.WalletID)
	if !found {
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrWalletNotExists
	}

	c.LoggerDebug(logger, "src wallet ID", srcEWalletID.WalletID)

	dequeue := true
	if srcEWalletID.ExtraParms != nil && srcEWalletID.ExtraParms.Queue == "no-dequeue" {
		c.LoggerDebug(logger, "should not dequeue")
		dequeue = false
	}

	c.LoggerDebug(logger, "EncWalletVShare: ")

	unprotoSrcWalletCreateWalletVShareBind := c.UnprotoizeVShareBindData(srcWallet.CreateWalletVShareBind)
	// decrypt the destination wallet id
	var vShareWallet types.EncryptableCreateWallet

	err = c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoSrcWalletCreateWalletVShareBind, srcWallet.EncCreateWalletVShare, &vShareWallet)
	if err != nil {
		return nil, err
	}

	// we need to double-check that the destination wallet ID matches the ephemeral's destination wallet ID
	dstEWalletID := vShareWallet.DstEWalletID

	sameWallet := false
	if msg.Creator == srcEWalletID.WalletID {
		c.LoggerDebug(logger, "src & dst are the same")
		sameWallet = true
	} else if dstEWalletID.WalletID != msg.Creator {
		c.LoggerError(logger, "Ephemeral's destination wallet ID", dstEWalletID.WalletID, "does not match the transaction's destination wallet ID", msg.Creator)
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrInvalidCreator
	}

	if !sameWallet && !dequeue {
		c.LoggerError(logger, "Must dequeue if receiver is not the same wallet as the eph wallet")
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrGenericTransaction
	}

	token := msg.TokenDenom

	if token == types.AQadenaTokenDenom {
		token = types.QadenaTokenDenom
	}

	// validate the wallet is an ephemeral wallet
	if srcWallet.EphemeralWalletAmountCount[token] == types.QadenaRealWallet {
		c.LoggerError(logger, "the wallet is a real wallet")
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrInvalidWallet
	}

	// validate the ephemeral wallet has something in it
	if srcWallet.EphemeralWalletAmountCount[token] < 1 {
		c.LoggerError(logger, "ephemeral wallet is empty")
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrInvalidWallet
	}

	transferDoublePrimePC := msg.HiddenTransferPC
	transferPrimePC := srcWallet.WalletAmount // FIFO

	if !c.ValidatePedersenCommit(bankPC) || bankPC.A.Cmp(c.BigIntZero) < 0 {
		if c.Debug {
			c.LoggerError(logger, "bankPC is invalid, or bankPC.A < 0")
		}
		return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrGenericPedersen
	}

	unprotoTransferPrimePC := c.UnprotoizeBPedersenCommit(transferPrimePC[token].WalletAmountPedersenCommit)
	c.LoggerDebug(logger, "transferPrimePC "+c.PrettyPrint(unprotoTransferPrimePC))
	unprotoTransferDoublePrimePC := c.UnprotoizeBPedersenCommit(transferDoublePrimePC)
	c.LoggerDebug(logger, "transferDoublePrimePC "+c.PrettyPrint(unprotoTransferDoublePrimePC))

	if sameWallet {
		unprotoNewDestinationPC := c.UnprotoizeBPedersenCommit(msg.NewDestinationPC)
		if c.ValidateSubPedersenCommit(unprotoTransferPrimePC, unprotoTransferDoublePrimePC, unprotoNewDestinationPC) {
			if c.Debug {
				c.LoggerDebug(logger, "validated transferPrimePC - transferDoublePrimePC - newDestinationPC = 0")
			}
		} else {
			if c.Debug {
				c.LoggerError(logger, "failed to validate transferPrimePC - transferDoublePrimePC - bankPC = 0")
			}
			return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrGenericPedersen
		}
	} else {
		if c.ValidateSubPedersenCommit(unprotoTransferPrimePC, unprotoTransferDoublePrimePC, bankPC) {
			if c.Debug {
				c.LoggerDebug(logger, "validated transferPrimePC - transferDoublePrimePC - bankPC = 0")
			}
		} else {
			if c.Debug {
				c.LoggerError(logger, "failed to validate transferPrimePC - transferDoublePrimePC - bankPC = 0")
			}
			return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: false}, types.ErrGenericPedersen
		}
	}

	// this is where we used to lockCoin...

	mustUpdateDstWallet := true
	if dequeue {
		c.LoggerDebug(logger, "dequeue")

		// check if there is still item in the queue, if not delete the WalletAmountPC on QueuedWalletAmountPedersenCommit
		if len(srcWallet.QueuedWalletAmount[token].WalletAmounts) > 0 {
			srcWallet.WalletAmount[token] = srcWallet.QueuedWalletAmount[token].WalletAmounts[0]
			srcWallet.QueuedWalletAmount[token].WalletAmounts = srcWallet.QueuedWalletAmount[token].WalletAmounts[1:]
		} else {
			delete(srcWallet.WalletAmount, token)
		}

		srcWallet.EphemeralWalletAmountCount[token]--

		c.LoggerDebug(logger, "new src wallet"+c.PrettyPrint(srcWallet))

		s.setWallet(srcWallet)

		if sameWallet {
			c.LoggerDebug(logger, "same wallet && dequeue, setting mustUpdateDstWallet to false")
			mustUpdateDstWallet = false
		}
	}

	return &types.ValidateTransferDoublePrimeReply{UpdateDestinationWallet: mustUpdateDstWallet}, nil
}

// reportParty is one side of a report, resolved to whatever descriptor that side actually has.
//
// Exactly one of pi and ci is non-nil.  A wallet contributes decrypted personal info; a whitelisted
// non-wallet contributes an address, its pinned code ID and the governance-recorded reason.  Keeping
// them as distinct fields rather than filling a personal-info struct with invented values is what
// lets a regulator tell a real identity from a contract after decryption.
type reportParty struct {
	pi *types.EncryptablePersonalInfo
	ci *types.EncryptableContractInfo
	// set when ci describes a party with no identity at all rather than a whitelisted one; both use
	// the same descriptor, and this is what the reader's party kind is built from
	addressOnly bool
}

func (p reportParty) kind() types.SuspiciousPartyKind {
	switch {
	case p.addressOnly:
		return types.SuspiciousPartyKind_SUSPICIOUS_PARTY_KIND_ADDRESS_ONLY
	case p.ci != nil:
		return types.SuspiciousPartyKind_SUSPICIOUS_PARTY_KIND_CONTRACT
	default:
		return types.SuspiciousPartyKind_SUSPICIOUS_PARTY_KIND_WALLET
	}
}

// nonce is this party's contribution to the report's amount nonce.
//
// For a wallet that is the credential nonce, as it always was.  For a contract there is no secret to
// draw one from, so the address stands in: public and stable, which is all this needs to be -- its
// job is to make the amount nonce unique per pair, not to hide either party.
func (p reportParty) nonce() string {
	if p.ci != nil {
		return p.ci.Nonce
	}
	return p.pi.Nonce
}

// resolveReportParty produces the descriptor for one side of a report.
//
// contract is non-nil only when the keeper found this address on the scanned-contract whitelist and
// re-verified its pinned code ID; the enclave takes that as given, since it holds no wasm state.
//
// allowAddressOnly permits falling back to naming the party by address when it has no wallet or no
// credential.  Passed true ONLY for the destination of a send from a whitelisted party -- the
// onboarding case, where a treasury funds a key that does not have an identity yet and acquires one
// afterwards.  Everywhere else it is false, so an unidentifiable party still fails the report and
// therefore refuses the transfer.
func (s *qadenaServer) resolveReportParty(walletID string, contract *types.ScannedContractWhitelist, side string, allowAddressOnly bool) (reportParty, error) {
	if contract != nil {
		return reportParty{ci: &types.EncryptableContractInfo{
			Nonce:   contract.Address,
			Address: contract.Address,
			CodeID:  contract.CodeID,
			Reason:  contract.Reason,
		}}, nil
	}

	// Named by address alone: no codeID, no governance reason, because there is no entry behind it.
	addressOnlyParty := reportParty{
		addressOnly: true,
		ci: &types.EncryptableContractInfo{
			Nonce:   walletID,
			Address: walletID,
		},
	}

	wallet, found := s.getWallet(walletID)
	if !found {
		if allowAddressOnly {
			c.LoggerDebug(logger, side+" "+walletID+" has no wallet yet; naming it by address")
			return addressOnlyParty, nil
		}
		c.LoggerError(logger, "couldn't find "+side+" wallet "+walletID)
		return reportParty{}, types.ErrGenericScan
	}

	credential, found := s.getCredential(wallet.CredentialID, types.PersonalInfoCredentialType)
	if !found {
		if allowAddressOnly {
			c.LoggerDebug(logger, side+" "+walletID+" holds no credential yet; naming it by address")
			return addressOnlyParty, nil
		}
		c.LoggerError(logger, "couldn't find "+side+" credential "+wallet.CredentialID)
		return reportParty{}, types.ErrGenericScan
	}

	unprotoCredentialInfoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
	var pi types.EncryptablePersonalInfo
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, credential.EncCredentialInfoVShare, &pi)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt "+side+" credential "+wallet.CredentialID)
		return reportParty{}, types.ErrGenericScan
	}

	c.LoggerDebug(logger, side+" personal info "+c.PrettyPrint(pi))

	return reportParty{pi: &pi}, nil
}

// suspiciousReportSeed is the secret the report encryption derives its ephemeral key and nonce from.
//
// It must be IDENTICAL on every enclave, or the nodes produce different ciphertext and fork -- which
// is the whole point of deriving rather than sampling.  The jar private key qualifies: it lives in
// SharedEnclaveParams and InitEnclave hands it to a joining node's enclave, so every enclave in the
// set holds the same bytes.
//
// The regulator key is deliberately NOT used.  It is intended to be handed to the regulator
// eventually, and a seed that leaves the enclave set would let its holder recompute every ephemeral
// key ever derived.  That grants nothing today -- the regulator can already decrypt these reports --
// but it would tie the secrecy of the derivation to a key that is meant to be exported.
func (s *qadenaServer) suspiciousReportSeed() []byte {
	return []byte(s.getSharedEnclaveParamsJarPrivK())
}

// createSuspiciousTransaction files one report with the regulator.
//
// RETURNS AN ERROR, and every caller must act on it.  It used to return nothing and simply log on
// any missing piece, which meant a transfer that crossed a threshold could be allowed through with
// no report ever filed -- silently, and indistinguishably from one that was reported.  That was
// tolerable only while reports were rare; now that the bank path reports too, and the treasuries
// moved onto the scanned-contract whitelist rather than out of scanning altogether, a report that
// cannot be built has to refuse the transfer instead of vanishing.
//
// srcContract and dstContract come from the keeper: non-nil for a whitelisted non-wallet party, nil
// for an ordinary wallet.  Both nil on the transfer-funds path, which only ever moves value between
// credentialed wallets.
//
// allowAddressOnlyDst permits the destination to be named by address when it has no identity yet.
// True only on the bank path and only when the SOURCE is whitelisted -- a treasury onboarding a
// fresh key.  The source itself is never address-only: it is either a wallet or a listed party, or
// the send was refused before reaching here.
func (s *qadenaServer) createSuspiciousTransaction(ctx context.Context, reason string, jarID string, tf c.TransferFunds, optInReason string, srcContract, dstContract *types.ScannedContractWhitelist, allowAddressOnlyDst bool) error {
	regulatorID, found := s.getJarRegulator(jarID)

	if !found {
		// Reachable only before the enclave has finished InitEnclave, which is what creates the
		// regulator identity in the first place -- so in practice, only in the first few blocks of
		// a brand new chain, before anything can transact.
		c.LoggerError(logger, "couldn't find regulator ID for jar", jarID)
		return types.ErrGenericScan
	}

	regulatorPubKID, _, _, found := s.getIntervalPublicKeyId(regulatorID, types.RegulatorNodeType)
	if !found {
		c.LoggerError(logger, "couldn't find regulator pubkid for regulator ID", regulatorID)
		return types.ErrGenericScan
	}

	regulatorPubK, found := s.getPublicKey(regulatorPubKID, types.CredentialPubKType)
	if !found {
		c.LoggerError(logger, "couldn't find regulator pubk for regulator pubKID", regulatorPubKID)
		return types.ErrGenericScan
	}

	c.LoggerDebug(logger, "regulatorPubK", regulatorPubK)

	// no secret sharing for now, decode the credentials

	src, err := s.resolveReportParty(tf.SourceWalletID, srcContract, "source", false)
	if err != nil {
		return err
	}
	dst, err := s.resolveReportParty(tf.DestinationWalletID, dstContract, "destination", allowAddressOnlyDst)
	if err != nil {
		return err
	}

	var eSuspiciousAmount types.EncryptableESuspiciousAmount
	eSuspiciousAmount.Nonce = src.nonce() + "/" + dst.nonce()
	eSuspiciousAmount.USDCoinAmount = &tf.USDCoinAmount
	eSuspiciousAmount.CoinAmount = &tf.CoinAmount

	// EVERY FIELD BELOW IS ENCRYPTED DETERMINISTICALLY, and that is a consensus requirement rather
	// than a preference.  This report is written into CHAIN state by EnclaveEndBlock, and every
	// validator builds it in its own enclave.  With ecies.Encrypt -- a fresh ephemeral key and a
	// fresh nonce from crypto/rand -- each node produced different bytes for the same report, the
	// app hashes diverged, and the chain forked.  That is not a risk, it happened: a two-validator
	// chain forked at the exact block that filed its first report, and the second validator halted
	// with "wrong Block.Header.AppHash".
	//
	// The encryption is still public-key to the regulator and byte-compatible with ecies.Decrypt --
	// the regulator reads it with their private key alone.  Only the source of the two random
	// values changes.
	//
	// THE CONTEXT MUST BE UNIQUE PER ENCRYPTION.  Reusing one would reuse both the AES key and the
	// GCM nonce, which leaks plaintext and allows tag forgery.  Uniqueness here comes from:
	//   tf.Time   block time, identical on every node, distinct per block
	//   reason    separates the per-send report from the aggregated one in the same transaction
	//   seq       ordinal within the block, so two reports in one block never collide
	//   parties   the source/destination nonces
	//   field tag distinguishes the several fields of one report
	// A block height alone would satisfy none of the last four.
	seed := s.suspiciousReportSeed()
	if len(seed) == 0 {
		c.LoggerError(logger, "no shared enclave secret to derive report encryption from")
		return types.ErrGenericEnclave
	}
	seq := len(s.pendingSuspiciousTransactions) + len(outboxGet[types.SuspiciousTransaction](s, outboxSuspiciousKey))
	baseCtx := fmt.Sprintf("suspicious|%s|%s|%s|%s|%s|%d",
		jarID, regulatorPubKID, tf.Time, reason, eSuspiciousAmount.Nonce, seq)

	encField := func(tag string, v proto.Message) ([]byte, error) {
		return c.ProtoMarshalAndBEncryptDeterministic(regulatorPubK, v, seed, []byte(baseCtx+"|"+tag))
	}

	encAmount, err := encField("amount", &eSuspiciousAmount)
	if err != nil {
		c.LoggerError(logger, "could not encrypt the report amount: "+err.Error())
		return types.ErrGenericEnclave
	}
	encOptIn, err := c.BEncryptDeterministic(regulatorPubK, []byte(optInReason), seed, []byte(baseCtx+"|optin"))
	if err != nil {
		c.LoggerError(logger, "could not encrypt the opt-in reason: "+err.Error())
		return types.ErrGenericEnclave
	}

	var st = types.SuspiciousTransaction{JarID: jarID,
		RegulatorPubKID:             regulatorPubKID,
		Reason:                      reason,
		Time:                        tf.Time,
		SourceKind:                  src.kind(),
		DestinationKind:             dst.kind(),
		EncEAmountRegulatorPubK:     encAmount,
		EncOptInReasonRegulatorPubK: encOptIn,
	}

	// Only the descriptor that side actually has is encrypted into the report; the other stays
	// empty, which is what SourceKind/DestinationKind tell the reader to expect.
	if src.pi != nil {
		if st.EncSourcePersonalInfoRegulatorPubK, err = encField("src.pi", src.pi); err != nil {
			c.LoggerError(logger, "could not encrypt source personal info: "+err.Error())
			return types.ErrGenericEnclave
		}
	} else {
		if st.EncSourceContractInfoRegulatorPubK, err = encField("src.ci", src.ci); err != nil {
			c.LoggerError(logger, "could not encrypt source contract info: "+err.Error())
			return types.ErrGenericEnclave
		}
	}
	if dst.pi != nil {
		if st.EncDestinationPersonalInfoRegulatorPubK, err = encField("dst.pi", dst.pi); err != nil {
			c.LoggerError(logger, "could not encrypt destination personal info: "+err.Error())
			return types.ErrGenericEnclave
		}
	} else {
		if st.EncDestinationContractInfoRegulatorPubK, err = encField("dst.ci", dst.ci); err != nil {
			c.LoggerError(logger, "could not encrypt destination contract info: "+err.Error())
			return types.ErrGenericEnclave
		}
	}

	// PENDING, not committed.  TransactionComplete moves this into the suspicious outbox only if
	// the transaction succeeds -- a report must never outlive the movement of value it describes.
	s.pendingSuspiciousTransactions = append(s.pendingSuspiciousTransactions, st)
	return nil
}

func (s *qadenaServer) ScanTransaction(ctx context.Context, st *types.MsgScanTransactions) (*types.ScanTransactionReply, error) {
	c.LoggerDebug(logger, "scan transaction")

	msg := st.Msg

	exchangerate, err := math.LegacyNewDecFromStr(st.GetExchangerate())
	if err != nil {
		exchangerate = math.LegacyZeroDec()
	}

	unprotoMsgTransferFundsVShareBind := c.UnprotoizeVShareBindData(msg.TransferFundsVShareBind)

	if unprotoMsgTransferFundsVShareBind.GetJarID() != s.getSharedEnclaveParamsJarID() {
		if c.Debug {
			c.LoggerError(logger, "jarID mismatch", unprotoMsgTransferFundsVShareBind.GetJarID(), s.getSharedEnclaveParamsJarID())
			c.LoggerError(logger, unprotoMsgTransferFundsVShareBind.GetValidDecryptAsAddresses())
		}
		return nil, types.ErrGenericScan
	}

	c.LoggerDebug(logger, "exchange rate: "+exchangerate.String())
	c.LoggerDebug(logger, "it's mine, I can decode and scan")

	var vShareTransferFunds types.EncryptableTransferFunds

	c.LoggerDebug(logger, "EncTransferFundsVShare: ")

	err = c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoMsgTransferFundsVShareBind, msg.EncTransferFundsVShare, &vShareTransferFunds)
	if err != nil {
		return nil, err
	}

	etransferPC := vShareTransferFunds.HiddenTransferPC

	// validate transferPC
	transferPC := c.UnprotoizeEncryptablePedersenCommit(etransferPC)

	if !c.ValidatePedersenCommit(transferPC) || transferPC.A.Cmp(c.BigIntZero) < 0 {
		if c.Debug {
			c.LoggerError(logger, "transferPC is invalid, or transferPC.A < 0")
		}
		return nil, types.ErrGenericPedersen
	}

	// check if transferPC commitment is the same as the one in the transaction
	// unprotoize HiddenTransferPC
	unprotoHiddenTransferPC := c.UnprotoizeBPedersenCommit(msg.HiddenTransferPC)

	if !c.ComparePedersenCommit(transferPC, unprotoHiddenTransferPC) {
		if c.Debug {
			c.LoggerError(logger, "transferPC commitment is not the same as the one in the transaction")
		}
		return nil, types.ErrGenericPedersen
	}

	dstEWalletID := vShareTransferFunds.DstEWalletID

	c.LoggerDebug(logger, "ephemeral destination wallet ID "+dstEWalletID.WalletID)

	dstEWallet, found := s.getWallet(dstEWalletID.WalletID)

	if !found {
		c.LoggerError(logger, "Couldn't get the actual wallet")
		return nil, err
	}

	c.LoggerDebug(logger, "Destination EncWalletVShare: ")

	unprotoDstWalletCreateWalletVShareBind := c.UnprotoizeVShareBindData(dstEWallet.CreateWalletVShareBind)
	// decrypt the destination wallet id
	var vShareCreateWallet types.EncryptableCreateWallet

	err = c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoDstWalletCreateWalletVShareBind, dstEWallet.EncCreateWalletVShare, &vShareCreateWallet)
	if err != nil {
		return nil, err
	}

	dstWalletID := vShareCreateWallet.DstEWalletID

	optInReason := vShareTransferFunds.OptInReason

	c.LoggerDebug(logger, "optInReason '"+optInReason+"'")

	bankTransparentAmount := c.UnprotoizeBInt(msg.TransparentAmount)

	bankTransparentAmountUsd := math.LegacyNewDecFromBigInt(bankTransparentAmount).Mul(exchangerate)
	privateTransferAmountUsd := math.LegacyNewDecFromBigInt(transferPC.A).Mul(exchangerate)

	sumUSD := bankTransparentAmountUsd.Add(privateTransferAmountUsd)
	usdCoinAmount := sdk.NewCoin(types.AttoUSDFiatDenom, sumUSD.RoundInt())

	sum := *c.BigIntZero
	sum.Add(transferPC.A, bankTransparentAmount)
	coinAmount := sdk.NewCoin(msg.TokenDenom, math.NewIntFromBigInt(&sum))

	// get the source wallet
	srcWallet, found := s.getWallet(msg.Creator)
	if !found {
		c.LoggerError(logger, "Couldn't get the actual wallet")
		return nil, err
	}

	c.LoggerDebug(logger, "Source EncWalletVShare: ")

	unprotoSrcWalletCreateWalletVShareBind := c.UnprotoizeVShareBindData(srcWallet.CreateWalletVShareBind)
	// decrypt the destination wallet id
	var srcVShareCreateWallet types.EncryptableCreateWallet

	err = c.VShareBDecryptAndProtoUnmarshal(s.getSharedEnclaveParamsJarPrivK(), s.getSharedEnclaveParamsJarPubK(), unprotoSrcWalletCreateWalletVShareBind, srcWallet.EncCreateWalletVShare, &srcVShareCreateWallet)
	if err != nil {
		return nil, err
	}

	srcWalletID := srcVShareCreateWallet.DstEWalletID.WalletID

	tf := c.TransferFunds{Time: st.Timestamp, SourceWalletID: srcWalletID, DestinationWalletID: dstWalletID.WalletID, USDCoinAmount: usdCoinAmount, CoinAmount: coinAmount}

	c.LoggerDebug(logger, "time "+tf.Time.String()+" src "+tf.SourceWalletID+" dst "+tf.DestinationWalletID+" amount "+tf.CoinAmount.String())

	// 1.  Work out which jurisdiction's reporting limit applies to this sender.
	policy := c.SuspiciousPolicyFromParams(st.Params)

	countries, err := s.senderJurisdictions(srcWalletID)
	if err != nil {
		c.LoggerError(logger, "couldn't resolve sender jurisdictions "+err.Error())
		return nil, err
	}

	if len(countries) == 0 && !policy.AllowTransferWithoutEKYC {
		// No eKYC means no jurisdiction, and no jurisdiction means no reporting limit to apply.
		// Letting the transfer through under a default limit would make "hold no credential" the
		// cheapest way to pick your own threshold, so the transfer is refused instead.
		c.LoggerError(logger, "refusing transfer from "+srcWalletID+": no residency or citizenship on record")
		return nil, types.ErrNoEKYCForTransfer
	}

	defaultThreshold, ok := math.NewIntFromString(st.DefaultThresholdAttoUSD)
	if !ok || defaultThreshold.IsNil() || !defaultThreshold.IsPositive() {
		// The keeper resolves this through the pricefeed and fails closed if it cannot, so an
		// unusable value here means the two sides disagree about the message -- not something to
		// paper over with a guess, since every guess is either "report everything" or "report
		// nothing".
		c.LoggerError(logger, "unusable default threshold from keeper: "+st.DefaultThresholdAttoUSD)
		return nil, types.ErrGenericScan
	}

	threshold := sdk.NewCoin(types.AttoUSDFiatDenom, c.SelectThreshold(countries, st.CountryThresholds, defaultThreshold))

	c.LoggerDebug(logger, "sender "+srcWalletID+" jurisdictions "+strings.Join(countries, ",")+
		" threshold "+threshold.String()+" window "+policy.Window.String())

	// 2a.  A single transfer at or above the limit.  Checked BEFORE the transfer is recorded, so a
	// refused transfer does not enter the window.
	if tf.USDCoinAmount.IsGTE(threshold) {
		c.LoggerDebug(logger, "suspicious individual transaction "+tf.USDCoinAmount.String()+" "+tf.CoinAmount.String()+" "+tf.SourceWalletID+" "+tf.DestinationWalletID)
		if optInReason == "" && policy.BlockTransferWithoutOptInReason {
			// The chain has chosen refusal over reporting.  Nothing is filed, so the regulator
			// learns nothing about this attempt -- which is the cost of this setting.
			return nil, types.ErrGenericScan
		}
		// Both parties are credentialed wallets on this path -- transfer-funds moves value between
		// qadena wallets and nothing else -- so neither side takes a contract descriptor.
		if err := s.createSuspiciousTransaction(ctx, "Transaction value >= reporting threshold", unprotoMsgTransferFundsVShareBind.GetJarID(), tf, c.OptInReasonOrDefault(optInReason), nil, nil, false); err != nil {
			// Refuse rather than proceed unreported.  This used to be unreachable by construction:
			// the function logged and returned, so a transfer whose report could not be built was
			// allowed through and the regulator simply never heard about it.
			return nil, err
		}
		// Returning here means the transfer is NOT appended to the window, and that is deliberate:
		// its whole value has just been reported, so leaving it in would let the aggregate rule
		// report the same money a second time.  Earlier sub-threshold transfers to this
		// destination stay exactly where they are -- they have not been reported, so they must
		// still be able to accumulate.  The invariant across both rules is: what goes into a
		// report leaves the window, what does not, stays.
		return &types.ScanTransactionReply{Status: true}, nil
	}

	// 2b.  The rolling-window total to a single destination.
	//
	// Expiry is applied lazily, here, on the one source being scanned: bounded work per transfer,
	// where a sweep across every wallet would not be.  A dormant wallet keeps its stale rows until
	// it next sends, which costs a little storage and changes no verdict -- they are pruned before
	// anything is summed.
	history := s.getScanTransferHistory(srcWalletID)
	cutoff := st.Timestamp.Add(-policy.Window).Unix()
	history.Transfers = c.PruneExpired(history.Transfers, cutoff)

	history.Transfers = append(history.Transfers, &types.EncryptableScanTransfer{
		UnixTime:            st.Timestamp.Unix(),
		DestinationWalletID: tf.DestinationWalletID,
		USDCoinAmount:       tf.USDCoinAmount,
		CoinAmount:          tf.CoinAmount,
	})

	c.LoggerDebug(logger, "src wallet "+srcWalletID+" window holds "+strconv.Itoa(len(history.Transfers))+" transfers")

	// Ordered by destination, not a map range: report order decides the IDs
	// AppendSuspiciousTransaction hands out at EndBlock, so a per-process iteration order would
	// fork the chain the first time two destinations cross in one scan.  See DestinationTotal.
	for _, agg := range c.AggregateByDestination(history.Transfers) {
		dstWalletID := agg.DestinationWalletID
		v := agg.USDCoinAmount
		c.LoggerDebug(logger, "aggregate total "+dstWalletID+" "+v.String())
		if v.IsGTE(threshold) {
			c.LoggerDebug(logger, "suspicious aggregate total "+tf.SourceWalletID+" "+dstWalletID+" "+v.String())
			// USD is the aggregate; the token amount is this transfer's, because a window can hold
			// several denominations and there is no meaningful sum across them
			aggregated := c.TransferFunds{Time: st.Timestamp, SourceWalletID: tf.SourceWalletID, DestinationWalletID: dstWalletID, USDCoinAmount: v, CoinAmount: tf.CoinAmount}

			if optInReason == "" && policy.BlockTransferWithoutOptInReason {
				// Refused.  Returning here without writing leaves the window untouched, and the
				// rolled-back transaction would discard the write in any case.
				return nil, types.ErrGenericScan
			}
			// Filed BEFORE the window is reset, so a report that cannot be built leaves the window
			// intact.  Resetting first and then failing would drop the accumulated history on the
			// floor while refusing the transfer -- the money would have to accumulate all over
			// again, and the totals a regulator eventually sees would understate what happened.
			if err := s.createSuspiciousTransaction(ctx, "Total transaction value >= reporting threshold", unprotoMsgTransferFundsVShareBind.GetJarID(), aggregated, c.OptInReasonOrDefault(optInReason), nil, nil, false); err != nil {
				return nil, err
			}

			// Reported, so the pair starts over -- the whole accumulated total went into the
			// report, and without the reset every later transfer to the same destination would
			// report that same money again.
			history.Transfers = c.DropDestination(history.Transfers, dstWalletID)
		}
	}

	s.setScanTransferHistory(srcWalletID, history)

	return &types.ScanTransactionReply{Status: true}, nil
}

// senderJurisdictions returns the countries the sender belongs to, by way of their credential.
//
// An empty result means "no eKYC data", which the caller decides what to do with; an error means
// the lookup itself failed and the two must not be conflated -- one is a policy question, the other
// is a fault.  Only the enclave can do this at all: residency and citizenship are sealed inside the
// credential's VShare, which is why the keeper sends thresholds for every jurisdiction rather than
// resolving the sender's own.
func (s *qadenaServer) senderJurisdictions(srcWalletID string) ([]string, error) {
	srcWallet, found := s.getWallet(srcWalletID)
	if !found {
		return nil, types.ErrWalletNotExists
	}

	if srcWallet.CredentialID == "" {
		return nil, nil
	}

	srcCredential, found := s.getCredential(srcWallet.CredentialID, types.PersonalInfoCredentialType)
	if !found {
		return nil, nil
	}

	unprotoBind := c.UnprotoizeVShareBindData(srcCredential.CredentialInfoVShareBind)
	var srcPI types.EncryptablePersonalInfo
	err := c.VShareBDecryptAndProtoUnmarshal(
		s.getSSPrivK(unprotoBind.GetSSIntervalPubKID()),
		s.getPubK(unprotoBind.GetSSIntervalPubKID()),
		unprotoBind, srcCredential.EncCredentialInfoVShare, &srcPI)
	if err != nil {
		return nil, err
	}

	return c.CountriesFromDetails(srcPI.Details), nil
}

func (s *qadenaServer) GetStoreHash(ctx context.Context, gsh *types.MsgGetStoreHash) (*types.GetStoreHashReply, error) {
	c.LoggerDebug(logger, "GetStoreHash")

	// READ-ONLY, deliberately.  This used to call s.commitCache() first, which promoted a
	// partially executed transaction's writes into the store -- a write side effect on a read
	// RPC, reachable from enclaveSynchronizeStores at startup.  It was also unnecessary: every
	// caller invokes this either before any transaction has executed (BeginBlock) or after every
	// transaction has completed (EndBlock's drain path), so all hash-relevant writes are already
	// promoted by TransactionComplete.  Hashing ServerCtx without flushing observes exactly the
	// committed-plus-completed state both sides mean to compare.

	storeHashes := []*types.StoreHash{}

	// THIS ORDER IS LOAD-BEARING, because enclaveSynchronizeStores pushes the out-of-sync stores in
	// exactly the order they come back here.
	//
	// SetProtectKey and SetRecoverKey decrypt a vshare before writing, which needs an ACTIVE
	// EnclaveIdentity for this enclave's own uniqueID.  With EnclaveIdentity last, a node seeding
	// every store at once -- a state-synced or wiped enclave, the only case where they are all
	// out-of-sync together -- pushed ProtectKey and RecoverKey while the identity table was still
	// empty.  Every row was refused with
	//
	//     But couldn't find an active enclave identity for uniqueID: <id>
	//     error returned by SetProtectKey ... code 1110: Encryption generic error
	//
	// and the enclave came up permanently short of those rows plus the private indexes their
	// handlers build as a side effect.  That was silent until the push started checking errors; it
	// is now a halt, which is how it was found.
	//
	// EnclaveIdentity and IntervalPublicKeyID therefore come FIRST: identity to authenticate with,
	// interval keys to find a peer, before anything that needs either.
	keys := storeHashKeys

	// A caller may ask for a SUBSET.  Hashing a prefix is a full scan of it, and the dsvs module
	// handles exactly one (AuthorizedSignatory, 167 rows today) -- it was triggering a scan of all
	// ten, ~16,000 rows, to obtain that one and discarding the rest with "Ignoring key=...".
	//
	// Empty means all, so every existing caller is unaffected.  The FILTER RUNS OVER `keys` ABOVE
	// rather than over the request, so the reply keeps the canonical order whatever order it was
	// asked in -- see the note above about why that order is load-bearing for seeding.
	want := map[string]bool{}
	for _, k := range gsh.GetKeys() {
		want[k] = true
	}

	for _, k := range keys {
		if len(want) > 0 && !want[k] {
			continue
		}
		var sh types.StoreHash
		h := c.StoreHashByStoreKey(s.ServerCtx, s.StoreKey, k)
		c.LoggerDebug(logger, "key "+k+" hash "+h)
		sh.Key = k
		sh.Hash = h

		// SHADOW ONLY.  The hash returned above is the scan, and it stays the answer; this just
		// reports whether the incrementally maintained accumulator agrees with it.  Running the two
		// side by side is the whole point: an accumulator is a maintained invariant, and the two
		// previous maintained invariants in this codebase -- the iavl fast index and the
		// CredentialPCXY index -- both drifted from the data they described without saying so.
		// Here, drift is a log line rather than a wrong answer.

		storeHashes = append(storeHashes, &sh)
	}

	return &types.GetStoreHashReply{Hashes: storeHashes}, nil
}

func (s *qadenaServer) TransactionComplete(ctx context.Context, tc *types.MsgTransactionComplete) (*types.TransactionCompleteReply, error) {
	c.LoggerDebug(logger, "transaction complete "+strconv.FormatBool(tc.Success))

	if tc.Success {
		// Reports become real at exactly the moment the transaction's state writes do: appended
		// into the outbox THROUGH the cache, then promoted together with them by the write below.
		// A report can never describe value that did not move.
		if len(s.pendingSuspiciousTransactions) > 0 {
			c.LoggerDebug(logger, "committing "+strconv.Itoa(len(s.pendingSuspiciousTransactions))+" suspicious transaction(s)")
			outboxAppend(s, outboxSuspiciousKey, s.pendingSuspiciousTransactions...)
		}
		c.LoggerDebug(logger, "CacheCtx.Write")
		s.CacheCtxWrite()
	} else {
		c.LoggerDebug(logger, "Rollback CacheContext")
		s.CacheCtx, s.CacheCtxWrite = s.ServerCtx.CacheContext()
		if len(s.pendingSuspiciousTransactions) > 0 {
			c.LoggerDebug(logger, "discarding "+strconv.Itoa(len(s.pendingSuspiciousTransactions))+" suspicious transaction(s) from a failed transaction")
		}
	}

	// Cleared on BOTH paths.  PostHandle calls this for every non-simulate, non-CheckTx delivery, so
	// leaving a stale entry here would attach it to whichever transaction happened to run next.
	s.pendingSuspiciousTransactions = nil

	return &types.TransactionCompleteReply{Status: true}, nil
}

func (s *qadenaServer) commitCache() {
	c.LoggerDebug(logger, "commitCache")

	if s.CacheCtxWrite != nil {
		s.CacheCtxWrite()
	}
}

// EndBlock is the enclave's per-block durable commit -- the PREPARE of the two-phase commit with
// the chain.  It stamps the chain height into the version it commits (so the version is
// self-describing and rollback can find it) and indexes height->version in qmeta/.  The chain
// halts on any error returned here (haltOnEnclaveFailure): an enclave that cannot commit must
// stop the node, not let it run ahead on state that was never persisted.
func (s *qadenaServer) EndBlock(ctx context.Context, tc *types.MsgEndBlock) (*types.EndBlockReply, error) {
	if tc.Height == 0 {
		// A chain binary from before height bookkeeping sends the zero value.  Committing would
		// stamp PreparedHeight=0 into every version forever, quietly disabling rollback; refuse
		// instead, which halts the node with a message that names the actual problem.
		return nil, fmt.Errorf("EndBlock carried no height: the chain binary predates enclave height bookkeeping; upgrade qadenad and qadenad_enclave together")
	}

	prepared := s.getPreparedHeight()
	if prepared != 0 && tc.Height <= prepared {
		// A replayed or out-of-order EndBlock.  Committing it would map two different heights to
		// one version (or rewind the stamp without rewinding the tree), corrupting the index that
		// rollback depends on.  prepared==0 is exempt: a fresh enclave's first EndBlock may
		// arrive at any height (a node seeded mid-chain by sync-enclave).
		return nil, fmt.Errorf("EndBlock height %d is not beyond prepared height %d: refusing to commit a replayed or out-of-order block", tc.Height, prepared)
	}

	// Establish or rebuild any store accumulator that needs it, BEFORE the commit below, so these
	// writes land in the same version as the block's own.  Doing it here rather than on the next
	// incidental write is what gives the quiet stores coverage at all.
	s.maintainAccumulators()

	// The every-Nth-block honesty audit: recompute from the block-end data, halt on mismatch.
	// After maintain (so establishment precedes it) and before capture/commit, so what it audits
	// is exactly what this block ships and commits.
	if err := s.auditAccumulators(tc.Height); err != nil {
		return nil, err
	}

	// Capture the accumulators THIS BLOCK COMMITS -- after the maintain pass, before the commit
	// below, so the values are exactly the block-end state the chain's own maintain pass (which
	// runs just before this rpc) describes on its side.  Riding the reply gives per-block
	// content-agreement checking for ~330 bytes in an rpc that already happens.  Backlog item 44.
	blockAccumulators := s.collectAccumulatorEntries()

	// the stamp goes through the cache so it lands in the same version as the block's writes
	s.setPreparedHeight(tc.Height)
	s.commitCache()

	cms, ok := s.ServerCtx.MultiStore().(storetypes.CommitMultiStore)
	if !ok {
		// pre-height-bookkeeping code logged this and returned success, which committed nothing
		// while telling the chain everything was fine -- the exact silent divergence this whole
		// mechanism exists to prevent
		return nil, fmt.Errorf("enclave multistore is not a CommitMultiStore; cannot commit block %d", tc.Height)
	}

	lastCommitID := cms.LastCommitID()
	commitID := cms.Commit()
	s.setHeightVersion(tc.Height, commitID.Version)

	// prune the height->version index one interval tighter than the version window, so every
	// surviving entry is guaranteed to point at a version pruning has not yet taken
	if cutoff := hvPruneCutoff(tc.Height); cutoff > 0 {
		s.deleteHeightIndexBelow(cutoff)
	}

	if string(commitID.Hash) != string(lastCommitID.Hash) {
		c.LoggerDebug(logger, "has changed")
		c.LoggerDebug(logger, "LastCommitID "+c.PrettyPrint(lastCommitID))
		c.LoggerDebug(logger, "CommitID "+c.PrettyPrint(commitID))

		keys := []string{types.WalletKeyPrefix, types.CredentialKeyPrefix, types.JarRegulatorKeyPrefix, types.PublicKeyKeyPrefix, types.IntervalPublicKeyIDKeyPrefix, types.ProtectKeyKeyPrefix, types.RecoverKeyKeyPrefix}

		for _, k := range keys {
			h := c.StoreHashByStoreKey(s.ServerCtx, s.StoreKey, k)
			c.LoggerDebug(logger, "key="+k+" hash="+c.DisplayHash(h))
		}
	}

	return &types.EndBlockReply{PreparedHeight: tc.Height, Version: commitID.Version, Accumulators: blockAccumulators}, nil
}

func setupConfig() {
	// set the address prefixes
	config := sdk.GetConfig()
	cmdcfg.SetBech32Prefixes(config)
	// TODO fix
	// if err := cmdcfg.EnableObservability(); err != nil {
	// 	panic(err)
	// }
	cmdcfg.SetBip44CoinType(config)
	config.Seal()
}

// Panic recovery interceptor
func panicRecoveryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			c.LoggerError(logger, "Recovered from panic in gRPC call", r)
			err = status.Errorf(status.Code(err), "internal server error")
		}
	}()
	return handler(ctx, req)
}

func overwriteFlagDefaults(c *cobra.Command, defaults map[string]string) {
	set := func(s *pflag.FlagSet, key, val string) {
		if f := s.Lookup(key); f != nil {
			f.DefValue = val
			_ = f.Value.Set(val)
		}
	}
	for key, val := range defaults {
		set(c.Flags(), key, val)
		set(c.PersistentFlags(), key, val)
	}
	for _, c := range c.Commands() {
		overwriteFlagDefaults(c, defaults)
	}
}

func main() {
	port := flag.Int("port", 50051, "The server port")
	realEnclave := flag.Bool("realenclave", false, "Run in real enclave")
	homePath := flag.String("home", "", "Home directory")
	chainID := flag.String("chain-id", "", "Chain ID (e.g. qadena_1000-1)")

	querySignerID := flag.Bool("signer-id", false, "Query signer ID")
	queryUniqueID := flag.Bool("unique-id", false, "Query unique ID")
	queryVersion := flag.Bool("version", false, "Query version")
	logLevel := flag.String("log-level", "info", "Log level (debug or info)")

	testRemoteReportLocally := flag.Bool("test-remote-report-locally", false, "Test SGX remote report, but locally.")
	testRemoteReportHex := flag.String("test-remote-report-hex", "", "Test SGX remote report hex.")

	enclaveUpgradeModeArg := flag.Bool("upgrade-mode", false, "Enclave upgrade mode")
	upgradeFromEnclave := flag.String("upgrade-from-enclave-unique-id", "", "Unique ID of old enclave running on this node")
	// THE CHAIN'S OWN PRUNING WINDOW, passed in at startup by run_enclave.sh /
	// run_realenclave.sh, which read it straight out of the same config/app.toml the chain
	// reads.  The enclave must retain AT LEAST what the chain does: if it kept less, a rollback
	// the chain accepted would fail on the enclave and leave the two at different heights --
	// the one divergence nothing repairs in place.  Same flag names as the chain's, so there is
	// no second vocabulary to learn.
	//
	// A FLAG rather than an RPC because of ordering: the enclave starts BEFORE qadenad and must
	// have its retention set before LoadLatestVersion, so there is no window in which it runs
	// on a guess.
	pruningStrategy := flag.String("pruning", "default", "pruning strategy (default|nothing|everything|custom) -- must match the chain's")
	pruningKeepRecent := flag.Uint64("pruning-keep-recent", 0, "versions to keep when --pruning=custom")
	pruningInterval := flag.Uint64("pruning-interval", 0, "prune every N blocks when --pruning=custom")

	// A STARTUP FLAG rather than an RPC, deliberately.  The node must already be stopped to add it,
	// which makes the act unambiguous, and it adds no callable surface: nothing running can trigger
	// a reset, locally or otherwise.
	//
	// Not debug-gated, unlike ExportPrivateState, because the risk is a different class entirely.
	// That handler EMITS key material -- PioneerPrivK, JarPrivK, SealedTableSharedSecret -- as
	// plaintext to any local caller, an exfiltration route with no cruder equivalent.  This one only
	// deletes, and an operator can already do worse by hand with `rm -rf enclave_data/`, which takes
	// the secrets DB and the height index with it.  A supported reset that clears exactly the right
	// tables and leaves the markers consistent is the safer option, not the riskier one.
	//
	// Nor is what it clears unique to this node: every correct enclave holds the same logical
	// private state, so a reset is recoverable from any peer through the private-state transfer.
	// That is the opposite of key material, which is why this is not gated the same way.
	resetPrivateState := flag.Bool("reset-private-state", false,
		"clear the enclave's PRIVATE tables (AML window, credential hash index and aliases, sub-wallet and recovery maps) and exit, so the node re-fetches them from a peer on next start")

	flag.Parse()

	// configure logging level (defaults to info when flag omitted)
	c.SetLogLevel(*logLevel)

	enclaveUpgradeMode = *enclaveUpgradeModeArg

	if *realEnclave {
		selfReport, err := enclave.GetSelfReport()
		if err != nil {
			c.LoggerError(logger, "couldn't get self report "+err.Error())
			return
		}
		uniqueID = hex.EncodeToString(selfReport.UniqueID)
		signerID = hex.EncodeToString(selfReport.SignerID)
	}

	if *querySignerID {
		fmt.Println(signerID)
		os.Exit(0)
	}

	if *queryUniqueID {
		fmt.Println(uniqueID)
		os.Exit(0)
	}

	if *queryVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *upgradeFromEnclave != "" {
		logger = c.NewTMLogger("enclave-new-" + uniqueID)
	} else if enclaveUpgradeMode {
		logger = c.NewTMLogger("enclave-old-" + uniqueID)
	} else {
		logger = c.NewTMLogger("enclave")
	}

	c.LoggerInfo(logger, "Enclave starting", version, signerID, uniqueID)

	// TELL THE GARBAGE COLLECTOR HOW MUCH MEMORY IT ACTUALLY HAS.
	//
	// enclave.json fixes the heap at heapSize MB and the enclave CANNOT grow past it -- an
	// allocation that does not fit is a fatal error, not a request to the OS.  Go's collector knows
	// nothing about that: by default it paces off GOGC, letting the heap roughly double over live
	// data before collecting, on the assumption that more memory is always available.
	//
	// It is not, and a node died of it: 487MB of mostly-uncollected garbage, 24 goroutines and a
	// few hundred small records live, then one 64MB argon2 buffer that had nowhere to go --
	//
	//     runtime: out of memory: cannot allocate 67108864-byte block (510984192 in use)
	//     fatal error: out of memory
	//
	// A soft limit fixes the pacing: as the heap approaches it the collector runs harder rather
	// than waiting for a ratio that will never be reached in time.  Set below the enclave heap so
	// there is room for the runtime's own overhead and for a large transient to land.
	//
	// setMemoryLimitFromHeapSize keeps this in step with enclave.json rather than restating the
	// number here, because two places holding the same constant is how they drift.
	setMemoryLimitFromHeapSize()

	// A dead enclave now HALTS the node rather than forking the chain (haltOnEnclaveFailure in
	// x/qadena/keeper/enclave_grpc_client.go), so running out of memory costs availability instead
	// of correctness -- which is why it is worth watching the heap BEFORE it runs out.
	// Cheap: one line every reportMemStatsInterval, no allocation beyond the ReadMemStats struct.
	go reportMemStats()

	// DEBUG BUILDS ONLY.  A heap profile is a channel out of the enclave, and an enclave whose
	// memory can be dumped to the host filesystem on request is not an enclave -- the entire
	// property it provides is that the host cannot see inside it.  A pprof profile carries
	// allocation sites and sizes rather than key material, but the enclave holds every private key
	// on the node, and "this particular dump only leaks structure" is not a line worth defending
	// once the mechanism exists.  Whoever can signal the process chooses when it writes.
	//
	// So it is wired only when NOT running as a real enclave, which is the same flag every runtime
	// script already branches on: run_realenclave.sh passes --realenclave, run_enclave.sh does not.
	//
	// KNOWN GAP, accepted deliberately.  This is a runtime gate, not a compile-time one:
	// build_enclave.sh builds both variants from identical source with no build tag (only ego-go vs
	// go), so the profiling code is still PRESENT in the signed SGX binary and merely unreachable
	// through the flag.  Anyone able to start the process could `ego run` that same signed binary
	// without --realenclave -- same measurement -- and dump the heap.  Closing it properly means
	// `//go:build !sgxrelease` here and `-tags sgxrelease` on the SGX build line, so the code is
	// absent from the binary and the measurement itself attests to that.  Not done: it changes the
	// enclave measurement and therefore needs an upgrade.
	//
	// reportMemStats above is deliberately NOT gated.  It emits aggregate counters -- heapAlloc,
	// heapSys, numGC -- which reveal nothing about what is in memory, and losing them in production
	// is what made the out-of-memory that forked the chain take a crash dump and four discarded
	// hypotheses to diagnose.  Totals in production, breakdowns only in debug.
	if *realEnclave {
		c.LoggerInfo(logger, "real enclave: heap profiling disabled (SIGUSR1 ignored)")
	} else {
		go dumpHeapProfileOnSignal(*homePath)
	}

	c.LoggerDebug(logger, "port "+strconv.Itoa(*port))
	c.LoggerDebug(logger, "RealEnclave "+strconv.FormatBool(*realEnclave))
	c.LoggerDebug(logger, "homePath "+*homePath)
	c.LoggerDebug(logger, "chainID "+*chainID)

	c.LoggerDebug(logger, "signerID "+signerID)
	c.LoggerDebug(logger, "uniqueID "+uniqueID)

	setupConfig()
	cmdcfg.RegisterDenoms()

	// set things up so that it looks like we're running a CLI command (for now!)
	RootCmd = &cobra.Command{}

	legacyAmino := amino.NewLegacyAmino()
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	marshaler := amino.NewProtoCodec(interfaceRegistry)
	txConfig := authtx.NewTxConfig(marshaler, authtx.DefaultSignModes)
	enccodec.RegisterInterfaces(interfaceRegistry)

	authtypes.RegisterInterfaces(interfaceRegistry)

	types.RegisterInterfaces(interfaceRegistry)

	if cmdcfg.QadenaUsesEthSecP256k1 {
		c.LoggerInfo(logger, "Using EthSecP256k1")
		evmcryptocodec.RegisterInterfaces(interfaceRegistry)
		evmeip712.RegisterInterfaces(interfaceRegistry)

		overwriteFlagDefaults(RootCmd, map[string]string{
			flags.FlagKeyType: string(evmhd.EthSecp256k1.Name()),
		})

		evmcryptocodec.RegisterCrypto(legacyAmino)
	} else {
		enccodec.RegisterLegacyAminoCodec(legacyAmino)
	}

	clientCtx = client.Context{}.
		WithCodec(marshaler).
		WithInterfaceRegistry(interfaceRegistry).
		WithTxConfig(txConfig).
		WithLegacyAmino(legacyAmino).
		WithInput(os.Stdin).
		WithAccountRetriever(authtypes.AccountRetriever{}).
		WithBroadcastMode(qadenaflags.BroadcastSync).
		WithHomeDir("NO-DEFAULT-HOME").
		WithKeyringOptions(evmhd.EthSecp256k1Option()). // COSMOS EVM
		WithLedgerHasProtobuf(true).                    // COSMOS EVM
		WithViper(EnvPrefix)

	kb := keyring.NewInMemory(clientCtx.Codec, evmhd.EthSecp256k1Option())

	flags.AddTxFlagsToCmd(RootCmd)

	RootCmd.Flags().Set(flags.FlagChainID, *chainID)

	var err error

	clientCtx, err = client.ReadPersistentCommandFlags(clientCtx, RootCmd.Flags())
	if err != nil {
		c.LoggerError(logger, "couldn't read persistent command flags "+err.Error())
		return
	}

	clientCtx.SkipConfirm = true

	//	c.LoggerDebug(logger, "clientCtx " + c.PrettyPrint(clientCtx))
	clientCtx = clientCtx.WithKeyring(kb)

	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	//	memStoreKey := storetypes.NewMemoryStoreKey(types.MemStoreKey)

	//	db := tmdb.NewMemDB()

	// create enclave_config directory if it doesn't exist already
	if _, err := os.Stat(*homePath + "/enclave_config"); os.IsNotExist(err) {
		err = os.Mkdir(*homePath+"/enclave_config", 0755)
		if err != nil {
			c.LoggerError(logger, "Error creating enclave_config directory")
			return
		}
	}

	var db *tmdb.GoLevelDB
	var secretsDB *tmdb.GoLevelDB

	if *upgradeFromEnclave != "" || enclaveUpgradeMode {
		var opts tmdbopt.Options
		opts.ReadOnly = true
		db, err = tmdb.NewGoLevelDBWithOpts("enclave", *homePath+"/enclave_data", &opts)
		if err != nil {
			c.LoggerError(logger, "Error creating read-only GoLevelDB", err)
			return
		}
		var sopts tmdbopt.Options
		sopts.ReadOnly = true
		// ErrorIfMissing stays false: an upgrade from a pre-secrets-DB node has no
		// enclave_secrets yet, and the upgrade path only ferries params anyway
		secretsDB, err = tmdb.NewGoLevelDBWithOpts("secrets", *homePath+"/enclave_secrets", &sopts)
		if err != nil {
			c.LoggerError(logger, "Error creating read-only secrets GoLevelDB", err)
			return
		}
	} else {
		db, err = tmdb.NewGoLevelDB("enclave", *homePath+"/enclave_data", nil)
		if err != nil {
			c.LoggerError(logger, "Error creating GoLevelDB")
			return
		}
		secretsDB, err = tmdb.NewGoLevelDB("secrets", *homePath+"/enclave_secrets", nil)
		if err != nil {
			c.LoggerError(logger, "Error creating secrets GoLevelDB")
			return
		}
	}

	stateStore := store.NewCommitMultiStore(db, cosmossdkiolog.NewNopLogger(), storemetrics.NewNoOpMetrics())

	// BOUND THE IAVL NODE CACHE.  The SDK default is 500,000 NODES -- a count, with no byte limit --
	// chosen for a full node with gigabytes of RAM.  This is an enclave with a fixed heap, and the
	// difference is not academic:
	//
	//   a cached node costs 240B fixed (160B struct: five slice headers and three pointers; 32B
	//   hash; ~48B key) plus its sealed value, so 500,000 of them is 162MB at 100B values, 353MB at
	//   500B, and 591MB at 1KB
	//
	// The store grows about 1MB per regression run -- measured at 0.92MB/run over 172 runs on one
	// node and 1.10MB/run over 10 here -- which puts cache saturation somewhere around run 155-206.
	// A node whose enclave ran out of memory did so at run ~172, with iavl.(*Node).clone visibly
	// growing in its heap profile.
	//
	// TWO REASONS THE DEFAULT IS ESPECIALLY WRONG HERE.
	//
	// Cached nodes are LIVE, so debug.SetMemoryLimit above cannot rescue this: the collector is not
	// permitted to drop them and would simply thrash against a limit it cannot meet.  A bigger heap
	// buys runs, not safety.
	//
	// And the cache earns nothing at this size, because GetStoreHash iterates all nine prefixes on
	// nearly every state-changing block.  A full scan walks an LRU end to end and evicts it
	// wholesale, so a large cache is pure cost with no hit-rate benefit -- it is tuned for random
	// access, and this workload is dominated by sequential ones.
	//
	// What a cache IS worth here is the handful of wallets, credentials and history rows a single
	// block touches repeatedly.  That working set is thousands of nodes, not hundreds of thousands.
	// 20,000 covers it with room to spare and caps this contribution at roughly 9-25MB.
	stateStore.SetIAVLCacheSize(iavlCacheNodes)

	// EXPLICIT retention, matching the chain's pruning "default" window (362,880 versions).
	// Before this the enclave inherited PruningNothing -- every version ever committed was
	// retained, which is the only reason rollback worked at all, and also why enclave_data grew
	// without bound.  Retention is now a decision: the enclave can follow any rollback the chain
	// itself can perform, and nothing older survives to bloat the store.  The height->version
	// index is pruned in step at EndBlock (see enclaveRetainVersions there), slightly tighter
	// than the version window so an indexed height always maps to a live version.
	pruningOpts, perr := enclavePruningOptions(*pruningStrategy, *pruningKeepRecent, *pruningInterval)
	if perr != nil {
		c.LoggerError(logger, "invalid pruning configuration: "+perr.Error())
		return
	}
	enclaveRetainVersions = pruningOpts.KeepRecent
	enclavePruneInterval = pruningOpts.Interval
	c.LoggerInfo(logger, fmt.Sprintf("enclave retention: strategy=%s keepRecent=%d interval=%d", *pruningStrategy, enclaveRetainVersions, enclavePruneInterval))
	stateStore.SetPruning(pruningOpts)

	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	//	stateStore.MountStoreWithDB(memStoreKey, sdk.StoreTypeMemory, nil)

	serverCtx := sdk.NewContext(stateStore, tmproto.Header{}, false, logger)

	registry := codectypes.NewInterfaceRegistry()
	cdc := amino.NewProtoCodec(registry)

	// FATAL on error, deliberately.  This used to discard the error, and a failed or partial load
	// then yielded an empty tree -- which the enclave would happily serve and COMMIT on top of,
	// silently discarding its entire state.  Every recovery mechanism in enclave_height.go builds
	// on this load being real; an enclave that cannot load its state must not run.
	if err := stateStore.LoadLatestVersion(); err != nil {
		c.LoggerError(logger, "cannot load enclave state store: "+err.Error())
		return
	}

	cacheCtx, cacheCtxWrite := serverCtx.CacheContext()

	cs := qadenaServer{
		StoreKey:      storeKey,
		ServerCtx:     serverCtx,
		CacheCtx:      cacheCtx,
		CacheCtxWrite: cacheCtxWrite,
		Cdc:           cdc,
		MetaDB:        db,
		SecretsDB:     secretsDB,
		HomePath:      *homePath,
		RealEnclave:   *realEnclave,
	}

	// Stamp or verify the on-disk schema before anything can write.  Skipped in upgrade mode,
	// where the db handle is read-only and the process only ferries params between enclaves.
	if *upgradeFromEnclave == "" && !enclaveUpgradeMode {
		if err := cs.initSchema(); err != nil {
			c.LoggerError(logger, "enclave store schema check failed: "+err.Error())
			return
		}
	}

	if *resetPrivateState {
		if err := cs.resetPrivateState(); err != nil {
			c.LoggerError(logger, "reset-private-state failed: "+err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *testRemoteReportLocally {
		// Test SGX remote report, but locally
		fmt.Println("Getting remote report")
		report, err := cs.getRemoteReport("test")
		if err != nil {
			c.LoggerError(logger, "couldn't get remote report "+err.Error())
			return
		}
		fmt.Println("Hex encoded report:  " + hex.EncodeToString(report))

		// Test SGX remote report verification, but locally
		success := cs.verifyRemoteReportInternal(report, "test", true)
		if !success {
			c.LoggerError(logger, "couldn't verify remote report")
			return
		}
		fmt.Println("Remote report verified successfully")

		os.Exit(0)
	}

	if *testRemoteReportHex != "" {
		// Test SGX remote report, but locally
		fmt.Println("Remote report hex " + *testRemoteReportHex)
		report, err := hex.DecodeString(*testRemoteReportHex)
		if err != nil {
			c.LoggerError(logger, "Couldn't decode remote report hex "+err.Error())
			return
		}

		// Test SGX remote report verification, but locally
		success := cs.verifyRemoteReportInternal(report, "test", true)
		if !success {
			c.LoggerError(logger, "Couldn't verify remote report hex")
			return
		}
		fmt.Println("Remote report hex verified successfully")

		os.Exit(0)
	}

	// here's where we can connect to the old server if configured
	if *upgradeFromEnclave != "" {
		var conn *grpc.ClientConn
		var err error

		c.LoggerDebug(logger, "upgradeFromEnclave "+*upgradeFromEnclave)

		addr := fmt.Sprintf("unix:///tmp/qadena_%d.sock", *port)

		c.LoggerDebug(logger, "Will connect to QadenaDEnclave (unix domain socket)", addr)

		conn, err = grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithTimeout(time.Duration(5)*time.Second))

		greeterClient := types.NewGreeterClient(conn)

		// Contact the server and print out its response.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		r, err := greeterClient.SayHello(ctx, &types.HelloRequest{Name: "Pong"})
		if err != nil {
			c.LoggerError(logger, "Could not greet", err)
			os.Exit(10)
		}

		c.LoggerDebug(logger, "Greeting", r.GetMessage())

		enclaveClient := types.NewQadenaEnclaveClient(conn)

		mnemonic, err := c.GenerateNewMnemonic()
		if err != nil {
			c.LoggerError(logger, "Couldn't create new mnemonic")
			os.Exit(10)
		}

		createPublicKeyReq := c.PublicKeyReq{
			FriendlyName:    types.EnclaveKeyringName,
			RecoverMnemonic: mnemonic,
			IsEphemeral:     false,
			EphAccountIndex: 0,
		}

		_, _, _, _, err = c.CreatePublicKey(clientCtx, createPublicKeyReq)
		if err != nil {
			c.LoggerError(logger, "couldn't create enclave key")
			os.Exit(10)
		}

		_, _, tmpPubK, tmpPrivK, err := c.GetAddressByNameNoArmor(clientCtx, types.EnclaveKeyringName)
		if err != nil {
			c.LoggerError(logger, "couldn't get address for "+types.EnclaveKeyringName+" "+err.Error())
			os.Exit(10)
		}

		c.LoggerDebug(logger, "tmpPubK "+tmpPubK)
		c.LoggerDebug(logger, "tmpPrivK "+tmpPrivK)

		remoteReport, err := cs.getRemoteReport(strings.Join([]string{
			tmpPubK,
		}, "|"))
		if err != nil {
			c.LoggerError(logger, "Could not get remote report", err)
			os.Exit(10)
		}

		res, err := enclaveClient.UpgradeEnclave(context.Background(), &types.MsgUpgradeEnclave{
			RemoteReport: remoteReport,
			EnclavePubK:  tmpPubK,
		})

		if err != nil {
			st, ok := status.FromError(err)
			if ok {
				c.LoggerDebug(logger, "grpcstatus code", c.PrettyPrint(st.Code()))
				c.LoggerDebug(logger, "grpcstatus message", c.PrettyPrint(st.Message()))

				sdkErr := types.ErrRemoteReportNotVerified

				c.LoggerDebug(logger, "Cosmos Error:", sdkErr.GRPCStatus().Message())

				c.LoggerDebug(logger, "Cosmos Error Code:", sdkErr.ABCICode())
				c.LoggerDebug(logger, "Cosmos Error Description:", sdkErr.Error())

				if sdkErr.GRPCStatus().Message() == st.Message() {
					c.LoggerDebug(logger, "Cosmos Error:", sdkErr.GRPCStatus().Message())
					os.Exit(5)
				}
			}

			c.LoggerError(logger, "err "+err.Error())
			os.Exit(10)
		}

		// THE UPGRADE HANDOVER IS ITS OWN BOOTSTRAP, and it needs an anchor this enclave can check.
		//
		// We are a brand-new measurement: no sealed params, no trusted set, nothing but ourselves.
		// So the ordinary check -- "is the reporting measurement active in my trusted set" -- can
		// only ever fail here, and it did:
		//
		//     [enclave-new-unique048 - E]: But couldn't find an active enclave identity for uniqueID: unique047
		//     [enclave-new-unique048 - E]: remote report unverified
		//
		// It used to pass because trust was read from the MIRRORED STORE, which already held the old
		// measurement as active -- the store was doing bootstrap duty for this path, invisibly.
		//
		// The anchor that remains is the operator's own instruction: this process was started as
		// --upgrade-from-enclave-unique-id=<old>, naming exactly which measurement it expects state
		// from.  Checking the hardware report against THAT is a real check -- the report cannot lie
		// about its measurement -- and it is trust the operator has already extended by choosing
		// which binaries to run and pointing them at each other.
		//
		// Note the direction.  Secrets LEAVING the old enclave are gated by the old enclave, which
		// requires our measurement to be active on chain -- that check is untouched and is the one
		// that protects the keys.  This one protects US from adopting state from an impostor, whose
		// cost is a broken node rather than disclosure.
		if !cs.verifyUpgradeSourceIsExpected(
			res.GetRemoteReport(),
			string(res.GetEncEnclavePrivateStateEnclavePubK()),
			*upgradeFromEnclave) {
			os.Exit(10)
		}

		epStr := string(c.BDecrypt(tmpPrivK, res.GetEncEnclavePrivateStateEnclavePubK()))

		// print json
		c.LoggerDebug(logger, "ep "+epStr)

		var ep storedEnclaveParams

		err = json.Unmarshal([]byte(epStr), &ep)

		if err != nil {
			c.LoggerError(logger, "Couldn't unmarshal enclave params "+err.Error())
			os.Exit(10)
		}

		c.LoggerDebug(logger, "storedEnclaveParams "+c.PrettyPrint(ep))

		cs.privateEnclaveParams = ep.PrivateEnclaveParams
		cs.sharedEnclaveParams = ep.SharedEnclaveParams

		cs.saveEnclaveParams()

		os.Exit(0)
	}

	cs.pendingSuspiciousTransactions = make([]types.SuspiciousTransaction, 0)

	// No suspicious-transaction threshold is computed here any more.  It is per-sender now -- the
	// jurisdiction with the lowest limit among the sender's residency and citizenship -- and it
	// arrives with each scan already priced by the keeper, so a governance change takes effect
	// without restarting nodes.

	if !cs.loadEnclaveParams() {
		c.LoggerInfo(logger, "Enclave params could not be loaded, but this is ok if the enclave has not yet been initialized.")
	}

	var lis net.Listener

	if SupportsUnixDomainSockets {
		var err error

		sockPath := fmt.Sprintf("/tmp/qadena_%d.sock", *port)

		// A LEFTOVER SOCKET IS REMOVED, and a removal that FAILS is reported.
		//
		// This used to discard the error, which is fine while the same user always runs the enclave
		// and misleading the moment that changes.  /tmp is sticky, so a socket left behind by a
		// previous run AS ANOTHER USER -- root, typically, after the node was started with sudo for
		// SGX -- cannot be unlinked here.  net.Listen then fails with
		//
		//     bind: address already in use
		//
		// which names neither the file nor the reason, and run_enclave.sh retries forever against a
		// condition that will never clear on its own.
		if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
			c.LoggerError(logger, "could not remove the stale socket "+sockPath+": "+err.Error())
			if fi, statErr := os.Stat(sockPath); statErr == nil {
				if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
					c.LoggerError(logger, fmt.Sprintf(
						"it belongs to uid %d and this process is uid %d -- /tmp is sticky, so only that user or root can remove it.  Run:  sudo rm -f %s",
						st.Uid, os.Getuid(), sockPath))
				}
			}
		}

		// listen on a unix domain socket
		lis, err = net.Listen("unix", sockPath)

		if err != nil {
			c.LoggerError(logger, "failed to listen on "+sockPath+": "+err.Error())
			return
		}
	} else {
		if *realEnclave {
			// Create a TLS config with a self-signed certificate and an embedded report.
			var tlsCfg *tls.Config
			var err error
			for i := 0; i < 5; i++ {
				tlsCfg, err = enclave.CreateAttestationServerTLSConfig()
				if err != nil {
					c.LoggerError(logger, "FAILED to create attestation for TLS config: "+err.Error())
					time.Sleep(1 * time.Second)
				} else {
					break
				}
			}
			if err != nil {
				c.LoggerError(logger, "COMPLETELY FAILED to create attestation for TLS config: "+err.Error())
				return
			}
			lis, err = tls.Listen("tcp", fmt.Sprintf(":%d", *port), tlsCfg)
			if err != nil {
				c.LoggerError(logger, "failed to listen: "+err.Error())
				return
			}
		} else {
			var err error
			lis, err = net.Listen("tcp", fmt.Sprintf(":%d", *port))
			if err != nil {
				c.LoggerError(logger, "failed to listen: "+err.Error())
				return
			}
		}
	}

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(panicRecoveryInterceptor))

	types.RegisterGreeterServer(grpcServer, &pingServer{})
	types.RegisterQadenaEnclaveServer(grpcServer, &cs)
	c.LoggerDebug(logger, "server listening at "+c.PrettyPrint(lis.Addr()))

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		c.LoggerInfo(logger, "Received SIGINT, exiting with code 20")
		os.Exit(20)
	}()

	if err := grpcServer.Serve(lis); err != nil {
		c.LoggerError(logger, "failed to serve: "+err.Error())
	}
}
