package main

import (
	_ "embed"
	"fmt"
	"slices"
	"strconv"
	"sync"

	//	"net/http"
	"context"
	"flag"

	"bytes"
	"os"
	"strings"

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
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"

	//  "github.com/evmos/ethermint/encoding"
	//  "github.com/c3qtech/qadena/app"
	cmdcfg "github.com/c3qtech/qadena_v3/cmd/config"
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
	//	"github.com/cosmos/evm/crypto/ethsecp256k1"
	//	"github.com/cosmos/evm/crypto/ethsecp256k1"
	evmhd "github.com/cosmos/evm/crypto/hd"
	evmeip712 "github.com/cosmos/evm/ethereum/eip712"

	"google.golang.org/grpc/credentials/insecure"

	"os/signal"
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

	privateEnclaveParams PrivateEnclaveParams
	sharedEnclaveParams  types.EncryptableSharedEnclaveParams

	// for tracking what's changed within a block
	changedWallets     []string
	changedCredentials []CredentialKey
	//changedEnclaveIdentities []string // uniqueid
	changedRecoverKeys []string

	// for tracking suspicious transactions
	transactionMap map[string]c.Transactions

	newSuspiciousTransactions []types.SuspiciousTransaction

	coinSuspiciousAmount sdk.Coin

	HomePath    string
	RealEnclave bool

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

var keyUpdateFrequency int64 = 555

var unvalidatedEnclaveIdentitiesCheckCounter int64 = 1

var SupportsUnixDomainSockets bool = true

const (
	EnclaveSSIntervalOwnersKeyPrefix                     = "Enclave/SSIntervalOwners/value/"
	EnclaveSSIntervalSharesKeyPrefix                     = "Enclave/SSIntervalShares/value/"
	EnclaveSSIntervalPrivKKeyPrefix                      = "Enclave/SSIntervalPrivK/value/"
	EnclaveSSIntervalPubKKeyPrefix                       = "Enclave/SSIntervalPubK/value/"
	EnclaveCredentialHashKeyPrefix                       = "Enclave/CredentialHash/value/"
	EnclaveCredentialPCXYKeyPrefix                       = "Enclave/CredentialPCXY/value/"
	EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix = "Enclave/ProtectSubWalletIDByOriginalWalletID/value/"
	EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix = "Enclave/RecoverOriginalWalletIDByNewWalletID/value/"
	EnclaveAuthorizedSignatoryKeyPrefix                  = "Enclave/AuthorizedSignatory/value/"
	EnclaveEnclaveIdentityKeyPrefix                      = "Enclave/EnclaveIdentity/value/"
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

				c.LoggerDebug(logger, "params "+c.PrettyPrint(params))

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
	pioneerWalletID, _, found = s.getIntervalPublicKeyId(pioneerID, types.PioneerNodeType)
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

func (s *qadenaServer) saveEnclaveParams() bool {
	ep := storedEnclaveParams{
		PrivateEnclaveParams: s.privateEnclaveParams,
		SharedEnclaveParams:  s.sharedEnclaveParams,
	}

	c.LoggerDebug(logger, "saveEnclaveParams "+c.PrettyPrint(ep))

	b, err := json.Marshal(ep)

	var b2 []byte

	if testSeal {
		b2, err = json.Marshal(ep)
	}

	if err != nil {
		c.LoggerError(logger, "saveEnclaveParams marshal error "+err.Error())
		return false
	}

	c.LoggerDebug(logger, "sealing with product key (encrypting)")
	b, err = s.SealWithProductKey(b)

	if testSeal {
		b2, err = s.SealWithProductKey(b2)
	}

	if err != nil {
		c.LoggerError(logger, "sealing error "+err.Error())
		return false
	}

	err = os.WriteFile(s.HomePath+"/enclave_config/enclave_params_"+uniqueID+".json", b, 0644)
	if testSeal {
		err = os.WriteFile(s.HomePath+"/enclave_config/enclave_params_backup.json", b2, 0644)
	}

	if err != nil {
		c.LoggerError(logger, "err writing file "+err.Error())
		return false
	}

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

// returns true if valid
func (s *qadenaServer) verifyRemoteReport(remoteReportBytes []byte, certifyData string) bool {
	var uniqueID string
	var signerID string
	var success bool

	// gunzip report
	var buf bytes.Buffer
	reader, err := gzip.NewReader(bytes.NewReader(remoteReportBytes))
	if err != nil {
		c.LoggerError(logger, "error gunzipping remote report "+err.Error())
		return false
	}
	_, err = buf.ReadFrom(reader)
	if err != nil {
		c.LoggerError(logger, "error gunzipping remote report "+err.Error())
		return false
	}
	remoteReportBytes = buf.Bytes()

	if s.RealEnclave {
		remoteReport, err := enclave.VerifyRemoteReport(remoteReportBytes)
		if err != nil {
			c.LoggerError(logger, "error verifying remote report "+err.Error())
			return false
		}

		hash := sha256.Sum256([]byte(certifyData))
		if bytes.Compare(remoteReport.Data[:len(hash)], hash[:]) != 0 {
			c.LoggerDebug(logger, "mismatch hash")
			c.LoggerDebug(logger, "remoteReportData hash "+hex.EncodeToString(remoteReport.Data[:len(hash)]))
			c.LoggerDebug(logger, "certifyData hash "+hex.EncodeToString(hash[:]))
			return false
		}
		c.LoggerDebug(logger, "hash match")

		uniqueID = hex.EncodeToString(remoteReport.UniqueID)
		signerID = hex.EncodeToString(remoteReport.SignerID)
	} else {
		success, uniqueID, signerID = c.DebugVerifyRemoteReport(logger, remoteReportBytes, certifyData)
		if !success {
			c.LoggerError(logger, "couldn't verify remote report")
			return false
		}
	}
	c.LoggerDebug(logger, "remoteReport uniqueID: "+uniqueID)
	found := s.getEnclaveIdentity(uniqueID, signerID, false) // only get active ones
	if !found {
		c.LoggerError(logger, "couldn't find enclave identity")
		return false
	}
	return true
}

func (s *qadenaServer) loadEnclaveParams() bool {
	filename := s.HomePath + "/enclave_config/enclave_params_" + uniqueID + ".json"
	fileBytes, err := ioutil.ReadFile(filename)

	if err != nil {
		c.LoggerInfo(logger, "Couldn't read file "+filename+" but this is ok if the enclave has not yet been initialized.")
		return false
	} else {
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

	c.LoggerDebug(logger, "storedEnclaveParams "+c.PrettyPrint(ep))

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

	_, _, _, privK, _, err := c.GetAddressByName(clientCtx, in.PubKID, ArmorPassPhrase)
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

	var state struct {
		PrivateEnclaveParams                    PrivateEnclaveParams
		SharedEnclaveParams                     types.EncryptableSharedEnclaveParams
		Wallets                                 []types.Wallet
		Credentials                             []types.Credential
		CredentialHashMap                       map[string]string
		RecoverOriginalWalletIDByNewWalletIDMap map[string]string
		RecoverKeyByOriginalWalletIDs           []types.RecoverKey
		JarRegulators                           []types.JarRegulator
		PioneerJars                             []types.PioneerJar
		PublicKeys                              []types.PublicKey
		IntervalPublicKeyIds                    []types.IntervalPublicKeyID
		//		PioneerIPAddressMap                     PioneerIPAddressMap
		ProtectKeys                             []types.ProtectKey
		ProtectSubWalletIDByOriginalWalletIDMap map[string]string
		CredentialPCXYMap                       map[string]string
		EnclaveSSShareMap                       EnclaveSSShareMap
		EnclaveSSOwnersMap                      types.EncryptableEnclaveSSOwnerMap
		EnclavePrivKCacheMap                    EnclavePrivKCacheMap
		EnclavePubKCacheMap                     EnclavePubKCacheMap
		AuthorizedSignatoryMap                  []types.ValidateAuthorizedSignatoryRequest
	}

	state.PrivateEnclaveParams = s.privateEnclaveParams
	state.SharedEnclaveParams = s.sharedEnclaveParams

	state.EnclaveSSShareMap = s.exportSealedTable(EnclaveSSIntervalSharesKeyPrefix)
	state.EnclaveSSOwnersMap = *s.getAllOwners()
	state.EnclavePubKCacheMap = s.exportTable(EnclaveSSIntervalPubKKeyPrefix)
	state.EnclavePrivKCacheMap = s.exportSealedTable(EnclaveSSIntervalPrivKKeyPrefix)

	// export wallets
	state.Wallets = s.getAllWallets()

	// export credentials
	state.Credentials = s.getAllCredentials()

	state.CredentialHashMap = s.exportSealedTable(EnclaveCredentialHashKeyPrefix)

	state.CredentialPCXYMap = s.exportTable(EnclaveCredentialPCXYKeyPrefix)

	state.RecoverOriginalWalletIDByNewWalletIDMap = s.exportSealedTable(EnclaveRecoverOriginalWalletIDByNewWalletIDKeyPrefix)
	state.RecoverKeyByOriginalWalletIDs = s.getAllRecoverKeyByOriginalWalletIDs()

	state.PublicKeys = s.getAllPublicKeys()

	//	state.IntervalPublicKeyIdMap = make(map[string]string)
	//	for k, v := range intervalPublicKeyIdMap {
	//		state.IntervalPublicKeyIdMap["["+k.nodeID+","+k.nodeType+"]"] = v
	//	}

	state.IntervalPublicKeyIds = s.getAllIntervalPublicKeyIds()

	// export jar regulator map
	state.JarRegulators = s.getAllJarRegulators()

	// export pioneer jar map
	state.PioneerJars = s.getAllPioneerJars()

	//	state.PioneerIPAddressMap = s.getAllPioneerIPAddress()

	state.ProtectKeys = s.getAllProtectKeys()

	state.ProtectSubWalletIDByOriginalWalletIDMap = s.exportSealedTable(EnclaveProtectSubWalletIDByOriginalWalletIDKeyPrefix)

	state.AuthorizedSignatoryMap = s.getAllAuthorizedSignatories()

	//	state.CredentialIDByPCXYMap = credentialIDByPCXYMap

	//  c.LoggerDebug(logger, "state" + c.PrettyPrint(state))

	// export as jsonstring
	jsonState, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}

	return &types.ExportPrivateStateReply{State: string(jsonState)}, nil
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
	walletID, _, intervalPubK, intervalPrivK, _, err = c.GetAddressByName(clientCtx, mnemonic, ArmorPassPhrase)

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
		pioneerWalletID, _, found := s.getIntervalPublicKeyId(pioneers[i], types.PioneerNodeType)
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

func (s *qadenaServer) InitEnclave(ctx context.Context, in *types.MsgInitEnclave) (*types.InitEnclaveReply, error) {
	c.LoggerDebug(logger, "InitEnclave "+c.PrettyPrint(in))

	kb := clientCtx.Keyring

	if s.getPrivateEnclaveParamsPioneerID() != "" {
		c.LoggerDebug(logger, "already initialized, no need to do this again!")
		return &types.InitEnclaveReply{Status: true}, nil
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

	c.LoggerDebug(logger, "keyring "+c.PrettyPrint(kb))

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
		if in.IsProposer {
			go func() {
				c.LoggerDebug(logger, "checking for unvalidated enclave identities")
				// check for unvalidated identities
				s.validateEnclaveIdentities()
			}()
		}
		// set it to max to a large number to prevent it from firing again
		unvalidatedEnclaveIdentitiesCheckCounter = keyUpdateFrequency
	}

	return &types.UpdateHeightReply{Status: true}, nil
}

func (s *qadenaServer) updateSSIntervalKey() bool {
	c.LoggerDebug(logger, "updateSSIntervalKey")

	c.LoggerDebug(logger, "Going to create a new SS share")
	// create a new interval key if we are the leader
	c.LoggerDebug(logger, "enclaveParams"+c.PrettyPrint(s.privateEnclaveParams))

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

	c.LoggerDebug(logger, "msgs "+c.PrettyPrint(msgs))

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

	// seal it
	status := s.saveEnclaveParams()
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
	pwalletID, pwalletAddr, _, _, _, err := c.GetAddressByName(clientCtx, s.getPrivateEnclaveParamsPioneerID(), ArmorPassPhrase)
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

	c.LoggerDebug(logger, "msgs "+c.PrettyPrint(msgs))

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

	pwalletID, pwalletAddr, _, _, _, err := c.GetAddressByName(clientCtx, s.getPrivateEnclaveParamsPioneerID(), ArmorPassPhrase)

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
	c.LoggerDebug(logger, "QueryEnclaveSyncEnclave "+c.PrettyPrint(in))

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

	// send these for now
	//	JarID         string
	//	JarArmorPrivK string
	//	JarPrivK      string
	//	JarPubK       string

	//	RegulatorID         string
	//	RegulatorArmorPrivK string
	//	RegulatorPrivK      string
	//	RegulatorPubK       string

	// intentionally send the SSIntervalOwners
	tmpEnclaveParams.SSIntervalOwners = s.getAllOwners()

	// do not send the SSIntervalShares
	// do not send our local private key cache

	// remove first intentionally send the public key cache
	//  tmpEnclaveParams.SSIntervalPubKCache = s.exportTable(EnclaveSSIntervalPubKKeyPrefix)

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

func (s *qadenaServer) QueryEnclaveValidateEnclaveIdentity(goCtx context.Context, in *types.QueryEnclaveValidateEnclaveIdentityRequest) (*types.QueryEnclaveValidateEnclaveIdentityResponse, error) {
	c.LoggerDebug(logger, "QueryEnclaveValidateEnclaveIdentity "+c.PrettyPrint(in))

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
	c.LoggerDebug(logger, "QueryEnclaveSecretShare "+c.PrettyPrint(in))

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
	c.LoggerDebug(logger, "QueryEnclaveRecoverKeyShare "+c.PrettyPrint(in))

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
		c.LoggerDebug(logger, "processing rShare "+c.PrettyPrint(rShare))
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
	c.LoggerDebug(logger, "QueryGetRecoverKey "+c.PrettyPrint(in))

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
		c.LoggerDebug(logger, "processing rShare "+c.PrettyPrint(rShare))
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
			_, _, found := s.getIntervalPublicKeyId(shareWalletID, types.PioneerNodeType)
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

			c.LoggerDebug(logger, "params "+c.PrettyPrint(params))

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
	c.LoggerDebug(logger, "QueryFindCredential "+c.PrettyPrint(in))

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

	c.LoggerDebug(logger, "credential "+c.PrettyPrint(credential))

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

	c.LoggerDebug(logger, "credentialPC "+c.PrettyPrint(credentialPC))
	c.LoggerDebug(logger, "proofPC "+c.PrettyPrint(proofPC))
	c.LoggerDebug(logger, "checkPC "+c.PrettyPrint(checkPC))

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
	c.LoggerDebug(logger, "SyncEnclave "+c.PrettyPrint(in))

	if s.getPrivateEnclaveParamsPioneerID() != "" {
		c.LoggerDebug(logger, "already synchronized")
		return &types.SyncEnclaveReply{Status: true}, nil
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
	}

	c.LoggerDebug(logger, "params "+c.PrettyPrint(params))

	res, err := queryClient.EnclaveSyncEnclave(context.Background(), params)
	if err != nil {
		c.LoggerError(logger, "err "+err.Error())
		return nil, err
	}

	// still need to validate the returned remote report
	c.LoggerDebug(logger, "SyncEnclave returned", c.PrettyPrint(res))

	c.LoggerDebug(logger, "private enclave params", c.PrettyPrint(s.privateEnclaveParams))

	var fromRemoteEnclaveParams types.EncryptableSharedEnclaveParams
	_, err = c.BDecryptAndProtoUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), res.GetEncEnclaveParamsEnclavePubK(), &fromRemoteEnclaveParams)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt")
		return nil, err
	}

	c.LoggerDebug(logger, "fromRemoteEnclaveParams", c.PrettyPrint(fromRemoteEnclaveParams))

	// copy from fromRemoteEnclaveParams to enclaveParams

	s.setSharedEnclaveParamsJarInfo(fromRemoteEnclaveParams.JarID, fromRemoteEnclaveParams.JarPubK, fromRemoteEnclaveParams.JarPrivK, fromRemoteEnclaveParams.JarArmorPrivK)

	s.setSharedEnclaveParamsRegulatorInfo(fromRemoteEnclaveParams.RegulatorID, fromRemoteEnclaveParams.RegulatorPubK, fromRemoteEnclaveParams.RegulatorPrivK, fromRemoteEnclaveParams.RegulatorArmorPrivK)

	// store the owners
	s.setAllOwners(fromRemoteEnclaveParams.SSIntervalOwners)

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

	pwalletID, pwalletAddr, _, _, _, err = c.GetAddressByName(queryClientCtx, s.getPrivateEnclaveParamsPioneerID(), ArmorPassPhrase)

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
	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(queryClientCtx, flagSet, "various update msgs in SyncEnclave", msgs...)

	if err != nil {
		c.LoggerError(logger, "failed to broadcast "+err.Error())
		c.LoggerError(logger, "msgs "+c.PrettyPrint(msgs))
		return nil, err
	}

	// commit db
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
	c.LoggerDebug(logger, "UpgradeEnclave "+c.PrettyPrint(in))

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
	c.LoggerDebug(logger, "UpdateEnclaveIdentity "+c.PrettyPrint(in))

	if !s.verifyRemoteReport(
		in.RemoteReport,
		strings.Join([]string{
			in.EnclaveIdentity.UniqueID,
			in.EnclaveIdentity.SignerID,
			in.EnclaveIdentity.ProductID,
			in.EnclaveIdentity.Status,
		}, "|")) {
		c.LoggerError(logger, "remote report unverified")
		return nil, types.ErrRemoteReportNotVerified
	}

	s.setEnclaveIdentity(in.EnclaveIdentity)
	return &types.UpdateEnclaveIdentityReply{Status: true}, nil
}

func (s *qadenaServer) SetEnclaveIdentity(ctx context.Context, in *types.EnclaveIdentity) (*types.SetEnclaveIdentityReply, error) {
	c.LoggerDebug(logger, "SetEnclaveIdentity "+c.PrettyPrint(in))

	if in.UniqueID == uniqueID && in.SignerID == signerID {
		c.LoggerDebug(logger, "SetEnclaveIdentity matches our enclave identity")
		s.setEnclaveIdentity(in)
		return &types.SetEnclaveIdentityReply{Status: true}, nil
	}

	if in.Status != "inactive" && in.Status != "unvalidated" {
		c.LoggerError(logger, "status must be \"inactive\" or \"unvalidated\"")
		return nil, types.ErrInvalidStatus
	}
	s.setEnclaveIdentity(in)
	return &types.SetEnclaveIdentityReply{Status: true}, nil
}

func (s *qadenaServer) SetWallet(ctx context.Context, in *types.Wallet) (*types.SetWalletReply, error) {
	c.LoggerDebug(logger, "SetWallet "+c.PrettyPrint(in))
	s.setWalletNoNotify(*in)
	return &types.SetWalletReply{Status: true}, nil
}

func (s *qadenaServer) SetRecoverKey(ctx context.Context, in *types.RecoverKey) (*types.SetRecoverKeyReply, error) {
	c.LoggerDebug(logger, "SetRecoverKey "+c.PrettyPrint(in))
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
	c.LoggerDebug(logger, "SetProtectKey "+c.PrettyPrint(in))

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

	c.LoggerDebug(logger, "mainEWalletID "+c.PrettyPrint(mainEWalletID))

	s.setProtectKeyNoNotify(in)
	s.setProtectSubWalletIDByOriginalWalletID(mainEWalletID.WalletID, in.WalletID)
	return &types.SetProtectKeyReply{Status: true}, nil
}

func (s *qadenaServer) ClaimCredential(ctx context.Context, in *types.MsgClaimCredential) (*types.MsgClaimCredentialResponse, error) {
	c.LoggerDebug(logger, "ClaimCredential "+c.PrettyPrint(in))

	unprotoClaimCredentialExtraParmsVShareBind := c.UnprotoizeVShareBindData(in.ClaimCredentialExtraParmsVShareBind)

	//var claimCredentialExtraParms c.ClaimCredentialExtraParms
	var encryptableClaimCredentialExtraParms types.EncryptableClaimCredentialExtraParms
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoClaimCredentialExtraParmsVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoClaimCredentialExtraParmsVShareBind.GetSSIntervalPubKID()), unprotoClaimCredentialExtraParmsVShareBind, in.EncClaimCredentialExtraParmsVShare, &encryptableClaimCredentialExtraParms)
	if err != nil {
		c.LoggerDebug(logger, "Can't decrypt claimCredentialExtraParms")
		return nil, err
	}

	c.LoggerDebug(logger, "claimCredentialExtraParms "+c.PrettyPrint(encryptableClaimCredentialExtraParms))

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

	c.LoggerDebug(logger, "credentialCCPubK "+c.PrettyPrint(credentialCCPubK))
	c.LoggerDebug(logger, "encryptableClaimCredentialExtraParms.GetCredentialInfoVShareBind() "+c.PrettyPrint(encryptableClaimCredentialExtraParms.CredentialInfoVShareBind))
	c.LoggerDebug(logger, "encryptableClaimCredentialExtraParms.EncCredentialInfoVShare "+c.PrettyPrint(encryptableClaimCredentialExtraParms.CredentialInfoVShareBind))

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

	c.LoggerDebug(logger, "ipCredential "+c.PrettyPrint(ipCredential))

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
		c.LoggerError(logger, "failed to validate credentialPC - newCredentialPC - zeroPC = 0")
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

	c.LoggerDebug(logger, "checkPC "+c.PrettyPrint(checkPC))
	c.LoggerDebug(logger, "newCredentialPC "+c.PrettyPrint(newCredentialPC))

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
	ipCredential.WalletID = "CLAIMED"
	s.setCredential(ipCredential.CredentialID, ipCredential.CredentialType, ipCredential)

	return &types.MsgClaimCredentialResponse{}, nil
}

func (s *qadenaServer) ValidateAuthorizedSigner(ctx context.Context, in *types.ValidateAuthorizedSignerRequest) (*types.ValidateAuthorizedSignerReply, error) {
	c.LoggerDebug(logger, "ValidateAuthorizedSigner "+c.PrettyPrint(in))

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

	c.LoggerDebug(logger, "vShareCreateWallet "+c.PrettyPrint(vShareCreateWallet))

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

	c.LoggerDebug(logger, "emailSCI "+c.PrettyPrint(emailSCI))

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

func (s *qadenaServer) decryptSignatory(in *types.VShareSignatory, trusted bool) *types.EncryptableSignatory {
	c.LoggerDebug(logger, "decryptSignatory "+c.PrettyPrint(in)+" "+strconv.FormatBool(trusted))

	bindData := c.UnprotoizeVShareBindData(in.VShareBind)

	var b64Address string
	var ssIntervalPubKID string
	var found bool

	if trusted {
		// find the ss interval pubk in the bind data
		b64Address, ssIntervalPubKID = bindData.FindB64AddressAndBech32AddressByNodeIDAndType(types.SSNodeID, types.SSNodeType)
		c.LoggerDebug(logger, "trustedssIntervalPubKID "+b64Address+" "+ssIntervalPubKID)
	} else {
		// get ss interval public key id
		ssIntervalPubKID, _, found = s.getIntervalPublicKeyId(types.SSNodeID, types.SSNodeType)

		if !found {
			return nil
		}

		b64Address = bindData.FindB64Address(ssIntervalPubKID)

		if b64Address == "" {
			c.LoggerError(logger, "bindData does not contain the ssIntervalPubKID")
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

	c.LoggerDebug(logger, "es "+c.PrettyPrint(es))

	return &es
}

func (s *qadenaServer) decryptAuthorizedSignatory(in *types.VShareSignatory, trusted bool) *types.EncryptableAuthorizedSignatory {
	c.LoggerDebug(logger, "decryptAuthorizedSignatory "+c.PrettyPrint(in)+" "+strconv.FormatBool(trusted))

	bindData := c.UnprotoizeVShareBindData(in.VShareBind)

	var b64Address string
	var ssIntervalPubKID string
	var found bool

	if trusted {
		// find the ss interval pubk in the bind data
		b64Address, ssIntervalPubKID = bindData.FindB64AddressAndBech32AddressByNodeIDAndType(types.SSNodeID, types.SSNodeType)
		c.LoggerDebug(logger, "trustedssIntervalPubKID "+b64Address+" "+ssIntervalPubKID)
	} else {
		// get ss interval public key id
		ssIntervalPubKID, _, found = s.getIntervalPublicKeyId(types.SSNodeID, types.SSNodeType)

		if !found {
			return nil
		}

		b64Address = bindData.FindB64Address(ssIntervalPubKID)

		if b64Address == "" {
			c.LoggerError(logger, "bindData does not contain the ssIntervalPubKID")
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

	c.LoggerDebug(logger, "eas "+c.PrettyPrint(eas))

	return &eas
}

func (s *qadenaServer) ValidateAuthorizedSignatory(ctx context.Context, in *types.ValidateAuthorizedSignatoryRequest) (*types.ValidateAuthorizedSignatoryReply, error) {
	c.LoggerDebug(logger, "ValidateAuthorizedSignatory "+c.PrettyPrint(in))

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

		c.LoggerDebug(logger, "vShareCreateWallet "+c.PrettyPrint(vShareCreateWallet))

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

	s.SetAuthorizedSignatory(ctx, in)

	return &types.ValidateAuthorizedSignatoryReply{Status: true}, nil
}

// we'll store the request
func (s *qadenaServer) SetAuthorizedSignatory(ctx context.Context, in *types.ValidateAuthorizedSignatoryRequest) {
	c.LoggerDebug(logger, "SetAuthorizedSignatory "+c.PrettyPrint(in))

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveAuthorizedSignatoryKeyPrefix))

	b := s.Cdc.MustMarshal(in)

	store.Set(EnclaveKeyKey(in.Creator), b)
	c.LoggerDebug(logger, "Stored authorized signatory")
}

func (s *qadenaServer) GetAuthorizedSignatory(ctx context.Context, creator string) (*types.VShareSignatory, bool) {
	c.LoggerDebug(logger, "GetAuthorizedSignatory "+creator)

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveAuthorizedSignatoryKeyPrefix))

	bz := store.Get(EnclaveKeyKey(creator))
	if bz == nil {
		return nil, false
	}

	var in types.ValidateAuthorizedSignatoryRequest
	s.Cdc.MustUnmarshal(bz, &in)

	return in.Signatory, true
}

func (s *qadenaServer) SetCredential(ctx context.Context, in *types.Credential) (*types.SetCredentialReply, error) {
	c.LoggerDebug(logger, "SetCredential "+c.PrettyPrint(in))
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

func (s *qadenaServer) RemoveCredential(ctx context.Context, in *types.Credential) (*types.RemoveCredentialReply, error) {
	c.LoggerDebug(logger, "RemoveCredential "+c.PrettyPrint(in))

	// get the credential
	credential, found := s.getCredential(in.CredentialID, in.CredentialType)
	if !found {
		c.LoggerError(logger, "credential does not exist")
		return &types.RemoveCredentialReply{Status: false}, types.ErrCredentialNotExists
	}

	if credential.WalletID != "" {
		c.LoggerError(logger, "credential is already claimed: "+credential.WalletID)
		return &types.RemoveCredentialReply{Status: false}, types.ErrCredentialClaimed
	}

	s.removeCredentialByPCXY(&credential)
	s.removeCredentialNoNotify(in.CredentialID, in.CredentialType)

	return &types.RemoveCredentialReply{Status: true}, nil
}

func (s *qadenaServer) SignRecoverKey(ctx context.Context, in *types.MsgSignRecoverPrivateKey) (*types.SignRecoverKeyReply, error) {
	c.LoggerDebug(logger, "SignRecoverKey "+c.PrettyPrint(in))

	unprotoDestinationEWalletIDVShareBind := c.UnprotoizeVShareBindData(in.DestinationEWalletIDVShareBind)
	privK := s.getSSPrivK(unprotoDestinationEWalletIDVShareBind.GetSSIntervalPubKID())
	if privK != "" {
		var dstEWalletID types.EncryptableSignRecoverKeyEWalletID
		err := c.VShareBDecryptAndProtoUnmarshal(privK, s.getPubK(unprotoDestinationEWalletIDVShareBind.GetSSIntervalPubKID()), unprotoDestinationEWalletIDVShareBind, in.EncDestinationEWalletIDVShare, &dstEWalletID)
		if err != nil {
			return nil, err
		}

		c.LoggerDebug(logger, "SignRecoverKey: dstEWalletID "+c.PrettyPrint(dstEWalletID))

		recoverKey, found := s.getRecoverKeyByOriginalWalletID(dstEWalletID.WalletID)

		if !found {
			c.LoggerDebug(logger, "SignRecoverKey: Couldn't find recover key "+dstEWalletID.WalletID)
			return nil, types.ErrInvalidSignRecoverKey
		}

		c.LoggerDebug(logger, "SignRecoverKey: recoverKey "+c.PrettyPrint(recoverKey))

		protectKey, found := s.getProtectKey(dstEWalletID.WalletID)

		if !found {
			c.LoggerDebug(logger, "SignRecoverKey: Couldn't find protect key "+dstEWalletID.WalletID)
			return nil, types.ErrInvalidSignRecoverKey
		}

		c.LoggerDebug(logger, "SignRecoverKey: protectKey "+c.PrettyPrint(protectKey))

		// find the canonical name of the signer
		var signerName string
		for _, recoverShare := range protectKey.RecoverShare {
			// check if recoverShare.WalletID is a bech32 address
			if !c.IsBech32Address(recoverShare.WalletID) {
				walletID, _, foundPioneerID := s.getIntervalPublicKeyId(recoverShare.WalletID, types.PioneerNodeType)
				if foundPioneerID {
					// it's a canonical name
					if walletID == in.Creator {
						signerName = recoverShare.WalletID
						break
					}
				} else {
					// check if service provider
					walletID, _, foundServiceProviderID := s.getIntervalPublicKeyId(recoverShare.WalletID, types.ServiceProviderNodeType)
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
	c.LoggerDebug(logger, "RecoverKey "+c.PrettyPrint(in))

	if in.CredentialType == types.PersonalInfoCredentialType && in.WalletID != "" {
		c.LoggerDebug(logger, "recovering key wallet ID "+in.WalletID)
		c.LoggerDebug(logger, "recovering key credential ID "+in.CredentialID)
		unprotoCredentialHashVShareBind := c.UnprotoizeVShareBindData(in.CredentialHashVShareBind)
		credentialHashPrivK := s.getSSPrivK(unprotoCredentialHashVShareBind.GetSSIntervalPubKID())
		if credentialHashPrivK != "" {
			var credentialHash types.EncryptableString
			err := c.VShareBDecryptAndProtoUnmarshal(credentialHashPrivK, s.getPubK(unprotoCredentialHashVShareBind.GetSSIntervalPubKID()), unprotoCredentialHashVShareBind, in.EncCredentialHashVShare, &credentialHash)
			if err == nil {
				c.LoggerDebug(logger, "credentialHash "+credentialHash.Value)
				credential, exists := s.getCredentialByHash(credentialHash.Value)
				if exists {
					c.LoggerError(logger, "credential hash exists "+credentialHash.Value)
					c.LoggerDebug(logger, "credential ID "+credential.CredentialID)
					c.LoggerDebug(logger, "credential's wallet ID "+credential.WalletID)
					subWalletID, found := s.getProtectSubWalletIDByOriginalWalletID(credential.WalletID)
					c.LoggerDebug(logger, "sub wallet ID "+subWalletID)
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

					// update the credential used to find the
					newCredential, exists := s.getCredential(in.CredentialID, in.CredentialType)
					if exists {
						newCredential.WalletID = "RECOVERKEY"
						c.LoggerDebug(logger, "Setting WalletID to RECOVERKEY")
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
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalOwnersKeyPrefix))

	b := store.Get(EnclaveKeyKey(
		pubKID))

	var ownersArray types.EncryptablePioneerIDs
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find owners "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &ownersArray)

		c.LoggerDebug(logger, "ownersArray "+c.PrettyPrint(ownersArray))
		found = true
		owners = ownersArray
	}

	return
}

func (s *qadenaServer) getAllOwners() (ownersMap *types.EncryptableEnclaveSSOwnerMap) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalOwnersKeyPrefix))

	ownersMap = new(types.EncryptableEnclaveSSOwnerMap)
	// init Pioneers
	ownersMap.Pioneers = make(map[string]*types.EncryptablePioneerIDs)

	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		fixedKey := string(itr.Key()[:len(itr.Key())-1])
		c.LoggerDebug(logger, "key "+fixedKey)
		var found bool
		owners, found := s.getOwners(fixedKey)
		if !found {
			c.LoggerDebug(logger, "couldn't find in owners db")
		} else {
			ownersMap.Pioneers[fixedKey] = &owners
		}
		itr.Next()
	}
	itr.Close()

	return
}

func (s *qadenaServer) getShare(pubKID string) (share string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalSharesKeyPrefix))

	b := store.Get(s.MustSealStable(EnclaveKeyKey(pubKID)))

	var shareString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find share "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(s.MustUnseal(b), &shareString)

		c.LoggerDebug(logger, "shareString "+c.PrettyPrint(shareString))
		found = true
		share = shareString.GetS()
	}

	return
}

func (s *qadenaServer) setAllOwners(ownersMap *types.EncryptableEnclaveSSOwnerMap) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalOwnersKeyPrefix))
	for key, value := range ownersMap.Pioneers {
		ownerArray := value
		b := s.Cdc.MustMarshal(ownerArray)
		store.Set(EnclaveKeyKey(key), b)
	}
}

func (s *qadenaServer) setOwnersAndShare(pubKID string, owners []string, share string) {
	c.LoggerDebug(logger, "setOwnersAndShare", pubKID, c.PrettyPrint(owners))
	ownerArray := types.EnclaveStoreStringArray{A: owners}
	shareString := types.EnclaveStoreString{S: share}
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalOwnersKeyPrefix))
	b := s.Cdc.MustMarshal(&ownerArray)
	store.Set(EnclaveKeyKey(pubKID), b)
	store = prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalSharesKeyPrefix))
	b = s.Cdc.MustMarshal(&shareString)
	store.Set(s.MustSealStable(EnclaveKeyKey(pubKID)), s.MustSeal(b))
}

func (s *qadenaServer) SetPublicKey(ctx context.Context, in *types.PublicKey) (*types.SetPublicKeyReply, error) {
	c.LoggerDebug(logger, "SetPublicKey "+c.PrettyPrint(in))

	s.setPublicKeyNoNotify(*in)
	p, _ := s.getPublicKey(in.PubKID, in.PubKType)
	c.LoggerDebug(logger, "get public key "+p)

	owners := make([]string, 0)
	var myShare string
	for _, share := range in.Shares {
		owners = append(owners, share.PioneerID)
		if share.PioneerID == s.getPrivateEnclaveParamsPioneerID() {
			c.LoggerDebug(logger, "received a share "+c.PrettyPrint(share))
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

		c.LoggerDebug(logger, "publicKey "+c.PrettyPrint(pk))
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
	store.Set(types.PublicKeyKey(in.PubKID, in.PubKType), b)
}

func (s *qadenaServer) getIntervalPublicKeyId(nodeID string, nodeType string) (keyID string, serviceProviderType string, found bool) {
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
		// remove the old one by PubKID, so we don't keep growing the kvstore
		storeByPubKID.Delete(types.IntervalPublicKeyIDByPubKIDKey(in.PubKID))
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
	c.LoggerDebug(logger, "SetSecretSharePrivateKey "+c.PrettyPrint(in))
	var ssIDAndPrivK types.EncryptableSSIDAndPrivK

	_, err := c.BDecryptAndProtoUnmarshal(s.getPrivateEnclaveParamsEnclavePrivK(), in.EncEnclaveSSIDAndPrivK, &ssIDAndPrivK)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt")
		return nil, err
	}

	c.LoggerDebug(logger, "SetSecretSharePrivateKey ssIDAndPrivK "+c.PrettyPrint(ssIDAndPrivK))

	s.setPrivKCache(ssIDAndPrivK.PubKID, ssIDAndPrivK.PrivK)
	s.setPubKCache(ssIDAndPrivK.PubKID, ssIDAndPrivK.PubK)

	return &types.SetSecretSharePrivateKeyReply{Status: true}, nil
}

func (s *qadenaServer) setPrivKCache(pubKID string, privK string) {
	privKString := types.EnclaveStoreString{S: privK}
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalPrivKKeyPrefix))
	b := s.Cdc.MustMarshal(&privKString)
	key := s.MustSealStable(EnclaveKeyKey(pubKID))
	c.LoggerDebug(logger, "setPrivkCache key "+hex.EncodeToString(key))
	store.Set(key, s.MustSeal(b))
	c.LoggerDebug(logger, "setPrivkCache "+pubKID)
}

func (s *qadenaServer) removePrivKCache(pubKID string) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalPrivKKeyPrefix))
	store.Delete(s.MustSealStable(EnclaveKeyKey(pubKID)))
}

func (s *qadenaServer) getPrivKCache(pubKID string) (privK string, found bool) {
	c.LoggerDebug(logger, "getPrivKCache "+pubKID)
	if pubKID == "" {
		return "", false
	}

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalPrivKKeyPrefix))

	key := s.MustSealStable(EnclaveKeyKey(pubKID))
	c.LoggerDebug(logger, "getPrivKCache key "+hex.EncodeToString(key))
	b := store.Get(key)

	var privKString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find privk "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(s.MustUnseal(b), &privKString)

		c.LoggerDebug(logger, "privKString "+c.PrettyPrint(privKString))
		found = true
		privK = privKString.GetS()
	}

	return
}

func (s *qadenaServer) setPubKCache(pubKID string, pubK string) {
	pubKString := types.EnclaveStoreString{S: pubK}
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalPubKKeyPrefix))
	b := s.Cdc.MustMarshal(&pubKString)
	store.Set(EnclaveKeyKey(pubKID), b)
}

func (s *qadenaServer) getPubKCache(pubKID string) (pubK string, found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalPubKKeyPrefix))

	b := store.Get(EnclaveKeyKey(
		pubKID))

	var pubKString types.EnclaveStoreString
	if b == nil {
		c.LoggerDebug(logger, "Couldn't find pubk "+pubKID)
		found = false
	} else {
		s.Cdc.MustUnmarshal(b, &pubKString)

		c.LoggerDebug(logger, "pubKString "+c.PrettyPrint(pubKString))
		found = true
		pubK = pubKString.GetS()
	}

	return
}

func (s *qadenaServer) setAllPubKCache(pubKCacheMap EnclavePubKCacheMap) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveSSIntervalPubKKeyPrefix))
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
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialPCXYKeyPrefix))

	credentialPCXY := credential.FindCredentialPedersenCommit.C.Compressed

	b := store.Get(EnclaveKeyBKeyCredentialType(credentialPCXY, credential.CredentialType))

	if b == nil {
		return false
	}

	return true
}

func (s *qadenaServer) setCredentialByPCXY(credential *types.Credential) {
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
	credentialPCXY := credential.FindCredentialPedersenCommit.C.Compressed
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveCredentialPCXYKeyPrefix))
	store.Delete(EnclaveKeyBKeyCredentialType(credentialPCXY, credential.CredentialType))
	c.LoggerDebug(logger, "Removed credentialByPCXY", hex.EncodeToString(credentialPCXY), credential.CredentialType)
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
	store.Set(types.JarRegulatorKey(in.JarID), b)
}

func (s *qadenaServer) setPioneerJarNoNotify(in types.PioneerJar) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.PioneerJarKeyPrefix))

	b := s.Cdc.MustMarshal(&in)
	store.Set(types.PioneerJarKey(in.JarID), b)
}

func (s *qadenaServer) validateEnclaveIdentities() {
	// get the unvalidated identities
	unvalidated := s.getUnvalidatedEnclaveIdentities()
	c.LoggerDebug(logger, "unvalidateEnclaveIdentities "+c.PrettyPrint(unvalidated))
	// validate the identities
	pioneers := s.getAllPioneers()
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

			res, err := queryClient.EnclaveValidateEnclaveIdentity(context.Background(), params)
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
				c.LoggerError(logger, "remote report unverified")
				continue
			}

			if res.Status == types.ActiveStatus {
				activeCount++
				if activeCount >= threshold {
					c.LoggerDebug(logger, "enclave identity validated by", pioneer)
					break
				}
			}
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
		} else {
			// mark as inactive
			identity.Status = types.InactiveStatus
			c.LoggerDebug(logger, "enclave identity is INVALID", identity)
		}

		pwalletID, pwalletAddr, _, _, _, err := c.GetAddressByName(clientCtx, s.getPrivateEnclaveParamsPioneerID(), ArmorPassPhrase)
		report, err := s.getRemoteReport(strings.Join([]string{
			identity.UniqueID,
			identity.SignerID,
			identity.ProductID,
			identity.Status,
		}, "|"))
		if err != nil {
			c.LoggerError(logger, "couldn't getRemoteReport "+err.Error())
			continue
		}
		msg := types.NewMsgPioneerUpdateEnclaveIdentity(
			pwalletAddr.String(),
			identity.UniqueID,
			identity.SignerID,
			identity.ProductID,
			identity.Status,
			report,
		)

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
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
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
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	b := s.Cdc.MustMarshal(&arr)
	store.Set(EnclaveKeyKey("unvalidated"), b)
	c.LoggerDebug(logger, "setUnvalidatedEnclaveIdentities "+c.PrettyPrint(arr))
}

func (s *qadenaServer) setEnclaveIdentity(in *types.EnclaveIdentity) {
	c.LoggerDebug(logger, "setEnclaveIdentity "+c.PrettyPrint(in))
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))
	b := s.Cdc.MustMarshal(in)
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

func (s *qadenaServer) getEnclaveIdentity(uniqueID string, signerID string, includeUnvalidated bool) (found bool) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.EnclaveIdentityKeyPrefix))

	b := store.Get(types.EnclaveIdentityKey(
		uniqueID,
	))
	if b == nil {
		return false
	}

	var id types.EnclaveIdentity
	s.Cdc.MustUnmarshal(b, &id)
	if includeUnvalidated {
		return id.SignerID == signerID && id.Status != types.InactiveStatus
	}
	return id.SignerID == signerID && id.Status == types.ActiveStatus
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
	store.Set(types.WalletKey(in.WalletID), b)
}

func (s *qadenaServer) setWallet(in types.Wallet) {
	s.setWalletNoNotify(in)
	s.changedWallets = append(s.changedWallets, in.WalletID)
}

func (s *qadenaServer) setCredentialNoNotify(credID string, credType string, credential types.Credential) {
	//  credKey := CredentialKey{credID, credType}
	//	credentialMap[credKey] = credential

	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.CredentialKeyPrefix))
	b := s.Cdc.MustMarshal(&credential)
	store.Set(types.CredentialKey(
		credID,
		credType,
	), b)
}

func (s *qadenaServer) removeCredentialNoNotify(credID string, credType string) {
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(types.CredentialKeyPrefix))
	store.Delete(types.CredentialKey(
		credID,
		credType,
	))
}

func (s *qadenaServer) setCredential(credID string, credType string, credential types.Credential) {
	s.setCredentialNoNotify(credID, credType, credential)
	credKey := CredentialKey{credID, credType}
	s.changedCredentials = append(s.changedCredentials, credKey)
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

func (s *qadenaServer) getAllAuthorizedSignatories() (arr []types.ValidateAuthorizedSignatoryRequest) {
	arr = make([]types.ValidateAuthorizedSignatoryRequest, 0)
	store := prefix.NewStore(s.CacheCtx.KVStore(s.StoreKey), types.KeyPrefix(EnclaveAuthorizedSignatoryKeyPrefix))
	itr := store.Iterator(nil, nil)
	for itr.Valid() {
		var val types.ValidateAuthorizedSignatoryRequest
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
	store.Set(types.RecoverKeyKey(walletID), b)
}

func (s *qadenaServer) setRecoverKeyByOriginalWalletID(walletID string, in *types.RecoverKey) {
	s.setRecoverKeyByOriginalWalletIDNoNotify(walletID, in)
	s.changedRecoverKeys = append(s.changedRecoverKeys, walletID)
}

// called from various Qadena MsgServer
func (s *qadenaServer) enclaveGetIntervalPublicKey(intervalNodeID string, intervalNodeType string) (pubKID string, pubK string, serviceProviderType string, err error) {
	// find the interval ss pubk
	intervalPubKID, spType, found := s.getIntervalPublicKeyId(intervalNodeID, intervalNodeType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	intervalPubK, found := s.getPublicKey(intervalPubKID, types.TransactionPubKType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
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
		ssIntervalPubKID, ssIntervalPubK, _, err := s.enclaveGetIntervalPublicKey(types.SSNodeID, types.SSNodeType)

		if err != nil {
			c.LoggerError(logger, "Couldn't get interval public key")
			return nil, err
		}

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     ssIntervalPubK,
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

		jarIntervalPubKID, jarIntervalPubK, _, err := s.enclaveGetIntervalPublicKey(jarID, types.JarNodeType)

		if err != nil {
			c.LoggerError(logger, "Couldn't get jar interval public key", jarID, types.JarNodeType)
			return nil, err
		}

		c.LoggerDebug(logger, "jarIntervalPubKID", jarIntervalPubKID, "jarIntervalPubK", jarIntervalPubK)

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     jarIntervalPubK,
			NodeID:   jarID,
			NodeType: types.JarNodeType,
		})
	}

	return ccPubK, nil
}

// find any service providers that are optional
func (s *qadenaServer) enclaveAppendOptionalServiceProvidersCCPubK(ccPubK []c.VSharePubKInfo, serviceProviderID []string, optionalServiceProviderType []string) ([]c.VSharePubKInfo, error) {
	for i := range serviceProviderID {
		_, pubK, serviceProviderType, err := s.enclaveGetIntervalPublicKey(serviceProviderID[i], types.ServiceProviderNodeType)
		if err != nil {
			c.LoggerError(logger, "Couldn't get service provider interval public key", serviceProviderID[i], types.ServiceProviderNodeType)
			return nil, err
		}

		// check if serviceProviderType is in array requiredServiceProviderType
		for j := range optionalServiceProviderType {
			if serviceProviderType == optionalServiceProviderType[j] {
				ccPubK = append(ccPubK, c.VSharePubKInfo{
					PubK:     pubK,
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

	wallets := []*types.Wallet{}

	for _, changedWallet := range s.changedWallets {
		c.LoggerDebug(logger, "Wallet changed "+changedWallet)
		wallet, found := s.getWallet(changedWallet)
		if found {
			wallets = append(wallets, &wallet)
		}
	}

	if in.Clear && len(wallets) > 0 {
		c.LoggerDebug(logger, "Clearing s.changedWallets")
		s.changedWallets = nil
	}

	return &types.SyncWalletsReply{Wallets: wallets}, nil
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

	credentials := []*types.Credential{}

	for _, changedCredential := range s.changedCredentials {
		c.LoggerDebug(logger, "Credential changed "+c.PrettyPrint(changedCredential))
		credential, found := s.getCredential(changedCredential.credentialID, changedCredential.credentialType)
		if found {
			credentials = append(credentials, &credential)
		}
	}

	if in.Clear && len(credentials) > 0 {
		c.LoggerDebug(logger, "Clearing changedCredentials")
		s.changedCredentials = nil
	}

	return &types.SyncCredentialsReply{Credentials: credentials}, nil
}

func (s *qadenaServer) SyncRecoverKeys(ctx context.Context, in *types.MsgSyncRecoverKeys) (*types.SyncRecoverKeysReply, error) {
	//  c.LoggerDebug(logger, "SyncRecoverKeys " + c.PrettyPrint(in))

	recoverKeys := []*types.RecoverKey{}

	for _, changedRecoverKey := range s.changedRecoverKeys {
		c.LoggerDebug(logger, "RecoverKey changed "+changedRecoverKey)
		recoverKey, found := s.getRecoverKeyByOriginalWalletID(changedRecoverKey)
		if found {
			recoverKeys = append(recoverKeys, &recoverKey)
		}
	}

	//  c.LoggerDebug(logger, "changed " + c.PrettyPrint(recoverKeys))

	if in.Clear && len(recoverKeys) > 0 {
		c.LoggerDebug(logger, "Clearing changedRecoverKeys")
		s.changedRecoverKeys = nil
	}

	return &types.SyncRecoverKeysReply{RecoverKeys: recoverKeys}, nil
}

func (s *qadenaServer) SyncSuspiciousTransactions(ctx context.Context, in *types.MsgSyncSuspiciousTransactions) (*types.SyncSuspiciousTransactionsReply, error) {
	c.LoggerDebug(logger, "SyncSuspiciousTransactions "+c.PrettyPrint(in))

	// display count of new suspicious transactions

	c.LoggerDebug(logger, "# newSuspiciousTransactions "+strconv.Itoa(len(s.newSuspiciousTransactions)))

	suspiciousTransactions := []*types.SuspiciousTransaction{}

	for _, newSuspiciousTransaction := range s.newSuspiciousTransactions {
		suspiciousTransactions = append(suspiciousTransactions, &newSuspiciousTransaction)
	}

	if in.Clear && len(s.newSuspiciousTransactions) > 0 {
		c.LoggerDebug(logger, "Clearing newSuspiciousTransactions")
		s.newSuspiciousTransactions = nil
	}

	return &types.SyncSuspiciousTransactionsReply{SuspiciousTransactions: suspiciousTransactions}, nil
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

				c.LoggerDebug(logger, "extra parms "+c.PrettyPrint(cwExtraParms))
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

	c.LoggerDebug(logger, "extra parms "+c.PrettyPrint(tfExtraParms))

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
		// store the "zero" in our queue
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

	} else if dstWallet.EphemeralWalletAmountCount[token] == 1 {
		dstWallet.QueuedWalletAmount[token].WalletAmounts = append(
			dstWallet.QueuedWalletAmount[token].WalletAmounts,
			&wa,
		)

	} else {
		// >= 1
		// put the new value so that it comes out last
		queuedWalletAmounts := dstWallet.QueuedWalletAmount[token].WalletAmounts

		/*
			dstWallet.QueuedWalletAmount[token].WalletAmounts = append(
				queuedWalletAmounts[:len(queuedWalletAmounts)-1],
				&wa,
				queuedWalletAmounts[len(queuedWalletAmounts)-1],
			)
		*/
		dstWallet.QueuedWalletAmount[token].WalletAmounts = append(
			queuedWalletAmounts,
			&wa,
		)
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

func (s *qadenaServer) createSuspiciousTransaction(ctx context.Context, reason string, jarID string, tf c.TransferFunds, optInReason string) {
	regulatorID, found := s.getJarRegulator(jarID)

	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find regulator ID for jar", jarID)
		return
	}

	regulatorPubKID, _, found := s.getIntervalPublicKeyId(regulatorID, types.RegulatorNodeType)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find regulator pubkid for regulator ID", regulatorID)
		return
	}

	regulatorPubK, found := s.getPublicKey(regulatorPubKID, types.CredentialPubKType)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find regulator pubk for regulator pubKID", regulatorPubKID)
		return
	}

	c.LoggerDebug(logger, "regulatorPubK", regulatorPubK)

	// no secret sharing for now, decode the credentials

	srcWallet, found := s.getWallet(tf.SourceWalletID)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find source wallet", tf.SourceWalletID)
		return
	}
	dstWallet, found := s.getWallet(tf.DestinationWalletID)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find destination wallet", tf.DestinationWalletID)
		return
	}

	srcCredential, found := s.getCredential(srcWallet.CredentialID, types.PersonalInfoCredentialType)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find source credential", srcWallet.CredentialID)
		return
	}

	dstCredential, found := s.getCredential(dstWallet.CredentialID, types.PersonalInfoCredentialType)
	if !found {
		c.LoggerError(logger, "BAD!  Couldn't find destination credential", dstWallet.CredentialID)
		return
	}

	unprotoCredentialInfoVShareBind := c.UnprotoizeVShareBindData(srcCredential.CredentialInfoVShareBind)
	var srcPI types.EncryptablePersonalInfo
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, srcCredential.EncCredentialInfoVShare, &srcPI)
	if err != nil {
		c.LoggerError(logger, "couldn't get decrypt source credential", srcWallet.CredentialID)
		return
	}

	unprotoCredentialInfoVShareBind = c.UnprotoizeVShareBindData(dstCredential.CredentialInfoVShareBind)
	var dstPI types.EncryptablePersonalInfo
	err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, dstCredential.EncCredentialInfoVShare, &dstPI)
	if err != nil {
		c.LoggerError(logger, "couldn't get decrypt destination credential", dstWallet.CredentialID)
		return
	}

	//	srcPI.PIN = ""
	//	dstPI.PIN = ""

	c.LoggerDebug(logger, "src personal info "+c.PrettyPrint(srcPI))
	c.LoggerDebug(logger, "dst personal info "+c.PrettyPrint(dstPI))

	var eSuspiciousAmount types.EncryptableESuspiciousAmount
	eSuspiciousAmount.Nonce = srcPI.Nonce + "/" + dstPI.Nonce
	eSuspiciousAmount.USDCoinAmount = &tf.USDCoinAmount
	eSuspiciousAmount.CoinAmount = &tf.CoinAmount

	var st = types.SuspiciousTransaction{JarID: jarID,
		RegulatorPubKID:                         regulatorPubKID,
		Reason:                                  reason,
		Time:                                    tf.Time,
		EncSourcePersonalInfoRegulatorPubK:      c.ProtoMarshalAndBEncrypt(regulatorPubK, &srcPI),
		EncDestinationPersonalInfoRegulatorPubK: c.ProtoMarshalAndBEncrypt(regulatorPubK, &dstPI),
		EncEAmountRegulatorPubK:                 c.ProtoMarshalAndBEncrypt(regulatorPubK, &eSuspiciousAmount),
		EncOptInReasonRegulatorPubK:             c.MarshalAndBEncrypt(regulatorPubK, optInReason),
	}
	s.newSuspiciousTransactions = append(s.newSuspiciousTransactions, st)
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

	c.LoggerDebug(logger, "EncWalletVShare: ")

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

	tf := c.TransferFunds{Time: st.Timestamp, SourceWalletID: msg.Creator, DestinationWalletID: dstWalletID.WalletID, USDCoinAmount: usdCoinAmount, CoinAmount: coinAmount}

	c.LoggerDebug(logger, "time "+tf.Time.String()+" src "+tf.SourceWalletID+" dst "+tf.DestinationWalletID+" amount "+tf.CoinAmount.String())

	// 1.  store each transaction map per source (appending to an array)
	if s.transactionMap[tf.SourceWalletID] == nil {
		t := make([]*c.TransferFunds, 0)
		s.transactionMap[tf.SourceWalletID] = t
	}

	c.LoggerDebug(logger, "suspicious threshold "+s.coinSuspiciousAmount.String())

	// 2.  run simple logic for now

	// 2a.  Check transaction for "too large"
	if tf.USDCoinAmount.IsGTE(s.coinSuspiciousAmount) {
		c.LoggerDebug(logger, "suspicious individual transaction "+tf.USDCoinAmount.String()+" "+tf.CoinAmount.String()+" "+tf.SourceWalletID+" "+tf.DestinationWalletID)
		if optInReason != "" {
			s.createSuspiciousTransaction(ctx, "Transaction value >= 10k", unprotoMsgTransferFundsVShareBind.GetJarID(), tf, optInReason)
			return &types.ScanTransactionReply{Status: true}, nil
		} else {
			return nil, types.ErrGenericScan
		}
	}

	s.transactionMap[tf.SourceWalletID] = append(s.transactionMap[tf.SourceWalletID], &tf)

	// 2b.  Check accumulated exit for "too large"
	srcWalletID := tf.SourceWalletID

	c.LoggerDebug(logger, "src wallet "+srcWalletID+" "+strconv.Itoa(len(s.transactionMap[srcWalletID])))
	c.LoggerDebug(logger, "srcWalletID transactions "+c.PrettyPrint(s.transactionMap[srcWalletID]))

	var usdValueMap map[string]sdk.Coin = make(map[string]sdk.Coin)
	var valueMap map[string]sdk.Coin = make(map[string]sdk.Coin)

	// NOTE THIS ALGORITHM DOES NOT HANDLE SLIDING WINDOW OF TIME (e.g. it should only check the last month of transactions)
	for _, tmpTF := range s.transactionMap[srcWalletID] {
		c.LoggerDebug(logger, "dst wallet "+tmpTF.DestinationWalletID+" amount "+tmpTF.USDCoinAmount.String())
		usdv, found := usdValueMap[tmpTF.DestinationWalletID]
		if !found {
			usdv = sdk.NewCoin(types.AttoUSDFiatDenom, math.NewInt(0))
		}
		usdValueMap[tmpTF.DestinationWalletID] = usdv.Add(tmpTF.USDCoinAmount)

		v, found := valueMap[tmpTF.DestinationWalletID]
		if !found {
			v = sdk.NewCoin(tmpTF.CoinAmount.Denom, math.NewInt(0))
		}
		valueMap[tmpTF.DestinationWalletID] = v.Add(tmpTF.CoinAmount)
	}

	for dstWalletID, v := range usdValueMap {
		c.LoggerDebug(logger, "aggregate total "+dstWalletID+" "+v.String())
		if v.IsGTE(s.coinSuspiciousAmount) {
			c.LoggerDebug(logger, "suspicious aggregate total "+tf.SourceWalletID+" "+dstWalletID+" "+v.String())
			tf := c.TransferFunds{Time: st.Timestamp, SourceWalletID: tf.SourceWalletID, DestinationWalletID: dstWalletID, USDCoinAmount: v, CoinAmount: valueMap[dstWalletID]}

			if optInReason != "" {
				// erase all transactions to that destination from TransactionMap

				newTFs := make([]*c.TransferFunds, 0)
				for _, tmpTF := range s.transactionMap[srcWalletID] {
					if tmpTF.DestinationWalletID != dstWalletID {
						newTFs = append(newTFs, tmpTF)
					}
				}
				s.transactionMap[srcWalletID] = newTFs

				s.createSuspiciousTransaction(ctx, "Total transaction value >= 10k", unprotoMsgTransferFundsVShareBind.GetJarID(), tf, optInReason)
			} else {
				return nil, types.ErrGenericScan
			}
		}
	}

	return &types.ScanTransactionReply{Status: true}, nil
}

func (s *qadenaServer) GetStoreHash(ctx context.Context, gsh *types.MsgGetStoreHash) (*types.GetStoreHashReply, error) {
	c.LoggerDebug(logger, "GetStoreHash")

	s.commitCache()

	storeHashes := []*types.StoreHash{}

	keys := []string{types.WalletKeyPrefix, types.CredentialKeyPrefix, types.JarRegulatorKeyPrefix, types.PublicKeyKeyPrefix, types.IntervalPublicKeyIDKeyPrefix, types.ProtectKeyKeyPrefix, types.RecoverKeyKeyPrefix}

	for _, k := range keys {
		var sh types.StoreHash
		h := c.StoreHashByStoreKey(s.ServerCtx, s.StoreKey, k)
		c.LoggerDebug(logger, "key "+k+" hash "+h)
		sh.Key = k
		sh.Hash = h

		storeHashes = append(storeHashes, &sh)
	}

	return &types.GetStoreHashReply{Hashes: storeHashes}, nil
}

func (s *qadenaServer) TransactionComplete(ctx context.Context, tc *types.MsgTransactionComplete) (*types.TransactionCompleteReply, error) {
	c.LoggerDebug(logger, "transaction complete "+strconv.FormatBool(tc.Success))

	if tc.Success {
		c.LoggerDebug(logger, "CacheCtx.Write")
		s.CacheCtxWrite()
	} else {
		c.LoggerDebug(logger, "Rollback CacheContext")
		s.CacheCtx, s.CacheCtxWrite = s.ServerCtx.CacheContext()
	}

	return &types.TransactionCompleteReply{Status: true}, nil
}

func (s *qadenaServer) commitCache() {
	c.LoggerDebug(logger, "commitCache")

	if s.CacheCtxWrite != nil {
		s.CacheCtxWrite()
	}
}

func (s *qadenaServer) EndBlock(ctx context.Context, tc *types.MsgEndBlock) (*types.EndBlockReply, error) {
	//	c.LoggerDebug(logger, "end block")

	//  c.LoggerDebug(logger, "CacheCtx.Write")
	s.commitCache()

	cms, ok := s.ServerCtx.MultiStore().(storetypes.CommitMultiStore)

	if ok {
		//    qadenaStore := cms.GetCommitKVStore(s.StoreKey)

		lastCommitID := cms.LastCommitID()
		commitID := cms.Commit()
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

	} else {
		c.LoggerError(logger, "Couldn't cast multistore to commitstore")
	}

	return &types.EndBlockReply{}, nil
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

	enclaveUpgradeModeArg := flag.Bool("upgrade-mode", false, "Enclave upgrade mode")
	upgradeFromEnclave := flag.String("upgrade-from-enclave-unique-id", "", "Unique ID of old enclave running on this node")

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
			c.LoggerDebug(logger, "Error creating enclave_config directory")
			return
		}
	}

	var db *tmdb.GoLevelDB

	if *upgradeFromEnclave != "" || enclaveUpgradeMode {
		var opts tmdbopt.Options
		opts.ReadOnly = true
		db, err = tmdb.NewGoLevelDBWithOpts("enclave", *homePath+"/enclave_data", &opts)
		if err != nil {
			c.LoggerDebug(logger, "Error creating read-only GoLevelDB", err)
			return
		}
	} else {
		db, err = tmdb.NewGoLevelDB("enclave", *homePath+"/enclave_data", nil)
		if err != nil {
			c.LoggerDebug(logger, "Error creating GoLevelDB")
			return
		}
	}

	stateStore := store.NewCommitMultiStore(db, cosmossdkiolog.NewNopLogger(), storemetrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	//	stateStore.MountStoreWithDB(memStoreKey, sdk.StoreTypeMemory, nil)

	serverCtx := sdk.NewContext(stateStore, tmproto.Header{}, false, logger)

	registry := codectypes.NewInterfaceRegistry()
	cdc := amino.NewProtoCodec(registry)

	stateStore.LoadLatestVersion()

	cacheCtx, cacheCtxWrite := serverCtx.CacheContext()

	cs := qadenaServer{
		StoreKey:      storeKey,
		ServerCtx:     serverCtx,
		CacheCtx:      cacheCtx,
		CacheCtxWrite: cacheCtxWrite,
		Cdc:           cdc,
		HomePath:      *homePath,
		RealEnclave:   *realEnclave,
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

		_, _, tmpPubK, tmpPrivK, _, err := c.GetAddressByName(clientCtx, types.EnclaveKeyringName, ArmorPassPhrase)
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

		if !cs.verifyRemoteReport(
			res.GetRemoteReport(),
			strings.Join([]string{
				string(res.GetEncEnclavePrivateStateEnclavePubK()),
			}, "|")) {
			c.LoggerError(logger, "remote report unverified")
			os.Exit(10)
		} else {
			c.LoggerDebug(logger, "remote report verified")
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

	cs.changedWallets = make([]string, 0)
	cs.newSuspiciousTransactions = make([]types.SuspiciousTransaction, 0)
	cs.transactionMap = make(map[string]c.Transactions)

	cs.coinSuspiciousAmount, _ = sdk.ParseCoinNormalized(c.SuspiciousThreshold)
	if cs.coinSuspiciousAmount.Denom == types.USDFiatDenom {
		displayAmount := cs.coinSuspiciousAmount.Amount
		cs.coinSuspiciousAmount = sdk.NewCoin(types.AttoUSDFiatDenom, displayAmount.Mul(math.NewIntFromBigInt(c.GetDenomAtomicFactor(18))))
	}

	if !cs.loadEnclaveParams() {
		c.LoggerInfo(logger, "Enclave params could not be loaded, but this is ok if the enclave has not yet been initialized.")
	}

	var lis net.Listener

	if SupportsUnixDomainSockets {
		var err error

		// delete file if it exists
		os.Remove(fmt.Sprintf("/tmp/qadena_%d.sock", *port))

		// listen on a unix domain socket
		lis, err = net.Listen("unix", fmt.Sprintf("/tmp/qadena_%d.sock", *port))

		if err != nil {
			c.LoggerError(logger, "failed to listen: "+err.Error())
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
