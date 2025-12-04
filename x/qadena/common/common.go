package common

import (
	"fmt"
	"strconv"
	time "time"

	//"github.com/rs/zerolog"

	"math/rand"

	"github.com/cometbft/cometbft/crypto/tmhash"

	//	"github.com/cometbft/cometbft/libs/log"
	"cosmossdk.io/log"

	//	"bytes"
	"encoding/hex"
	"encoding/json"

	//	"net/http"
	"strings"
	//  "time"
	//	"os"
	//  "io"
	"encoding/base64"
	//	"io/ioutil"

	"context"

	"errors"

	"crypto/sha256"
	"math/big"

	"sort"

	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	//	codectypes "github.com/cosmos/cosmos-sdk/codec/types"

	dsvstypes "github.com/c3qtech/qadena_v3/x/dsvs/types"
	nstypes "github.com/c3qtech/qadena_v3/x/nameservice/types"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/cosmos-sdk/client"

	//	"github.com/fomichev/secp256k1"

	//	ethhd "github.com/tharsis/ethermint/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	sdkcryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdktypes "github.com/cosmos/cosmos-sdk/types"
	bip39 "github.com/cosmos/go-bip39"

	//	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	ethcommon "github.com/ethereum/go-ethereum/common"

	"cosmossdk.io/core/store"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	//	"github.com/spf13/cobra"
)

var EnclaveAddr string
var EnclaveSignerID string
var EnclaveUniqueID string

type PubKeyStruct struct {
	Type string `json:"@type"`
	Key  string `json:"key"`
}

type StringHolder struct {
	S string
}

func (sh *StringHolder) Set(s string) {
	sh.S = s
}

func (sh *StringHolder) Get() string {
	return sh.S
}

type UInt64Holder struct {
	V uint64
}

func (ih *UInt64Holder) Set(v uint64) {
	ih.V = v
}

func (ih *UInt64Holder) Get() uint64 {
	return ih.V
}

var BigIntZero *big.Int = big.NewInt(0)
var SuspiciousThreshold = "10000usd"

var Seed = rand.NewSource(time.Now().UnixNano())
var Random = rand.New(Seed)

var Debug bool = false
var DebugFull bool = false

// if this is enabled, you can see the encrypted values -- this is good for debugging
var TextBasedEncrypt = false

var DebugTimeout int64 = 2

var DebugAmounts = false

func RedText(text string) string {
	return "\u001B[31m" + text + "\u001B[0m"
}

func GreenText(text string) string {
	return "\u001B[32m" + text + "\u001B[0m"
}

func BlueText(text string) string {
	return "\u001B[34m" + text + "\u001B[0m"
}

func YellowText(text string) string {
	return "\u001B[33m" + text + "\u001B[0m"
}

func WhiteUnderlineText(text string) string {
	return "\u001B[4;37m" + text + "\u001B[0m"
}

func TruncateText(s string, max int) string {
	return s[:max]
}

func Hash(s string) string {
	var r string
	if TextBasedEncrypt {
		r = "Hash(" + s + ")"
	} else {
		r = hex.EncodeToString(tmhash.Sum([]byte(s)))
	}
	return r
}

func StoreHashByKVStoreService(ctx sdktypes.Context, storeService store.KVStoreService, p string) string {
	storeAdapter := runtime.KVStoreAdapter(storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(p))

	ret, count := StoreHashByPrefixStore(ctx, store)
	ContextDebug(ctx, "StoreHashByKVStoreService", p, count, ret)
	return ret
}

func StoreHashByStoreKey(ctx sdktypes.Context, storeKey storetypes.StoreKey, p string) string {
	store := prefix.NewStore(ctx.KVStore(storeKey), types.KeyPrefix(p))

	ret, count := StoreHashByPrefixStore(ctx, store)
	ContextDebug(ctx, "StoreHashByStoreKey", p, count, ret)
	return ret
}

func CreateCredentialHash(pd *types.EncryptablePersonalInfoDetails) string {
	firstMiddleLast := pd.LastName + "," + pd.MiddleName + "," + pd.FirstName
	credentialHash := hex.EncodeToString(tmhash.Sum([]byte(firstMiddleLast + "|" + pd.Birthdate + "|" + pd.Gender)))
	return credentialHash
}

func Nonce() string {
	nonce := strconv.Itoa(Random.Intn(1000))
	return nonce
}

func StoreHashByPrefixStore(ctx sdktypes.Context, prefixStore prefix.Store) (string, int) {
	itr := prefixStore.Iterator(nil, nil)
	h := sha256.New()
	count := 0
	for itr.Valid() {
		///		ContextDebug(ctx, "StoreHashByPrefixStore", string(itr.Key()), string(itr.Value()))
		h.Write(itr.Key())
		h.Write(itr.Value())
		itr.Next()
		count++
	}
	itr.Close()
	return hex.EncodeToString(h.Sum(nil)), count
}

func IsBech32Address(address string) bool {
	_, err := sdktypes.AccAddressFromBech32(address)
	return err == nil
}

func GetAddressByName(ctx client.Context, name string, passphrase string) (walletID string, walletAddr sdktypes.AccAddress, pubK string, privK string, armorPrivK string, err error) {
	var privKHex string
	walletID, _, pubK, privKHex, err = GetAddress(ctx, name)

	if err != nil {
		fmt.Println("couldn't get address for", name, err)
		return
	}

	walletAddr, err = sdktypes.AccAddressFromBech32(walletID)
	if err != nil {
		fmt.Println("couldn't convert to addr", walletID, err)
		return
	}

	privK = privKHex

	armorPrivK, err = ctx.Keyring.ExportPrivKeyArmor(name, passphrase)
	if err != nil {
		fmt.Println("couldn't export key as armor", err)
		return
	}
	return
}

// unsafeExporter is implemented by key stores that support unsafe export
// of private keys' material.
type unsafeExporter interface {
	// ExportPrivateKeyObject returns a private key in unarmored format.
	ExportPrivateKeyObject(uid string) (sdkcryptotypes.PrivKey, error)
}

// unsafeExportPrivKeyHex exports private keys in unarmored hexadecimal format.
func unsafeExportPrivKeyHex(ks unsafeExporter, uid string) (privkey string, err error) {
	priv, err := ks.ExportPrivateKeyObject(uid)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(priv.Bytes()), nil
}

func GetAddress(ctx client.Context, addr string) (string, []byte, string, string, error) {
	kb := ctx.Keyring
	if Debug && DebugFull {
		fmt.Println("GetAddress", addr)
	}
	keyInfo, err := kb.Key(addr)

	// get it by "friendly name" (from the keyring) first
	if err != nil {
		var address sdktypes.Address
		// if not found by "friendly name", let's try to convert it from an eth address
		if ethcommon.IsHexAddress(addr) {
			address, err = sdktypes.AccAddressFromHexUnsafe(addr[2:])
			if err != nil {
				fmt.Println("Couldn't convert from hex format", addr)
				return "", nil, "", "", err
			}
		} else {
			//    fmt.Println("Couldn't find using friendly name", addr)
			// might be a bech32 (COSMOS) address
			address, err = sdktypes.AccAddressFromBech32(addr)
			if err != nil {
				fmt.Println("Couldn't convert from bech32 format", addr)
				return "", nil, "", "", err
			}
		}

		keyInfo, err = kb.KeyByAddress(address)

		if err != nil {
			// it looks at least like a valid bech32 address, let's return
			if Debug {
				fmt.Println("Valid bech32 address, but no other info available", addr)
			}
			return addr, nil, "", "", nil
		}
	}

	keyOut, err := keys.MkAccKeyOutput(keyInfo)

	if err != nil {
		return "", nil, "", "", err
	}

	privKeyHex, err := unsafeExportPrivKeyHex(kb.(unsafeExporter), keyInfo.Name)

	if err != nil {
		return "", nil, "", "", err
	}

	var pubKeyParsed PubKeyStruct
	err = json.Unmarshal([]byte(keyOut.PubKey), &pubKeyParsed)

	if err != nil {
		return "", nil, "", "", err
	}

	if Debug && DebugFull {
		fmt.Println("pubKeyParsed: ", pubKeyParsed)
	}

	pubKey := pubKeyParsed.Key
	pubkbytes, err := base64.StdEncoding.DecodeString(pubKey)

	if err != nil {
		return "", nil, "", "", err
	}

	//	pubkbytes := []byte(pubKeyParsed.Key)

	//pubKey := base64.StdEncoding.EncodeToString(pubkbytes)

	return keyOut.Address, pubkbytes, pubKey, privKeyHex, nil
}

func PrettyPrint(i interface{}) string {
	s, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(s)
}

func ToJson(i interface{}) []byte {
	s, err := json.Marshal(i)
	if err != nil {
		return nil
	}
	return s
}

func DisplayHash(h string) string {
	if h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		h = "*empty*"
	}
	return h
}

func DebugVerifyRemoteReport(logger log.Logger, remoteReportBytes []byte, certifyData string) (success bool, uniqueID string, signerID string) {
	logger.Debug("DebugVerifyRemoteReport " + certifyData)
	hash := sha256.Sum256([]byte(certifyData))

	r := strings.Split(string(remoteReportBytes), ":")
	if len(r) < 5 {
		logger.Debug("couldn't split remote report string")
		return false, "", ""
	}

	if r[0] != "TRUST-ME" {
		logger.Debug("Bad, *NO* TRUST-ME")
		return false, "", ""
	}

	hashString := hex.EncodeToString(hash[:])
	if hashString != r[3] {
		logger.Debug("Hash not matching " + r[3] + " " + hashString)
		return false, "", ""
	}
	return true, r[1], r[2]
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func STRNot(str string) string {
	result := ""

	for _, i := range str {
		if i == '0' {
			result += "1"
		} else {
			result += "0"
		}
	}
	return result
}

// used to clean up
func RemovePublicKey(ctx client.Context, friendlyName string) error {
	kb := ctx.Keyring
	err := kb.Delete(friendlyName)
	return err
}

var defaultBIP39Passphrase = ""

// return bip39 seed with empty passphrase
func mnemonicToSeed(mnemonic string) []byte {
	return bip39.NewSeed(mnemonic, defaultBIP39Passphrase)
}

func GenerateNewMnemonic() (string, error) {
	mnemonicEntropySize := 256

	// read entropy seed straight from tmcrypto.Rand and convert to mnemonic
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		return "", err
	}

	return bip39.NewMnemonic(entropySeed)
}

func GetKeyring(ctx client.Context) keyring.Keyring {
	return ctx.Keyring
}

func GetAlgo(kb keyring.Keyring) (keyring.SignatureAlgo, error) {
	keyringAlgos, _ := kb.SupportedAlgorithms()
	if Debug && DebugFull {
		fmt.Println("keyringAlgos", keyringAlgos)
	}
	algoStr := string(keyringAlgos[0].Name())
	if Debug && DebugFull {
		fmt.Println("algoStr", algoStr)
	}
	algo, err := keyring.NewSigningAlgoFromString(algoStr, keyringAlgos)
	if err != nil {
		return nil, err
	}

	return algo, nil
}

func GetBip39PassPhrase() string {
	var bip39Passphrase string
	return bip39Passphrase
}

func GetEphAccountAddress(mnemonic string, bip39Passphrase string, accountType uint32, parsedEphAccountIndex uint32, algo keyring.SignatureAlgo) (sdktypes.AccAddress, error) {
	hdPath := hd.CreateHDPath(sdktypes.GetConfig().GetCoinType(), accountType, uint32(parsedEphAccountIndex)).String()

	// create master key and derive first key for keyring
	derivedPriv, err := algo.Derive()(mnemonic, bip39Passphrase, hdPath)
	if err != nil {
		return nil, err
	}

	privKey := algo.Generate()(derivedPriv)

	address := sdktypes.AccAddress(privKey.PubKey().Address())

	return address, nil
}

func CreatePublicKey(ctx client.Context, req PublicKeyReq) (string, sdktypes.AccAddress, string, string, error) {
	var accountType uint32 = types.TransactionWalletType
	var ephAccountIndex uint32 = req.EphAccountIndex

	// check if the current account creation is transaction or credential
	// 0 - transaction account type
	// 1 - credential account type
	isCredential := strings.Index(req.FriendlyName, "-credential")
	if isCredential >= 0 {
		accountType = types.CredentialWalletType
	}

	kb := GetKeyring(ctx)

	_, err := kb.Key(req.FriendlyName)
	if err == nil {
		fmt.Println("friendly name already exists", req.FriendlyName)
		return "", nil, "", "", errors.New("aborted")
	}

	algo, err := GetAlgo(kb)
	if err != nil {
		return "", nil, "", "", err
	}

	if Debug && DebugFull {
		fmt.Println("coin", sdktypes.GetConfig().GetCoinType())
		fmt.Println("algo", algo)
	}

	mnemonic := req.RecoverMnemonic

	if Debug && DebugFull {
		fmt.Println("mnemonic:", mnemonic)
	}

	var hdPath string
	var bip39Passphrase = GetBip39PassPhrase()

	// m / 44' / coinType' / account' / 0 / address_index
	hdPath = hd.CreateHDPath(sdktypes.GetConfig().GetCoinType(), accountType, ephAccountIndex).String()
	if Debug && DebugFull {
		fmt.Println("hdPath::", hdPath)
	}

	info, err := kb.NewAccount(req.FriendlyName, mnemonic, bip39Passphrase, hdPath, algo)
	if err != nil {
		return "", nil, "", "", err
	}

	out, err := keys.MkAccKeyOutput(info)

	if Debug && DebugFull {
		fmt.Println("out", out)

		fmt.Println("friendly name", out.Name)
		fmt.Println("address", out.Address)
	}
	address, err := info.GetAddress()
	if err != nil {
		return "", nil, "", "", err
	}
	if Debug && DebugFull {
		fmt.Println("GetAddress()", address)
	}
	pubkey, err := info.GetPubKey()
	if err != nil {
		return "", nil, "", "", err
	}
	if Debug && DebugFull {
		fmt.Println("GetBytes() in hex", hex.EncodeToString(pubkey.Bytes()))
		fmt.Println("pubkey", out.PubKey)
	}

	var pubKeyParsed PubKeyStruct

	err = json.Unmarshal([]byte(out.PubKey), &pubKeyParsed)
	if err != nil {
		fmt.Println("unmarshal err", err)
		return "", nil, "", "", err
	}
	if Debug && DebugFull {
		fmt.Println("pubKeyParsed: ", pubKeyParsed)
	}

	from := out.Address
	fromAddr, fromName, _, err := client.GetFromFields(ctx, ctx.Keyring, from)
	if err != nil {
		return "", nil, "", "", err
	}

	return from, fromAddr, fromName, pubKeyParsed.Key, nil
}

func GetWallet(ctx client.Context, walletID string) (types.Wallet, error) {
	queryClient := types.NewQueryClient(ctx)

	if Debug {
		fmt.Println("getWallet", walletID)
	}

	params := &types.QueryGetWalletRequest{
		WalletID: walletID,
	}

	res, err := queryClient.Wallet(context.Background(), params)
	if err != nil {
		if Debug {
			fmt.Println("err", err)
		}
		return types.Wallet{}, err
	}

	return res.Wallet, nil
}

func GetCredential(ctx client.Context, credentialID string, credentialType string) (types.Credential, error) {
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getCredential", credentialID)
	}

	params := &types.QueryGetCredentialRequest{
		CredentialID:   credentialID,
		CredentialType: credentialType,
	}

	res, err := queryClient.Credential(context.Background(), params)
	if err != nil {
		fmt.Println("err", err)
		return types.Credential{}, err
	}

	return res.Credential, nil
}

func GetJarForPioneer(ctx client.Context, pioneerID string) (string, error) {
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getJarForPioneer", pioneerID)
	}

	params := &types.QueryGetPioneerJarRequest{
		PioneerID: pioneerID,
	}

	res, err := queryClient.PioneerJar(context.Background(), params)
	if err != nil {
		fmt.Println("err", err)
		return "", err
	}

	return res.PioneerJar.JarID, nil
}

func FindSubWallet(ctx client.Context, credential string, credentialType string) (string, error) {
	queryClient := nstypes.NewQueryClient(ctx)

	params := &nstypes.QueryGetNameBindingRequest{
		Credential:     credential,
		CredentialType: credentialType,
	}

	res, err := queryClient.NameBinding(context.Background(), params)
	if err != nil {
		return "", err
	}

	return res.GetNameBinding().Address, nil
}

// pioneerID is the ID of the pioneer if this is a financial transaction (i.e. a transfer, receive, create wallet, etc.)
func ClientAppendRequiredChainCCPubK(ctx client.Context, ccPubK []VSharePubKInfo, pioneerID string, excludeSSIntervalPubK bool) ([]VSharePubKInfo, error) {
	if excludeSSIntervalPubK && pioneerID == "" {
		fmt.Println("Logic error")
		return nil, fmt.Errorf("Logic error")
	}
	if !excludeSSIntervalPubK {
		ssIntervalPubKID, ssIntervalPubK, err := GetIntervalPublicKey(ctx, types.SSNodeID, types.SSNodeType)

		if err != nil {
			fmt.Println("Couldn't get interval public key")
			return nil, err
		}

		ccPubK = append(ccPubK, VSharePubKInfo{
			PubK:     ssIntervalPubK,
			NodeID:   types.SSNodeID,
			NodeType: types.SSNodeType,
		})

		if Debug && DebugFull {
			fmt.Println("ssIntervalPubKID", ssIntervalPubKID, "ssIntervalPubK", ssIntervalPubK)
		}
	}

	if pioneerID != "" {
		jarID, err := GetJarForPioneer(ctx, pioneerID)

		if err != nil {
			fmt.Println("Couldn't get jar for pioneer", pioneerID)
			return nil, err
		}

		if Debug && DebugFull {
			fmt.Println("jarID", jarID)
		}

		jarIntervalPubKID, jarIntervalPubK, err := GetIntervalPublicKey(ctx, jarID, types.JarNodeType)

		if err != nil {
			fmt.Println("Couldn't get jar interval public key", jarID, types.JarNodeType)
			return nil, err
		}

		if Debug && DebugFull {
			fmt.Println("jarIntervalPubKID", jarIntervalPubKID, "jarIntervalPubK", jarIntervalPubK)
		}

		ccPubK = append(ccPubK, VSharePubKInfo{
			PubK:     jarIntervalPubK,
			NodeID:   jarID,
			NodeType: types.JarNodeType,
		})
	}

	return ccPubK, nil
}

// find any service providers that are optional
func ClientAppendOptionalServiceProvidersCCPubK(ctx client.Context, ccPubK []VSharePubKInfo, serviceProviderID []string, optionalServiceProviderType []string) ([]VSharePubKInfo, error) {
	for i := range serviceProviderID {
		_, pubK, serviceProviderType, err := ClientGetIntervalPublicKey(ctx, serviceProviderID[i], types.ServiceProviderNodeType)
		if err != nil {
			fmt.Println("Couldn't get service provider interval public key", serviceProviderID[i], types.ServiceProviderNodeType)
			return nil, err
		}

		// check if serviceProviderType is in array requiredServiceProviderType
		for j := range optionalServiceProviderType {
			if serviceProviderType == optionalServiceProviderType[j] {
				ccPubK = append(ccPubK, VSharePubKInfo{
					PubK:     pubK,
					NodeID:   serviceProviderID[i],
					NodeType: types.ServiceProviderNodeType,
				})
			}
		}
	}

	return ccPubK, nil
}

func ClientAppendRequiredServiceProvidersCCPubK(ctx client.Context, ccPubK []VSharePubKInfo, serviceProviderID []string, requiredServiceProviderType []string) ([]VSharePubKInfo, error) {
	foundRequiredServiceProviderType := make([]bool, len(requiredServiceProviderType))
	for i := range serviceProviderID {
		_, pubK, serviceProviderType, err := ClientGetIntervalPublicKey(ctx, serviceProviderID[i], types.ServiceProviderNodeType)
		if err != nil {
			fmt.Println("Couldn't get service provider interval public key")
			return nil, err
		}

		// check if serviceProviderType is in array requiredServiceProviderType
		for j := range requiredServiceProviderType {
			if serviceProviderType == requiredServiceProviderType[j] {
				foundRequiredServiceProviderType[j] = true
				ccPubK = append(ccPubK, VSharePubKInfo{
					PubK:     pubK,
					NodeID:   serviceProviderID[i],
					NodeType: types.ServiceProviderNodeType,
				})
			}
		}
	}

	for i := range foundRequiredServiceProviderType {
		if !foundRequiredServiceProviderType[i] {
			return nil, fmt.Errorf("required service provider type %s not found", requiredServiceProviderType[i])
		}
	}
	return ccPubK, nil
}

func ClientGetIntervalPublicKey(ctx client.Context, intervalNodeID string, intervalNodeType string) (pubKID string, pubK string, serviceProviderType string, err error) {
	// we need to get a bunch of interval pubkid and pubk
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getIntervalPublicKey", intervalNodeID, intervalNodeType)
	}

	params := &types.QueryGetIntervalPublicKeyIDRequest{
		NodeID:   intervalNodeID,
		NodeType: intervalNodeType,
	}

	res, err := queryClient.IntervalPublicKeyID(context.Background(), params)
	if err != nil {
		fmt.Println("err", err)
		return
	}

	publicKeyId := res.IntervalPublicKeyID

	if Debug && DebugFull {
		fmt.Println("publicKeyId", publicKeyId)
	}

	params2 := &types.QueryGetPublicKeyRequest{
		PubKID:   publicKeyId.PubKID,
		PubKType: types.TransactionPubKType,
	}

	res2, err := queryClient.PublicKey(context.Background(), params2)
	if err != nil {
		fmt.Println("err", err)
		return
	}

	pubKID = publicKeyId.PubKID
	pubK = res2.PublicKey.PubK
	serviceProviderType = publicKeyId.ServiceProviderType
	return
}

func GetIntervalPublicKey(ctx client.Context, intervalNodeID string, intervalNodeType string) (string, string, error) {
	// we need to get a bunch of interval pubkid and pubk
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getIntervalPublicKey", intervalNodeID, intervalNodeType)
	}

	params := &types.QueryGetIntervalPublicKeyIDRequest{
		NodeID:   intervalNodeID,
		NodeType: intervalNodeType,
	}

	res, err := queryClient.IntervalPublicKeyID(context.Background(), params)
	if err != nil {
		fmt.Println("err", err)
		return "", "", err
	}

	publicKeyId := res.IntervalPublicKeyID

	if Debug && DebugFull {
		fmt.Println("publicKeyId", publicKeyId)
	}

	params2 := &types.QueryGetPublicKeyRequest{
		PubKID:   publicKeyId.PubKID,
		PubKType: types.TransactionPubKType,
	}

	res2, err := queryClient.PublicKey(context.Background(), params2)
	if err != nil {
		fmt.Println("err", err)
		return "", "", err
	}

	return publicKeyId.PubKID, res2.PublicKey.PubK, nil
}

// returns pubk and service provider type
func GetServiceProviderPublicKeyAndType(ctx client.Context, intervalNodeID string) (string, string, error) {
	intervalNodeType := types.ServiceProviderNodeType
	// we need to get a bunch of interval pubkid and pubk
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getIntervalPublicKey", intervalNodeID, intervalNodeType)
	}

	params := &types.QueryGetIntervalPublicKeyIDRequest{
		NodeID:   intervalNodeID,
		NodeType: intervalNodeType,
	}

	res, err := queryClient.IntervalPublicKeyID(context.Background(), params)
	if err != nil {
		fmt.Println("err", err)
		return "", "", err
	}

	publicKeyId := res.IntervalPublicKeyID

	if Debug && DebugFull {
		fmt.Println("publicKeyId", publicKeyId)
	}

	params2 := &types.QueryGetPublicKeyRequest{
		PubKID:   publicKeyId.PubKID,
		PubKType: types.TransactionPubKType,
	}

	res2, err := queryClient.PublicKey(context.Background(), params2)
	if err != nil {
		fmt.Println("err", err)
		return "", "", err
	}

	return res2.PublicKey.PubK, res.IntervalPublicKeyID.ServiceProviderType, nil
}

// returns pubk and service provider type
func GetServiceProviderHomePioneerID(ctx client.Context, intervalNodeID string) (string, error) {
	intervalNodeType := types.ServiceProviderNodeType
	// we need to get a bunch of interval pubkid and pubk
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getIntervalPublicKey", intervalNodeID, intervalNodeType)
	}

	params := &types.QueryGetIntervalPublicKeyIDRequest{
		NodeID:   intervalNodeID,
		NodeType: intervalNodeType,
	}

	res, err := queryClient.IntervalPublicKeyID(context.Background(), params)
	if err != nil {
		fmt.Println("err", err)
		return "", err
	}

	homePioneerID := res.IntervalPublicKeyID.HomePioneerID

	if Debug && DebugFull {
		fmt.Println("homePioneerID", homePioneerID)
	}

	return homePioneerID, nil
}

func GetPublicKey(ctx client.Context, pubKID string, pubKType string) (string, error) {
	// we need to get a bunch of interval pubkid and pubk
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getPublicKey", pubKID, pubKType)
	}

	params2 := &types.QueryGetPublicKeyRequest{
		PubKID:   pubKID,
		PubKType: pubKType,
	}

	res2, err := queryClient.PublicKey(context.Background(), params2)
	if err != nil {
		fmt.Println("err", err)
		return "", err
	}

	return res2.PublicKey.PubK, nil
}

func GetIncentives(ctx client.Context) (createWalletIncentive, createEphemeralWalletIncentive, createWalletTransparentIncentive, createEphemeralWalletTransparentIncentive *sdktypes.Coin, err error) {
	// we need to get a bunch of interval pubkid and pubk
	queryClient := types.NewQueryClient(ctx)

	if Debug && DebugFull {
		fmt.Println("getIncentives")
	}

	params2 := &types.QueryIncentivesRequest{}

	res2, err := queryClient.Incentives(context.Background(), params2)
	if err != nil {
		fmt.Println("err", err)
		return nil, nil, nil, nil, err
	}

	return &res2.CreateWalletIncentive, &res2.CreateEphemeralWalletIncentive, &res2.CreateWalletTransparentIncentive, &res2.CreateEphemeralWalletTransparentIncentive, nil
}

func GetProtectKey(ctx client.Context, walletID string, signerWalletID string) ([]byte, int, error) {
	queryClient := types.NewQueryClient(ctx)

	//	if Debug && DebugFull {
	fmt.Println("GetProtectKey", walletID, signerWalletID)
	//}

	params := &types.QueryGetProtectKeyRequest{
		WalletID: walletID,
	}

	res, err := queryClient.ProtectKey(context.Background(), params)
	if err != nil {
		return nil, 0, err
	}

	for _, recoverShare := range res.GetProtectKey().RecoverShare {
		fmt.Println("recoverShare", recoverShare)
		fmt.Println("signerWalletID", signerWalletID)
		fmt.Println("recoverShare.WalletID", recoverShare.WalletID)
		if recoverShare.WalletID == signerWalletID {
			fmt.Println("found")
			return recoverShare.EncWalletPubKShare, int(res.GetProtectKey().Threshold), nil
		}
	}

	return nil, 0, types.ErrKeyNotFound
}

func UnprotoizeBPedersenCommit(protoPC *types.BPedersenCommit) *PedersenCommit {
	ret := new(PedersenCommit)
	ret.A = BigIntZero
	ret.X = BigIntZero
	ecPoint := new(ECPoint)
	ecPoint, err := ECPointFromBytes(protoPC.C.Compressed)
	if err != nil {
		panic(err.Error())
	}
	// for some reason, UnmarshalCompressed doesn't work
	//	ecPoint.X, ecPoint.Y = elliptic.UnmarshalCompressed(ECPedersen.C, protoPC.C.Compressed)
	ret.C = ecPoint
	return ret
}

// make ConvertNSToQBPedersenCommit
func ConvertNSToQBPedersenCommit(pc *nstypes.BPedersenCommit) types.BPedersenCommit {
	var ret types.BPedersenCommit
	ret.C = &types.BECPoint{}

	if Debug && DebugFull {
		fmt.Println("ConvertNSToQBPedersenCommit", pc)

		fmt.Println("pc.C", pc)
	}

	if pc.C.Compressed != nil {
		ret.C.Compressed = pc.C.Compressed
	}

	return ret
}

// make NSProtoizeBPedersenCommit
func NSProtoizeBPedersenCommit(pc PedersenCommit) nstypes.BPedersenCommit {
	var ret nstypes.BPedersenCommit
	ret.C = &nstypes.BECPoint{}

	if Debug && DebugFull {
		fmt.Println("ProtoizeBPedersenCommit", pc)
	}

	if pc.A != nil && pc.A.Cmp(BigIntZero) != 0 {
		// raise exception
		panic("pc.A != 0")
	}

	if pc.X != nil && pc.X.Cmp(BigIntZero) != 0 {
		panic("pc.X != 0")
	}

	//	fmt.Println("ret.X", ret.X)

	if Debug && DebugFull {
		fmt.Println("pc.C", pc.C)
	}

	if pc.C.X != nil && pc.C.Y != nil {
		ret.C.Compressed = pc.C.Bytes()
	}

	return ret
}

func ProtoizeBPedersenCommit(pc *PedersenCommit) *types.BPedersenCommit {
	ret := new(types.BPedersenCommit)
	ret.C = new(types.BECPoint)

	if Debug {
		fmt.Println("ProtoizeBPedersenCommit", pc)
	}

	/*
		if pc.A != nil && pc.A.Cmp(BigIntZero) != 0 {
			// raise exception
			if Debug {
				fmt.Println("pc.A", pc.A, " != 0")
			}
		}

		if pc.X != nil && pc.X.Cmp(BigIntZero) != 0 {
			if Debug {
				fmt.Println("pc.X", pc.X, " != 0")
			}
		}
	*/

	//	fmt.Println("ret.X", ret.X)

	if Debug {
		fmt.Println("pc.C", pc.C)
	}

	if pc.C.X != nil && pc.C.Y != nil {
		ret.C.Compressed = pc.C.Bytes()
	}

	return ret
}

func UnprotoizeEncryptablePedersenCommit(protoEncryptablePedersenCommit *types.EncryptablePedersenCommit) *PedersenCommit {
	var ret *PedersenCommit

	if protoEncryptablePedersenCommit.A != nil && protoEncryptablePedersenCommit.X != nil {
		ret = NewPedersenCommit(UnprotoizeBInt(protoEncryptablePedersenCommit.A), UnprotoizeBInt(protoEncryptablePedersenCommit.X))
	}

	return ret
}

func ProtoizeEncryptablePedersenCommit(pc *PedersenCommit) *types.EncryptablePedersenCommit {
	ret := new(types.EncryptablePedersenCommit)

	if Debug && DebugFull {
		fmt.Println("ProtoizeEncryptablePedersenCommit", pc)
	}

	if pc.A != nil {
		ret.A = ProtoizeBInt(pc.A)
	}

	if Debug && DebugFull {
		fmt.Println("ret.A", ret.A)
	}

	if pc.X != nil {
		ret.X = ProtoizeBInt(pc.X)
	}

	return ret
}

func GetDenomAtomicFactor(x int64) *big.Int {
	baseNum := big.NewInt(10)
	powerNum := big.NewInt(x)
	return new(big.Int).Exp(baseNum, powerNum, nil)
}

func UnprotoizeBRangeProof(protoRangeProof *types.BRangeProof) *RangeProofV2 {
	var ret RangeProofV2

	// quick & temporary shortcut to allow empty RangeProofs for later integration
	if protoRangeProof.A.Compressed == nil || len(protoRangeProof.A.Compressed) == 0 {
		return nil
	}

	ret.A = UnprotoizeBECPoint(protoRangeProof.A)

	ret.S = UnprotoizeBECPoint(protoRangeProof.S)

	ret.TCommits = make([]*ECPoint, len(protoRangeProof.TCommits))

	for i := 0; i < len(protoRangeProof.TCommits); i++ {
		ret.TCommits[i] = UnprotoizeBECPoint(protoRangeProof.TCommits[i])
	}

	// new allocates the struct
	ret.TauX = UnprotoizeBInt(protoRangeProof.TauX)
	ret.Mu = UnprotoizeBInt(protoRangeProof.Mu)
	ret.T = UnprotoizeBInt(protoRangeProof.T)

	// for the InnerProductProofV2
	ipa := new(InnerProductProofV2)
	var ecp_L, ecp_R []*ECPoint

	// allocate the correct array length for both L and R
	ecp_L = make([]*ECPoint, len(protoRangeProof.IPP.L))
	ecp_R = make([]*ECPoint, len(protoRangeProof.IPP.R))

	// iterate through each of the InnerProdArg.L elements
	for i, v := range protoRangeProof.IPP.L {
		ecp_L[i] = UnprotoizeBECPoint(v)
	}

	// iterate through each of the InnerProdArg.R elements
	for i, v := range protoRangeProof.IPP.R {
		ecp_R[i] = UnprotoizeBECPoint(v)
	}

	ipa.L = ecp_L
	ipa.R = ecp_R
	ipa.A = UnprotoizeBInt(protoRangeProof.IPP.A)
	ipa.B = UnprotoizeBInt(protoRangeProof.IPP.B)

	ret.ProductProof = ipa

	return &ret
}

func ProtoizeBECPointInfo(ecpi *ECPointInfo) *types.BECPointInfo {
	ret := new(types.BECPointInfo)

	ret.ECPoint = ProtoizeBECPoint(ecpi.ECPoint)
	ret.NodeType = ecpi.NodeType
	ret.NodeID = ecpi.NodeID

	return ret
}

func UnprotoizeBECPointInfo(ecpi *types.BECPointInfo) *ECPointInfo {
	ret := new(ECPointInfo)

	ret.ECPoint = UnprotoizeBECPoint(ecpi.ECPoint)
	ret.NodeType = ecpi.NodeType
	ret.NodeID = ecpi.NodeID

	return ret
}

func DSVSProtoizeBECPointInfo(ecpi *ECPointInfo) *dsvstypes.BECPointInfo {
	ret := new(dsvstypes.BECPointInfo)

	ret.ECPoint = DSVSProtoizeBECPoint(ecpi.ECPoint)
	ret.NodeType = ecpi.NodeType
	ret.NodeID = ecpi.NodeID

	return ret
}

func DSVSUnprotoizeBECPointInfo(ecpi *dsvstypes.BECPointInfo) *ECPointInfo {
	ret := new(ECPointInfo)

	ret.ECPoint = DSVSUnprotoizeBECPoint(ecpi.ECPoint)
	ret.NodeType = ecpi.NodeType
	ret.NodeID = ecpi.NodeID

	return ret
}

func ProtoizeBECPoint(ecp *ECPoint) *types.BECPoint {
	ret := new(types.BECPoint)

	ret.Compressed = ecp.Bytes()

	return ret
}

func UnprotoizeBECPoint(ecp *types.BECPoint) *ECPoint {
	ret := new(ECPoint)

	// BECPoint contains compressed ECPoint, uncompress it

	ret, err := ECPointFromBytes(ecp.Compressed)

	if err != nil {
		panic(err.Error())
	}

	return ret
}

func UnprotoizeBVSharedSecret(vss *types.BVSharedSecret) *VSharedSecret {
	ret := new(VSharedSecret)

	ret.S1 = UnprotoizeBECPoint(vss.S1)
	ret.S2 = UnprotoizeBECPoint(vss.S2)

	return ret
}

func UnprotoizeVShareBindData(protoBindData *types.VShareBindData) *VShareBindData {

	if protoBindData == nil {
		return nil
	}
	if protoBindData.Data == nil {
		return nil
	}
	if len(protoBindData.Data) != 2 {
		return nil
	}

	ret := new(VShareBindData)

	ret.Data = make([]*vshareBindDataInternal, 2)

	for i := 0; i < 2; i++ {
		ret.Data[i] = UnprotoizeVShareBindDataInternal(protoBindData.Data[i])
	}

	return ret
}

func UnprotoizeVShareBindDataInternal(protoBindData *types.VShareBindDataInternal) *vshareBindDataInternal {
	ret := new(vshareBindDataInternal)

	W := UnprotoizeBInt(protoBindData.W)
	Z := UnprotoizeBInt(protoBindData.Z)

	ret.W = W
	ret.Z = Z

	ret.C = UnprotoizeBECPoint(protoBindData.C)
	ret.Y = UnprotoizeBECPointInfo(protoBindData.Y)

	ret.Cc = make([]*ECPointInfo, len(protoBindData.Cc))
	for i, v := range protoBindData.Cc {
		ret.Cc[i] = UnprotoizeBECPointInfo(v)
	}

	ret.R = UnprotoizeBVSharedSecret(protoBindData.R)

	ret.R_ = make([]*VSharedSecret, len(protoBindData.Rr))
	for i, v := range protoBindData.Rr {
		ret.R_[i] = UnprotoizeBVSharedSecret(v)
	}

	return ret
}

func ProtoizeBVSharedSecret(vss *VSharedSecret) *types.BVSharedSecret {
	ret := new(types.BVSharedSecret)

	ret.S1 = ProtoizeBECPoint(vss.S1)
	ret.S2 = ProtoizeBECPoint(vss.S2)

	return ret
}

func DSVSUnprotoizeVShareBindData(protoBindData *dsvstypes.VShareBindData) *VShareBindData {
	ret := new(VShareBindData)

	ret.Data = make([]*vshareBindDataInternal, 2)

	for i := 0; i < 2; i++ {
		ret.Data[i] = DSVSUnprotoizeVShareBindDataInternal(protoBindData.Data[i])
	}

	return ret
}

func DSVSUnprotoizeVShareBindDataInternal(protoBindData *dsvstypes.VShareBindDataInternal) *vshareBindDataInternal {
	ret := new(vshareBindDataInternal)

	W := DSVSUnprotoizeBInt(protoBindData.W)
	Z := DSVSUnprotoizeBInt(protoBindData.Z)

	ret.W = W
	ret.Z = Z

	ret.C = DSVSUnprotoizeBECPoint(protoBindData.C)
	ret.Y = DSVSUnprotoizeBECPointInfo(protoBindData.Y)

	ret.Cc = make([]*ECPointInfo, len(protoBindData.Cc))
	for i, v := range protoBindData.Cc {
		ret.Cc[i] = DSVSUnprotoizeBECPointInfo(v)
	}

	ret.R = DSVSUnprotoizeBVSharedSecret(protoBindData.R)

	ret.R_ = make([]*VSharedSecret, len(protoBindData.Rr))
	for i, v := range protoBindData.Rr {
		ret.R_[i] = DSVSUnprotoizeBVSharedSecret(v)
	}

	return ret
}

func DSVSUnprotoizeBVSharedSecret(vss *dsvstypes.BVSharedSecret) *VSharedSecret {
	ret := new(VSharedSecret)

	ret.S1 = DSVSUnprotoizeBECPoint(vss.S1)
	ret.S2 = DSVSUnprotoizeBECPoint(vss.S2)

	return ret
}

func DSVSUnprotoizeBInt(bi *dsvstypes.BInt) *big.Int {
	ret := new(big.Int)
	// set bytes starting at index 1
	ret.SetBytes(bi.I[1:])
	// set sign
	if bi.I[0] == 1 {
		ret.Neg(ret)
	}
	return ret
}

func DSVSUnprotoizeBECPoint(ecp *dsvstypes.BECPoint) *ECPoint {
	ret, err := ECPointFromBytes(ecp.Compressed)
	if err != nil {
		panic(err.Error())
	}
	return ret
}

func DSVSProtoizeVShareBindData(bd *VShareBindData) *dsvstypes.VShareBindData {
	ret := new(dsvstypes.VShareBindData)

	ret.Data = make([]*dsvstypes.VShareBindDataInternal, 2)

	for i := 0; i < 2; i++ {
		ret.Data[i] = DSVSProtoizeVShareBindDataInternal(bd.Data[i])
	}

	return ret
}

func DSVSProtoizeVShareBindDataInternal(bd *vshareBindDataInternal) *dsvstypes.VShareBindDataInternal {
	ret := new(dsvstypes.VShareBindDataInternal)

	ret.W = DSVSProtoizeBInt(bd.W)

	ret.Z = DSVSProtoizeBInt(bd.Z)

	ret.C = DSVSProtoizeBECPoint(bd.C)

	// protoize Y
	ret.Y = DSVSProtoizeBECPointInfo(bd.Y)

	// Cc []*ECPoint
	ret.Cc = make([]*dsvstypes.BECPointInfo, len(bd.Cc))
	for i, v := range bd.Cc {
		ret.Cc[i] = DSVSProtoizeBECPointInfo(v)
	}

	// R *ECPoint
	ret.R = DSVSProtoizeBVSharedSecret(bd.R)

	// Rr []*ECPoint
	ret.Rr = make([]*dsvstypes.BVSharedSecret, len(bd.R_))
	for i, v := range bd.R_ {
		ret.Rr[i] = DSVSProtoizeBVSharedSecret(v)
	}

	return ret
}

func DSVSProtoizeBInt(bi *big.Int) *dsvstypes.BInt {
	ret := new(dsvstypes.BInt)

	b := bi.Bytes()

	ret.I = make([]byte, len(b)+1)

	// copy the bytes
	copy(ret.I[1:], b)

	// set the first byte to 0 or 1 depending on the sign
	if bi.Sign() < 0 {
		ret.I[0] = 1
	} else {
		ret.I[0] = 0
	}

	return ret
}

func DSVSProtoizeBIntOld(bi *big.Int) *dsvstypes.BInt {
	ret := new(dsvstypes.BInt)

	ret.I, _ = bi.MarshalText()

	return ret
}

func DSVSProtoizeBECPoint(ecp *ECPoint) *dsvstypes.BECPoint {
	ret := new(dsvstypes.BECPoint)

	ret.Compressed = ecp.Bytes()

	return ret
}

func DSVSProtoizeBVSharedSecret(vss *VSharedSecret) *dsvstypes.BVSharedSecret {
	ret := new(dsvstypes.BVSharedSecret)

	ret.S1 = DSVSProtoizeBECPoint(vss.S1)
	ret.S2 = DSVSProtoizeBECPoint(vss.S2)

	return ret
}

func ProtoizeVShareBindData(bd *VShareBindData) *types.VShareBindData {
	if bd == nil {
		return nil
	}
	ret := new(types.VShareBindData)

	ret.Data = make([]*types.VShareBindDataInternal, 2)

	for i := 0; i < 2; i++ {
		ret.Data[i] = ProtoizeVShareBindDataInternal(bd.Data[i])
	}

	return ret
}

func ProtoizeVShareBindDataInternal(bd *vshareBindDataInternal) *types.VShareBindDataInternal {
	ret := new(types.VShareBindDataInternal)

	ret.W = ProtoizeBInt(bd.W)

	ret.Z = ProtoizeBInt(bd.Z)

	ret.C = ProtoizeBECPoint(bd.C)

	// protoize Y
	ret.Y = ProtoizeBECPointInfo(bd.Y)

	// Cc []*ECPoint
	ret.Cc = make([]*types.BECPointInfo, len(bd.Cc))
	for i, v := range bd.Cc {
		ret.Cc[i] = ProtoizeBECPointInfo(v)
	}

	// R *ECPoint
	ret.R = ProtoizeBVSharedSecret(bd.R)

	// Rr []*ECPoint
	ret.Rr = make([]*types.BVSharedSecret, len(bd.R_))
	for i, v := range bd.R_ {
		ret.Rr[i] = ProtoizeBVSharedSecret(v)
	}

	return ret
}

func ProtoizeBInt(bi *big.Int) *types.BInt {
	ret := new(types.BInt)

	b := bi.Bytes()

	ret.I = make([]byte, len(b)+1)

	// copy the bytes
	copy(ret.I[1:], b)

	// set the first byte to 0 or 1 depending on the sign
	if bi.Sign() < 0 {
		ret.I[0] = 1
	} else {
		ret.I[0] = 0
	}

	return ret
}

func UnprotoizeBInt(bi *types.BInt) *big.Int {
	ret := new(big.Int)
	// set bytes starting at index 1
	ret.SetBytes(bi.I[1:])
	// set sign
	if bi.I[0] == 1 {
		ret.Neg(ret)
	}
	return ret
}

func ProtoizeBIntOld(bi *big.Int) *types.BInt {
	ret := new(types.BInt)

	ret.I, _ = bi.MarshalText()

	return ret
}

func UnprotoizeBIntOld(bi *types.BInt) *big.Int {
	ret := new(big.Int)
	ret.UnmarshalText(bi.I)
	return ret
}

func ProtoizeBRangeProof(rp *RangeProofV2) *types.BRangeProof {
	ret := new(types.BRangeProof)

	ret.A = ProtoizeBECPoint(rp.A)

	ret.S = ProtoizeBECPoint(rp.S)

	ret.TCommits = make([]*types.BECPoint, len(rp.TCommits))
	for i := range rp.TCommits {
		ret.TCommits[i] = ProtoizeBECPoint(rp.TCommits[i])
	}

	if rp.TauX != nil {
		ret.TauX = ProtoizeBInt(rp.TauX)
	}

	if rp.Mu != nil {
		ret.Mu = ProtoizeBInt(rp.Mu)
	}

	if rp.T != nil {
		ret.T = ProtoizeBInt(rp.T)
	}

	ret.IPP = &types.BInnerProductProof{}

	// allocate the correct array length for L
	ret.IPP.L = make([]*types.BECPoint, len(rp.ProductProof.L))

	for i, v := range rp.ProductProof.L {
		ret.IPP.L[i] = ProtoizeBECPoint(v)
	}

	// allocate the correct array length for R
	ret.IPP.R = make([]*types.BECPoint, len(rp.ProductProof.R))

	for i, v := range rp.ProductProof.R {
		ret.IPP.R[i] = ProtoizeBECPoint(v)
	}

	if rp.ProductProof.A != nil {
		ret.IPP.A = ProtoizeBInt(rp.ProductProof.A)
	}

	if rp.ProductProof.B != nil {
		ret.IPP.B = ProtoizeBInt(rp.ProductProof.B)
	}

	return ret
}

func ProtoizeVShareSignatory(vss *VShareSignatory) *types.VShareSignatory {
	ret := new(types.VShareSignatory)

	ret.EncSignatoryVShare = vss.EncSignatoryVShare
	ret.VShareBind = ProtoizeVShareBindData(vss.VShareBind)

	return ret
}

func ProtoizeArrayOfVShareSignatory(vss []*VShareSignatory) []*types.VShareSignatory {
	ret := make([]*types.VShareSignatory, 0)

	for _, v := range vss {
		ret = append(ret, ProtoizeVShareSignatory(v))
	}

	return ret
}

func UnprotoizeVShareSignatory(vss *types.VShareSignatory) *VShareSignatory {
	ret := new(VShareSignatory)

	ret.EncSignatoryVShare = vss.EncSignatoryVShare
	ret.VShareBind = UnprotoizeVShareBindData(vss.VShareBind)

	return ret
}

func DSVSProtoizeVShareSignatory(vss *VShareSignatory) *dsvstypes.VShareSignatory {
	ret := new(dsvstypes.VShareSignatory)

	ret.EncSignatoryVShare = vss.EncSignatoryVShare
	ret.SignatoryVShareBind = DSVSProtoizeVShareBindData(vss.VShareBind)

	return ret
}

func DSVSUnprotoizeVShareSignatory(vss *dsvstypes.VShareSignatory) *VShareSignatory {
	ret := new(VShareSignatory)

	ret.EncSignatoryVShare = vss.EncSignatoryVShare
	ret.VShareBind = DSVSUnprotoizeVShareBindData(vss.SignatoryVShareBind)

	return ret
}

func SetStableWallet(wallet types.Wallet, sw *types.StableWallet) {
	// 1
	sw.WalletID = wallet.WalletID
	// 2
	sw.HomePioneerID = wallet.HomePioneerID

	// 3
	// copy service provider ID
	sw.ServiceProviderID = make([]string, len(wallet.ServiceProviderID))
	copy(sw.ServiceProviderID, wallet.ServiceProviderID)

	// 4
	keys := make([]string, 0, len(wallet.WalletAmount))
	for k := range wallet.WalletAmount {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sw.WalletAmount = append(sw.WalletAmount, &types.StringWalletAmount{Name: k, Val: wallet.WalletAmount[k]})
	}

	// 5
	sw.CredentialID = wallet.CredentialID

	// 6
	sw.EncCreateWalletVShare = wallet.EncCreateWalletVShare

	// 7
	sw.CreateWalletVShareBind = wallet.CreateWalletVShareBind

	// 8
	keys = make([]string, 0, len(wallet.EphemeralWalletAmountCount))
	for k := range wallet.EphemeralWalletAmountCount {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sw.EphemeralWalletAmountCount = append(sw.EphemeralWalletAmountCount, &types.StringInt32{Name: k, Val: wallet.EphemeralWalletAmountCount[k]})
	}

	// 9
	keys = make([]string, 0, len(wallet.QueuedWalletAmount))
	for k := range wallet.QueuedWalletAmount {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sw.QueuedWalletAmount = append(sw.QueuedWalletAmount, &types.StringListWalletAmount{Name: k, Val: wallet.QueuedWalletAmount[k]})
	}

	// 10
	sw.AcceptPasswordPedersenCommit = wallet.AcceptPasswordPedersenCommit

	// 11
	sw.EncAcceptValidatedCredentialsVShare = wallet.EncAcceptValidatedCredentialsVShare

	// 12
	sw.AcceptValidatedCredentialsVShareBind = wallet.AcceptValidatedCredentialsVShareBind

	// 13
	sw.SenderOptions = wallet.SenderOptions

	// 14
	sw.RecoverShares = wallet.RecoverShares
}

func validateVShare(ctx sdk.Context, vshare *VShareBindData, encVShare []byte, expectedPubK []VSharePubKInfo) bool {
	for i := 0; i < len(expectedPubK); i++ {
		if !vshare.FindVSharePubKInfo(expectedPubK[i]) {
			ContextError(ctx, "FindVSharePubKInfo failed", expectedPubK[i])
			return false
		}
	}
	if !vshare.VShareBVerify(encVShare) {
		ContextError(ctx, "VShareBVerify failed")
		return false
	}
	return true
}

func validateBulkVShare(ctx sdk.Context, vshare *VShareBindData, encVShare [][]byte, expectedPubK []VSharePubKInfo) bool {
	for i := 0; i < len(expectedPubK); i++ {
		if !vshare.FindVSharePubKInfo(expectedPubK[i]) {
			ContextError(ctx, "FindVSharePubKInfo failed", expectedPubK[i])
			return false
		}
	}

	hash := sha256.New()

	for _, enc := range encVShare {
		hash.Write(enc)
	}

	hashed := hash.Sum(nil)

	if !vshare.VShareBVerify(hashed) {
		ContextError(ctx, "VShareBVerify failed")
		return false
	}
	return true
}

func ValidateVShare(ctx sdk.Context, vshare *types.VShareBindData, encVShare []byte, expectedPubK []VSharePubKInfo) bool {
	unprotoVShare := UnprotoizeVShareBindData(vshare)
	return validateVShare(ctx, unprotoVShare, encVShare, expectedPubK)
}

func ValidateBulkVShare(ctx sdk.Context, vshare *types.VShareBindData, encVShare [][]byte, expectedPubK []VSharePubKInfo) bool {
	unprotoVShare := UnprotoizeVShareBindData(vshare)
	return validateBulkVShare(ctx, unprotoVShare, encVShare, expectedPubK)
}

func DSVSValidateVShare(ctx sdk.Context, vshare *dsvstypes.VShareBindData, encVShare []byte, expectedPubK []VSharePubKInfo) bool {
	unprotoVShare := DSVSUnprotoizeVShareBindData(vshare)
	return validateVShare(ctx, unprotoVShare, encVShare, expectedPubK)
}
