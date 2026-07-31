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
	"unicode"

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

// The AML reporting threshold used to be this one compiled-in figure.  It is now per-jurisdiction
// and governance-tunable -- see DefaultSuspiciousThreshold and SuspiciousPolicyFromParams in
// suspicious_policy.go.

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
	ContextDebug(ctx, "StoreHashByKVStoreService prefix="+p+",count="+strconv.Itoa(count)+",ret="+ret)
	return ret
}

func StoreHashByStoreKey(ctx sdktypes.Context, storeKey storetypes.StoreKey, p string) string {
	store := prefix.NewStore(ctx.KVStore(storeKey), types.KeyPrefix(p))

	ret, count := StoreHashByPrefixStore(ctx, store)
	ContextDebug(ctx, "StoreHashByStoreKey prefix="+p+",count="+strconv.Itoa(count)+",ret="+ret)
	return ret
}

// PersonalInfoBirthdateLayout is the one and only accepted representation of a birthdate.  It
// feeds CreateCredentialHash directly, so two spellings of the same date ("1970-Feb-02" vs
// "1970-feb-02") would hash to two different identities for the same person.
const PersonalInfoBirthdateLayout = "2006-Jan-02"

// CreateCredentialHash joins the identity-bearing fields with "," and "|" separators, so a field
// containing a separator could be re-parsed as a different split: ("a,b", "c") and ("a", "b,c")
// produce the same hash.  ValidatePersonalInfoDetails rejects those characters up front, which
// keeps the hash injective without changing its encoding (and therefore without invalidating
// every hash already recorded in the enclave's uniqueness index).
const credentialHashSeparators = ",|"

var ErrCredentialHashSeparatorInField = errors.New("personal info fields may not contain ',' or '|'")

// ErrCredentialHashDecomposedName rejects a name carrying combining marks -- see the check in
// ValidatePersonalInfoDetails.  The remedy is to submit the precomposed (NFC) spelling, which is
// what every normal input method produces.
var ErrCredentialHashDecomposedName = errors.New("names must use precomposed characters (e.g. \"ñ\" as one character, not \"n\" plus a combining tilde)")

// NormalizeBirthdateTime parses a birthdate in the canonical layout.  Case-insensitive month
// spellings ("1970-feb-02") parse fine; it is Format, not Parse, that fixes the canonical
// spelling, which is why NormalizeBirthdate round-trips through both.
func NormalizeBirthdateTime(birthdate string) (time.Time, error) {
	return time.Parse(PersonalInfoBirthdateLayout, birthdate)
}

// NormalizeBirthdate parses a birthdate and re-emits it in the canonical layout.  It returns an
// error rather than a best guess: an unparseable birthdate must not reach CreateCredentialHash.
func NormalizeBirthdate(birthdate string) (string, error) {
	t, err := NormalizeBirthdateTime(birthdate)
	if err != nil {
		return "", err
	}
	return t.Format(PersonalInfoBirthdateLayout), nil
}

// PersonalInfoReason identifies which invariant a credential broke.  It exists so the enclave can
// tell the chain WHY a submission was refused without saying WHAT was submitted: the enclave is the
// only party that can read the credential, and a transaction error is public, so the detailed
// messages below must never leave the enclave's log.  A reason code names the rule, not the value.
type PersonalInfoReason int32

const (
	PersonalInfoOK PersonalInfoReason = iota
	PersonalInfoNilDetails
	PersonalInfoSeparatorInField
	PersonalInfoDecomposedName
	PersonalInfoBirthdateFormat
	PersonalInfoBirthdateNotCanonical
	PersonalInfoInvalidGender
)

// Message is the sentence shown to the submitter.  Every one of these is a fixed string: none
// interpolates a submitted value, which is what makes it safe to put in a transaction error.
func (r PersonalInfoReason) Message() string {
	switch r {
	case PersonalInfoOK:
		return ""
	case PersonalInfoNilDetails:
		return "personal info details are missing"
	case PersonalInfoSeparatorInField:
		return "personal info fields may not contain ',' or '|'"
	case PersonalInfoDecomposedName:
		return "names must use precomposed characters (e.g. \"ñ\" as one character, not \"n\" plus a combining tilde)"
	case PersonalInfoBirthdateFormat:
		return "birthdate must be formatted as " + PersonalInfoBirthdateLayout
	case PersonalInfoBirthdateNotCanonical:
		return "birthdate is not in its canonical spelling; use the form " + PersonalInfoBirthdateLayout
	case PersonalInfoInvalidGender:
		return "gender must be one of m, f, n"
	default:
		return "personal info is invalid"
	}
}

// PersonalInfoReasonOf reports which invariant a credential breaks, or PersonalInfoOK.  This is the
// form the enclave uses, because it can be returned across the enclave boundary safely.
func PersonalInfoReasonOf(pd *types.EncryptablePersonalInfoDetails) PersonalInfoReason {
	r, _ := validatePersonalInfoDetails(pd)
	return r
}

// ValidatePersonalInfoDetails enforces the invariants CreateCredentialHash depends on.  Call it
// before hashing personal info, on both the client (for a friendly error) and inside the enclave
// (because the client cannot be trusted).
//
// The errors it returns may quote the submitted value, which makes them useful on the client and
// unsafe on the chain.  Anything running inside the enclave should return PersonalInfoReasonOf's
// code instead and log this message rather than returning it.
func ValidatePersonalInfoDetails(pd *types.EncryptablePersonalInfoDetails) error {
	_, err := validatePersonalInfoDetails(pd)
	return err
}

// validatePersonalInfoDetails is the single implementation behind both forms above, so a rule can
// never be enforced in one and missed in the other.
func validatePersonalInfoDetails(pd *types.EncryptablePersonalInfoDetails) (PersonalInfoReason, error) {
	if pd == nil {
		return PersonalInfoNilDetails, errors.New("personal info details are nil")
	}

	for _, f := range []string{pd.FirstName, pd.MiddleName, pd.LastName, pd.Birthdate, pd.Gender} {
		if strings.ContainsAny(f, credentialHashSeparators) {
			return PersonalInfoSeparatorInField, ErrCredentialHashSeparatorInField
		}
	}

	// Unicode has two spellings for an accented letter: precomposed ("ñ" = U+00F1) and decomposed
	// ("n" + U+0303).  They look identical and are the same name, but hash differently, which would
	// let the same person hold two identities.  The usual fix is norm.NFC, but golang.org/x/text is
	// barred here (module-versioned Unicode tables, see credential_policy.go) -- so instead of
	// normalizing the decomposed form we reject it, which needs only the stdlib's unicode.Mn table.
	//
	// This is the same posture as the birthdate check below: refuse non-canonical input rather than
	// silently rewrite it.  The cost is that scripts whose marks have no precomposed form (parts of
	// Devanagari, Thai, Hebrew niqqud) cannot be entered; Latin script, including every Spanish and
	// Filipino diacritic, is fully precomposable and unaffected.
	for _, f := range []string{pd.FirstName, pd.MiddleName, pd.LastName} {
		for _, r := range f {
			if unicode.Is(unicode.Mn, r) {
				return PersonalInfoDecomposedName, ErrCredentialHashDecomposedName
			}
		}
	}

	normalized, err := NormalizeBirthdate(pd.Birthdate)
	if err != nil {
		return PersonalInfoBirthdateFormat, errors.New("birthdate must be formatted as " + PersonalInfoBirthdateLayout)
	}
	if normalized != pd.Birthdate {
		return PersonalInfoBirthdateNotCanonical, errors.New("birthdate is not canonical, expected " + normalized)
	}

	if !types.ValidateGender(pd.Gender) {
		return PersonalInfoInvalidGender, errors.New("invalid gender " + pd.Gender)
	}

	return PersonalInfoOK, nil
}

// CanonicalizeName reduces a name to the form the identity hash is computed over: lowercased,
// trimmed, with internal whitespace runs collapsed to a single space.  The stored credential keeps
// whatever the user typed -- this affects only hashing and comparison.
//
// It exists because uniqueness is an EXACT lookup on CreateCredentialHash.  Without it "SMITH",
// "Smith" and "smith" are three unrelated identities, and the anti-squatting check that refuses a
// second claim of an identity is defeated by the shift key.
//
// What it deliberately does NOT do is strip diacritics.  "Peña" and "Pena" are different surnames,
// and folding them together would make the second person to claim collide with the first -- a false
// collision has no recovery path, whereas a missed one is merely the status quo.  For the same
// reason it does not strip punctuation: "O'Brien" and "OBrien" stay distinct.
//
// Stdlib only, for the reason given at the top of credential_policy.go: this runs inside the
// enclave on every validator, and golang.org/x/text's Unicode tables are module-versioned, so two
// nodes on different module versions could canonicalize differently and fork.  unicode.IsSpace
// moves only with the toolchain.  The NFC/NFD half of the problem is handled by rejection instead
// -- see the combining-mark check in ValidatePersonalInfoDetails.
func CanonicalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))

	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			inSpace = true
			continue
		}
		if inSpace {
			b.WriteRune(' ')
			inSpace = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CreateCredentialHash derives the identity key that the enclave's uniqueness index is keyed on.
//
// The name fields are canonicalized first (see CanonicalizeName); birthdate and gender are not,
// because ValidatePersonalInfoDetails already refuses anything but their canonical spelling.
//
// Changing what this function computes orphans every hash already recorded in the enclave's
// uniqueness index, so it cannot be altered on a live chain without a migration that re-derives
// every entry from decrypted credentials.  Note also that the client computes this hash too
// (tx_claim_credential.go, tx_update_credential.go) and the enclave verifies its own recomputation
// against it -- so wallet and chain must ship this function in lockstep, or every claim fails with
// ErrGenericPedersen.
func CreateCredentialHash(pd *types.EncryptablePersonalInfoDetails) string {
	firstMiddleLast := CanonicalizeName(pd.LastName) + "," + CanonicalizeName(pd.MiddleName) + "," + CanonicalizeName(pd.FirstName)
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

// for compatibility
func GetAddress(ctx client.Context, friendlyNameOrBech32Addr string) (bech32Addr string, pubKBytes []byte, pubK string, privKHex string, err error) {
	bech32Addr, pubKBytes, pubK, privKHex, _, err = GetAddressAndFriendlyName(ctx, friendlyNameOrBech32Addr)
	return
}

func GetAddressAndFriendlyName(ctx client.Context, friendlyNameOrBech32Addr string) (bech32Addr string, pubKBytes []byte, pubK string, privKHex string, friendlyName string, err error) {
	kb := ctx.Keyring
	if Debug && DebugFull {
		fmt.Println("GetAddress", friendlyNameOrBech32Addr)
	}
	keyInfo, err := kb.Key(friendlyNameOrBech32Addr)

	// get it by "friendly name" (from the keyring) first
	if err != nil {
		var address sdktypes.Address
		// if not found by "friendly name", let's try to convert it from an eth address
		if ethcommon.IsHexAddress(friendlyNameOrBech32Addr) {
			address, err = sdktypes.AccAddressFromHexUnsafe(friendlyNameOrBech32Addr[2:])
			if err != nil {
				fmt.Println("Couldn't convert from hex format", friendlyNameOrBech32Addr)
				return "", nil, "", "", "", err
			}
		} else {
			//    fmt.Println("Couldn't find using friendly name", addr)
			// might be a bech32 (COSMOS) address
			address, err = sdktypes.AccAddressFromBech32(friendlyNameOrBech32Addr)
			if err != nil {
				fmt.Println("Couldn't convert from bech32 format", friendlyNameOrBech32Addr)
				return "", nil, "", "", "", err
			}
		}

		keyInfo, err = kb.KeyByAddress(address)

		if err != nil {
			// it looks at least like a valid bech32 address, let's return
			if Debug {
				fmt.Println("Valid bech32 address, but no other info available", friendlyNameOrBech32Addr)
			}
			return friendlyNameOrBech32Addr, nil, "", "", "", nil
		}
	}

	keyOut, err := keys.MkAccKeyOutput(keyInfo)

	if err != nil {
		return "", nil, "", "", "", err
	}

	privKeyHex, err := unsafeExportPrivKeyHex(kb.(unsafeExporter), keyInfo.Name)

	if err != nil {
		return "", nil, "", "", "", err
	}

	var pubKeyParsed PubKeyStruct
	err = json.Unmarshal([]byte(keyOut.PubKey), &pubKeyParsed)

	if err != nil {
		return "", nil, "", "", "", err
	}

	if Debug && DebugFull {
		fmt.Println("pubKeyParsed: ", pubKeyParsed)
	}

	pubKey := pubKeyParsed.Key
	pubkbytes, err := base64.StdEncoding.DecodeString(pubKey)

	if err != nil {
		return "", nil, "", "", "", err
	}

	return keyOut.Address, pubkbytes, pubKey, privKeyHex, keyInfo.Name, nil
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
	ret.SignatoryVShareBind = ProtoizeVShareBindData(vss.VShareBind)
	ret.Time = vss.Time
	ret.WalletID = vss.WalletID

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
	ret.VShareBind = UnprotoizeVShareBindData(vss.SignatoryVShareBind)
	ret.Time = vss.Time
	ret.WalletID = vss.WalletID

	return ret
}

func DSVSProtoizeVShareSignatory(vss *VShareSignatory) *dsvstypes.VShareSignatory {
	ret := new(dsvstypes.VShareSignatory)

	ret.EncSignatoryVShare = vss.EncSignatoryVShare
	ret.SignatoryVShareBind = DSVSProtoizeVShareBindData(vss.VShareBind)
	ret.Time = vss.Time
	ret.WalletID = vss.WalletID

	return ret
}

func DSVSUnprotoizeVShareSignatory(vss *dsvstypes.VShareSignatory) *VShareSignatory {
	ret := new(VShareSignatory)

	ret.EncSignatoryVShare = vss.EncSignatoryVShare
	ret.VShareBind = DSVSUnprotoizeVShareBindData(vss.SignatoryVShareBind)
	ret.Time = vss.Time
	ret.WalletID = vss.WalletID

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
