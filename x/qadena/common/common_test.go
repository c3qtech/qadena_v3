package common

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra"

	// big
	"math/big"

	cmdcfg "qadena_v3/cmd/config"
	qadenakr "qadena_v3/crypto/keyring"

	// cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"

	//	qadenaflags "/qadena_v3/x/qadena/client/flags"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	amino "github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	//enccodec "github.com/evmos/evmos/v18/encoding/codec"
	// tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	//ecies "github.com/ecies/go/v2"
)

// GenerateKeys generates a specified number of public and private keys.
func GenerateKeys(t *testing.T, count int) ([]string, []string) {
	EnvPrefix := "QADENA"

	cmdcfg.RegisterDenoms()

	chainID := "qadena_1000-1"

	// set things up so that it looks like we're running a CLI command (for now!)
	rootCmd := &cobra.Command{}

	legacyAmino := amino.NewLegacyAmino()
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	marshaler := amino.NewProtoCodec(interfaceRegistry)
	txConfig := authtx.NewTxConfig(marshaler, authtx.DefaultSignModes)

	//enccodec.RegisterLegacyAminoCodec(legacyAmino)
	//enccodec.RegisterInterfaces(interfaceRegistry)

	clientCtx := client.Context{}.
		WithCodec(marshaler).
		WithInterfaceRegistry(interfaceRegistry).
		WithTxConfig(txConfig).
		WithLegacyAmino(legacyAmino).
		WithInput(os.Stdin).
		WithAccountRetriever(authtypes.AccountRetriever{}).
		WithHomeDir("NO-DEFAULT-HOME").
		WithKeyringOptions(qadenakr.Option()).
		WithViper(EnvPrefix)

	kb := keyring.NewInMemory(clientCtx.Codec, qadenakr.Option())

	flags.AddTxFlagsToCmd(rootCmd)

	rootCmd.Flags().Set(flags.FlagChainID, chainID)

	var err error

	clientCtx, err = client.ReadPersistentCommandFlags(clientCtx, rootCmd.Flags())
	if err != nil {
		fmt.Errorf("couldn't read persistent command flags " + err.Error() + "\n")
		t.Errorf("couldn't read persistent command flags " + err.Error() + "\n")
	}

	clientCtx.SkipConfirm = true

	clientCtx = clientCtx.WithKeyring(kb)

	isEphemeral := false
	argEphAccountIndex := uint32(0)
	accountMnemonic := []string{
		"inherit rebel absorb diamond leopard lens approve deny balcony toast merry text metal pair diamond lumber gravity song liberty pumpkin goddess nature slush basic",
		"palace friend deposit baby crunch flag airport mistake enlist island auction phrase double truck coffee salad hidden story orange couch useful feature electric crush",
		"join total tent make bone program uncle pitch prize body night snake chest mass switch glad opera security evidence catch maid behave gloom ahead",
		"wealth scatter potato bacon glass any present reopen box patrol divide erase tube matter half maze sugar tackle trial duty river eight fragile arctic",
	}

	pubKeys := make([]string, count)
	privKeys := make([]string, count)
	//addresses := make([]string, count)

	for i := 0; i < count; i++ {
		keyName := fmt.Sprintf("testName%d", i)

		createPublicKeyForTrxReq := PublicKeyReq{
			FriendlyName:    keyName,
			RecoverMnemonic: accountMnemonic[i],
			IsEphemeral:     isEphemeral,
			EphAccountIndex: argEphAccountIndex,
		}

		_, _, _, pubKey, err := CreatePublicKey(clientCtx, createPublicKeyForTrxReq)
		if err != nil {
			t.Errorf("Couldn't create public key for %s: %v", keyName, err)
		}

		_, _, walletPubKey, walletPrivKeyHex, err := GetAddress(clientCtx, keyName)
		if err != nil {
			t.Errorf("Couldn't get address for %s: %v", keyName, err)
		}

		privKeys[i] = walletPrivKeyHex + "_privkhex:" + walletPubKey + "_privk"
		pubKeys[i] = pubKey
		/*
			fmt.Println("pubKey hex", pubKey)
			fmt.Println("privKey hex", walletPrivKeyHex)

		*/
	}

	return pubKeys, privKeys
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

func TestAddress(t *testing.T) {
	setupConfig()
	pubKeys, privKeys := GenerateKeys(t, 1)

	fmt.Println("pubKey", pubKeys[0])
	fmt.Println("privKey", privKeys[0])

	pubkbytes, _ := base64.StdEncoding.DecodeString(pubKeys[0])
	ecPoint, _ := ECPointFromBytes(pubkbytes)

	fmt.Println("ecPoint", ecPoint)

	// check if is on curve
	fmt.Println("IsOnCurve", ECPedersen.Curve.IsOnCurve(ecPoint.X, ecPoint.Y))
	bech32Address := ecPoint.Bech32Address()
	fmt.Println("bech32Address", bech32Address)

	b64 := ecPoint.B64Address()
	fmt.Println("b64", b64)

}

func TestProtoUnproto(t *testing.T) {
	// create a new ECPoint
	//	convert "1234" to big.Int

	x, err := big.NewInt(0).SetString("15045532540185210796115304411577244178345486756514790769917116521566223995353", 10)
	y, err := big.NewInt(0).SetString("93948152462490931584246311174809229366570463085366411531424358318469650970706", 10)

	_ = err

	ECPoint := NewECPoint(x, y)
	fmt.Println("ECPoint", ECPoint)
	// check if is on curve
	fmt.Println("IsOnCurve", ECPedersen.Curve.IsOnCurve(x, y))
	// protoize
	protoBECPoint := ProtoizeBECPoint(ECPoint)
	fmt.Println("protoBECPoint", protoBECPoint)
	// unprotoize
	unprotoECPoint := UnprotoizeBECPoint(protoBECPoint)
	fmt.Println("unprotoECPoint", unprotoECPoint)

}

func TestBIntProtoUnproto(t *testing.T) {

	x, _ := big.NewInt(0).SetString("15045532540185210796115304411577244178345486756514790769917116521566223995353", 10)
	// print x
	fmt.Println("x", x)
	// print lenght of x
	fmt.Println("string length of x", len(x.String()))

	px := ProtoizeBInt(x)
	// print size of px
	fmt.Println("size of px", len(px.I))
	y := UnprotoizeBInt(px)
	// print y
	fmt.Println("y", y)

	// fail the test if x and y are not equal
	if x.Cmp(y) != 0 {
		t.Errorf("x and y are not equal")
	}

	// try negative number
	x, _ = big.NewInt(0).SetString("-15045532540185210796115304411577244178345486756514790769917116521566223995353", 10)
	// print x
	fmt.Println("x", x)
	// print lenght of x
	fmt.Println("string length of x", len(x.String()))

	px = ProtoizeBInt(x)
	// print size of px
	fmt.Println("size of px", len(px.I))
	y = UnprotoizeBInt(px)
	// print y
	fmt.Println("y", y)

	// fail the test if x and y are not equal
	if x.Cmp(y) != 0 {
		t.Errorf("x and y are not equal")
	}
}

func TestBInt2ProtoUnproto(t *testing.T) {

	x, _ := big.NewInt(0).SetString("15045532540185210796115304411577244178345486756514790769917116521566223995353", 10)
	// print x
	fmt.Println("x", x)
	// print lenght of x
	fmt.Println("string length of x", len(x.String()))

	px := ProtoizeBInt(x)
	// print size of px
	fmt.Println("size of px", len(px.I))
	y := UnprotoizeBInt(px)
	// print y
	fmt.Println("y", y)

	// fail the test if x and y are not equal
	if x.Cmp(y) != 0 {
		t.Errorf("x and y are not equal")
	}

	// try negative number
	x, _ = big.NewInt(0).SetString("-15045532540185210796115304411577244178345486756514790769917116521566223995353", 10)
	// print x
	fmt.Println("x", x)
	// print lenght of x
	fmt.Println("string length of x", len(x.String()))

	px = ProtoizeBInt(x)
	// print size of px
	fmt.Println("size of px", len(px.I))

	// print px
	fmt.Println("px", hex.EncodeToString(px.I))
	y = UnprotoizeBInt(px)
	// print y
	fmt.Println("y", y)

	// fail the test if x and y are not equal
	if x.Cmp(y) != 0 {
		t.Errorf("x and y are not equal")
	}

}
