package cli

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"

	"qadena/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdktypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"

	"fmt"

	qadenatx "qadena/x/qadena/client/tx"
	//	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	//	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	"math/big"
	"math/rand"
	"time"

	"errors"
	"strings"

	"github.com/cometbft/cometbft/crypto/tmhash"

	c "qadena/x/qadena/common"

	"cosmossdk.io/math"
)

var _ = strconv.Itoa(0)

func CmdReceiveFunds() *cobra.Command {
	var argMnemonic string
	cmd := &cobra.Command{
		Use:   "receive-funds [eph-wallet-id] [to-transparent-amount (e.g. 42qdn | all)]",
		Short: "Broadcast message ReceiveFunds",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argEphWalletID := args[0]

			argTransparentAmount := args[1]

			token := ""

			var transparentAmount math.Int

			if argTransparentAmount == "all" {
				transparentAmount = math.NewInt(-1)
			} else {
				transparentAmountCoin, err := sdktypes.ParseCoinNormalized(argTransparentAmount)
				if err != nil {
					return err
				}
				transparentAmount = transparentAmountCoin.Amount
				token = transparentAmountCoin.Denom
				if token == types.AQadenaTokenDenom {
					token = types.QadenaTokenDenom
				}
			}

			fmt.Println("token", token)
			fmt.Println("transparentAmount", transparentAmount)

			s1 := rand.NewSource(time.Now().UnixNano())
			r1 := rand.New(s1)

			txID := "tx-" + strconv.Itoa(r1.Intn(1000))
			nonce := "nonce-" + strconv.Itoa(r1.Intn(1000))

			ctx, err := client.GetClientTxContext(cmd)

			if err != nil {
				return err
			}

			var dstWalletID string
			var dstPubKey string
			var dstPrivKeyHex string
			if strings.Index(argEphWalletID, "qadena") < 0 {
				dstWalletID, _, dstPubKey, dstPrivKeyHex, err = c.GetAddress(ctx, ctx.GetFromAddress().String())
				if err != nil {
					return err
				}
			} else {
				kb := c.GetKeyring(ctx)

				algo, err := c.GetAlgo(kb)
				if err != nil {
					fmt.Println("Couldn't get keyring algo", err)
					return err
				}

				var bip39Passphrase = c.GetBip39PassPhrase()

				hdPath := hd.CreateHDPath(sdk.GetConfig().GetCoinType(), 0, 0).String()

				// create master key and derive first key for keyring
				derivedPriv, err := algo.Derive()(argMnemonic, bip39Passphrase, hdPath)
				if err != nil {
					return err
				}

				privKey := algo.Generate()(derivedPriv)
				dstPrivKeyHex = hex.EncodeToString(privKey.Bytes())
				dstPubKey = base64.StdEncoding.EncodeToString(privKey.PubKey().Bytes())
				dstWalletID = sdk.AccAddress(privKey.PubKey().Address()).String()
			}

			dstTransactionPrivateKey := dstPrivKeyHex + "_privkhex:" + dstPubKey + "_privk"
			fmt.Println("dstPrivKeyHex", dstPrivKeyHex)
			fmt.Println("but will use priv key", dstTransactionPrivateKey)
			fmt.Println("dstWalletID", dstWalletID)
			fmt.Println("ephWalletID (friendly name)", argEphWalletID)
			fmt.Println("txID", txID)
			fmt.Println("nonce", nonce)

			dstWallet, err := c.GetWallet(ctx, dstWalletID)
			if err != nil {
				return err
			}
			fmt.Println("dstWallet", dstWallet)

			// get service provider public key
			var dstServiceProviderIntervalPubK []string = make([]string, 0)

			for i := range dstWallet.ServiceProviderID {
				_, pubK, err := c.GetIntervalPublicKey(ctx, dstWallet.ServiceProviderID[i], types.ServiceProviderNodeType)
				if err != nil {
					fmt.Println("Couldn't get service provider interval public key")
					return err
				}

				dstServiceProviderIntervalPubK = append(dstServiceProviderIntervalPubK, pubK)
			}

			jarID, err := c.GetJarForPioneer(ctx, dstWallet.HomePioneerID)
			if err != nil {
				return err
			}
			fmt.Println("jarID", jarID)

			jarIntervalPubKID, jarIntervalPubK, err := c.GetIntervalPublicKey(ctx, jarID, types.JarNodeType)
			if err != nil {
				return err
			}
			fmt.Println("jarIntervalPubKID", jarIntervalPubKID, "jarIntervalPubK", jarIntervalPubK)

			//var wa c.WalletAmount

			var ewa types.EncryptableWalletAmount

			// check whether the token is supported
			if _, ok := dstWallet.WalletAmount[token]; ok {
				unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(dstWallet.WalletAmount[token].WalletAmountVShareBind)
				err = c.VShareBDecryptAndProtoUnmarshal(dstTransactionPrivateKey, dstPubKey, unprotoWalletAmountVShareBind, dstWallet.WalletAmount[token].EncWalletAmountVShare, &ewa)
				if err != nil {
					return err
				}
				if c.Debug {
					fmt.Println("decrypted wallet amount", ewa)
				}
			} else {
				ewa.Nonce = nonce
				ewa.TransactionID = txID
				ewa.PedersenCommit = c.ProtoizeEncryptablePedersenCommit(c.NewPedersenCommit(big.NewInt(0), nil))
			}

			var ephWalletID string
			var ephPubKey string
			var ephPrivKeyHex string
			if strings.Index(argEphWalletID, "qadena") < 0 {
				ephWalletID, _, ephPubKey, ephPrivKeyHex, err = c.GetAddress(ctx, argEphWalletID)
				if err != nil {
					return err
				}
			} else {
				kb := c.GetKeyring(ctx)

				algo, err := c.GetAlgo(kb)
				if err != nil {
					fmt.Println("Couldn't get keyring algo", err)
					return err
				}

				var bip39Passphrase = c.GetBip39PassPhrase()

				hdPath := hd.CreateHDPath(sdk.GetConfig().GetCoinType(), 0, 1).String()

				// create master key and derive first key for keyring
				derivedPriv, err := algo.Derive()(argMnemonic, bip39Passphrase, hdPath)
				if err != nil {
					return err
				}

				privKey := algo.Generate()(derivedPriv)
				ephPrivKeyHex = hex.EncodeToString(privKey.Bytes())
				ephPubKey = base64.StdEncoding.EncodeToString(privKey.PubKey().Bytes())
				ephWalletID = sdk.AccAddress(privKey.PubKey().Address()).String()
			}

			ephTransactionPrivateKey := ephPrivKeyHex + "_privkhex:" + ephPubKey + "_privk"
			fmt.Println("ephPrivKeyHex", ephPrivKeyHex)
			fmt.Println("but will use priv key", ephTransactionPrivateKey)

			ephWallet, err := c.GetWallet(ctx, ephWalletID)
			if err != nil {
				return err
			}

			fmt.Println("ephWallet", c.PrettyPrint(ephWallet))

			sameWallet := false
			if ephWalletID == dstWalletID {
				fmt.Println("src (eph) and dst are the same!")
				sameWallet = true
			}

			dstPubK, err := c.GetPublicKey(ctx, dstWalletID, types.TransactionPubKType)
			if err != nil {
				return err
			}

			if c.Debug {
				fmt.Println("dst transaction pubk", dstPubK)
			}

			// check if ephWallet.WalletAmount[token] exists
			if _, ok := ephWallet.WalletAmount[token]; !ok {
				return errors.New("There are no funds enqueued for " + token)
			}

			//var ephWA c.WalletAmount
			var ephEWA types.EncryptableWalletAmount

			unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(ephWallet.WalletAmount[token].WalletAmountVShareBind)
			c.VShareBDecryptAndProtoUnmarshal(ephTransactionPrivateKey, ephPubKey, unprotoWalletAmountVShareBind, ephWallet.WalletAmount[token].EncWalletAmountVShare, &ephEWA)

			if c.Debug {
				fmt.Println("ephWA", c.PrettyPrint(ephEWA))
			}

			senderOptions := strings.Split(ephWallet.SenderOptions, ",")

			fmt.Println("senderOptions" + c.PrettyPrint(senderOptions))

			if findSenderOption(senderOptions, types.RequireSenderFirstNamePersonalInfoSenderOption) {
				pin, ok := big.NewInt(0).SetString(ephEWA.RequiredSenderPIN, 10)
				if !ok {
					return errors.New("RequiredSenderPIN not numerical")
				}
				checkPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(ephEWA.RequiredSenderFirstName))), pin)
				fmt.Println("checkPC", c.PrettyPrint(checkPC))

				found := false
				for _, incomingCheckPC := range ephWallet.WalletAmount[token].RequiredSenderCheckPC {
					fmt.Println("incomingCheckPC", c.PrettyPrint(incomingCheckPC))
					unprotoIncomingCheckPC := c.UnprotoizeBPedersenCommit(incomingCheckPC)
					if c.ComparePedersenCommit(checkPC, unprotoIncomingCheckPC) {
						found = true
						fmt.Println("found a match")
						break
					}
				}

				if !found {
					return errors.New("Couldn't find a validated sender first name")
				}
			}

			if findSenderOption(senderOptions, types.RequireSenderMiddleNamePersonalInfoSenderOption) {
				pin, ok := big.NewInt(0).SetString(ephEWA.RequiredSenderPIN, 10)
				if !ok {
					return errors.New("RequiredSenderPIN not numerical")
				}
				checkPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(ephEWA.RequiredSenderMiddleName))), pin)
				fmt.Println("checkPC", c.PrettyPrint(checkPC))

				found := false
				for _, incomingCheckPC := range ephWallet.WalletAmount[token].RequiredSenderCheckPC {
					fmt.Println("incomingCheckPC", c.PrettyPrint(incomingCheckPC))
					unprotoIncomingCheckPC := c.UnprotoizeBPedersenCommit(incomingCheckPC)
					if c.ComparePedersenCommit(checkPC, unprotoIncomingCheckPC) {
						found = true
						fmt.Println("found a match")
						break
					}
				}

				if !found {
					return errors.New("Couldn't find a validated sender middle name")
				}
			}

			if findSenderOption(senderOptions, types.RequireSenderLastNamePersonalInfoSenderOption) {
				pin, ok := big.NewInt(0).SetString(ephEWA.RequiredSenderPIN, 10)
				if !ok {
					return errors.New("RequiredSenderPIN not numerical")
				}
				checkPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(ephEWA.RequiredSenderLastName))), pin)
				fmt.Println("checkPC", c.PrettyPrint(checkPC))

				found := false
				for _, incomingCheckPC := range ephWallet.WalletAmount[token].RequiredSenderCheckPC {
					fmt.Println("incomingCheckPC", c.PrettyPrint(incomingCheckPC))
					unprotoIncomingCheckPC := c.UnprotoizeBPedersenCommit(incomingCheckPC)
					if c.ComparePedersenCommit(checkPC, unprotoIncomingCheckPC) {
						found = true
						fmt.Println("found a match")
						break
					}
				}

				if !found {
					return errors.New("Couldn't find a validated sender last name")
				}
			}

			transferPrimePC := c.UnprotoizeEncryptablePedersenCommit(ephEWA.PedersenCommit)

			if !c.ValidatePedersenCommit(transferPrimePC) {
				fmt.Println("transferPrimePC is not valid")
				return types.ErrGenericPedersen
			}

			fmt.Println("transferPrimePC", c.PrettyPrint(transferPrimePC))

			unprotoWalletAmountPedersenCommit := c.UnprotoizeBPedersenCommit(ephWallet.WalletAmount[token].WalletAmountPedersenCommit)
			if !transferPrimePC.C.Equal(unprotoWalletAmountPedersenCommit.C) {
				fmt.Println("transferPrimePC.C is different than ephWallet.WalletAmountPedersenCommit.C")
				return types.ErrGenericPedersen
			}

			if transparentAmount.IsNegative() {
				transparentAmount = math.NewIntFromBigInt(c.UnprotoizeBInt(ephEWA.PedersenCommit.A))
				fmt.Println("transparentAmount set to", transparentAmount)
			}

			anonymizerBankTransferBlindingFactor, err := c.GenerateRandomBlindingFactor()
			if err != nil {
				fmt.Println("got error", err)
				return err
			}

			// this needs jar/anonymizer and optional finance service providers
			anonymizerCCPubK := make([]c.VSharePubKInfo, 0)

			anonymizerCCPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, anonymizerCCPubK, dstWallet.HomePioneerID, true) // excludeSSIntervalPubK
			if err != nil {
				return err
			}

			// add optional service providers to ccPubK
			anonymizerCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, anonymizerCCPubK, dstWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
			if err != nil {
				return err
			}

			encAnonymizerBankTransferBlindingFactorVShare, anonimizerBankTransferBlindingFactorVShareBind := c.ProtoMarshalAndVShareBEncrypt(anonymizerCCPubK, c.ProtoizeBInt(anonymizerBankTransferBlindingFactor))

			bankPC := c.NewPedersenCommit(transparentAmount.BigInt(), anonymizerBankTransferBlindingFactor) // random blinding factor

			if c.Debug {
				fmt.Println("bankPC", bankPC)
				if bankPC != nil {
					fmt.Println("bankPC commitment", bankPC.C)
				}
			}

			// need to compute double-prime PC
			transferDoublePrimePC := c.SubPedersenCommit(transferPrimePC, bankPC)

			if c.Debug {
				fmt.Println("transferDoublePrimePC", transferDoublePrimePC)
				if transferDoublePrimePC != nil {
					fmt.Println("transferDoublePrimePC commitment", transferDoublePrimePC.C)
				}
			}

			if c.ValidateSubPedersenCommit(transferPrimePC, transferDoublePrimePC, bankPC) {
				if c.Debug {
					fmt.Println("validated transferPrimePC - transferDoublePrimePC - bankPC = 0")
				}
			} else {
				return types.ErrGenericPedersen
			}

			dequeue := false
			if !sameWallet || (sameWallet && transferDoublePrimePC.A.Cmp(c.BigIntZero) == 0) {
				dequeue = true
			}

			dstPC := c.UnprotoizeEncryptablePedersenCommit(ewa.PedersenCommit)

			var newDstPC *c.PedersenCommit

			if sameWallet {
				newDstPC = c.SubPedersenCommit(dstPC, bankPC)

				if c.ValidateSubPedersenCommit(dstPC, bankPC, newDstPC) {
					if c.Debug {
						fmt.Println("validated dstPC - bankPC - newDstPC = 0")
					}
				} else {
					return types.ErrGenericPedersen
				}
			} else {
				newDstPC = c.AddPedersenCommit(dstPC, transferDoublePrimePC)

				if c.ValidateAddPedersenCommit(dstPC, transferDoublePrimePC, newDstPC) {
					if c.Debug {
						fmt.Println("validated dstPC - transferDoublePrimePC - newDstPC = 0")
					}
				} else {
					return types.ErrGenericPedersen
				}
			}

			ewa.PedersenCommit = c.ProtoizeEncryptablePedersenCommit(newDstPC)
			ewa.Nonce = nonce
			ewa.TransactionID = txID

			// new wallet's balance, needs optional finance service providers
			// nodes who will be cc'd
			dstCCPubK := []c.VSharePubKInfo{
				{PubK: dstPubK, NodeID: "", NodeType: ""},
			}

			// add optional service providers to ccPubK
			dstCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, dstCCPubK, dstWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
			if err != nil {
				return err
			}

			encNewWalletAmountVShare, newWalletAmountVShareBind := c.ProtoMarshalAndVShareBEncrypt(dstCCPubK, &ewa)

			if c.Debug {
				fmt.Println("encNewWalletAmount", encNewWalletAmountVShare)
			}

			// range proof for transferPC
			var transferPCProof *c.RangeProofV2

			// copying the logic below
			if sameWallet {
				transferPCProof = c.NewRangeProofV2(c.GetVectorBase(), bankPC)
			} else {
				transferPCProof = c.NewRangeProofV2(c.GetVectorBase(), transferDoublePrimePC)
			}

			// "protoize" the rangeproofs *before* they get zeroed-out below
			protoTransferPCProof := c.ProtoizeBRangeProof(transferPCProof)
			protoNewDstPCProof := c.ProtoizeBRangeProof(c.NewRangeProofV2(c.GetVectorBase(), newDstPC))

			if c.DebugAmounts {
			} else {
				dstPC.A = c.BigIntZero
				dstPC.X = c.BigIntZero
				transferDoublePrimePC.A = c.BigIntZero
				transferDoublePrimePC.X = c.BigIntZero
				newDstPC.A = c.BigIntZero
				newDstPC.X = c.BigIntZero
			}

			var ephEWalletID types.EncryptableReceiveFundsEWalletID
			ephEWalletID.Nonce = nonce
			ephEWalletID.WalletID = ephWalletID
			if !dequeue {
				ephEWalletID.ExtraParms = new(types.EncryptableReceiveFundsEWalletIDExtraParms)
				ephEWalletID.ExtraParms.Queue = "no-dequeue"
			}

			// unused
			//			encSSEphEWalletID := c.MarshalAndEncrypt(ssIntervalPubK, ephEWalletID)
			//			encJarEphEWalletID := c.MarshalAndEncrypt(jarIntervalPubK, ephEWalletID)

			//			encJarBankPC := c.MarshalAndEncrypt(jarIntervalPubK, bankPC)

			protoDstPC := c.ProtoizeBPedersenCommit(dstPC)

			var protoTransferPC *types.BPedersenCommit

			if sameWallet {
				if c.DebugAmounts {
				} else {
					bankPC.A = c.BigIntZero
					bankPC.X = c.BigIntZero
				}
				protoTransferPC = c.ProtoizeBPedersenCommit(bankPC)
			} else {
				protoTransferPC = c.ProtoizeBPedersenCommit(transferDoublePrimePC)
			}
			protoNewDstPC := c.ProtoizeBPedersenCommit(newDstPC)

			// protoBankPC := c.ProtoizePedersenCommit(*bankPC)

			creator := ""
			if strings.Index(argEphWalletID, "qadena") < 0 {
				creator = ctx.GetFromAddress().String()
			} else {
				creator = dstWalletID
			}

			// the vshare
			receiveFunds := types.EncryptableReceiveFunds{
				EphEWalletID: &ephEWalletID,
			}

			receiveFundsCCPubK := []c.VSharePubKInfo{
				{PubK: dstPubK, NodeID: "", NodeType: ""},
			}

			receiveFundsCCPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, receiveFundsCCPubK, dstWallet.HomePioneerID, true) // excludeSSIntervalPubK
			if err != nil {
				return err
			}

			// add optional service providers to ccPubK
			receiveFundsCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, receiveFundsCCPubK, dstWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
			if err != nil {
				return err
			}

			encReceiveFundsVShare, receiveFundsVShareBind := c.ProtoMarshalAndVShareBEncrypt(receiveFundsCCPubK, &receiveFunds)

			if receiveFundsVShareBind == nil {
				fmt.Println("ERROR! ProtoMarshalAndVShareBEncrypt() failed!")
				// return err
				return errors.New("could not ProtoMarshalAndVShareBEncrypt()")

			}

			// create the "protoized" bind data
			protoReceiveFundsVShareBind := c.ProtoizeVShareBindData(receiveFundsVShareBind)

			msg := types.NewMsgReceiveFunds(
				creator,                  // Creator
				txID,                     // TransactionID
				protoDstPC,               // DestinationPC
				protoTransferPC,          // TransferPC
				protoNewDstPC,            // NewDestinationPC
				encNewWalletAmountVShare, // EncNewDestinationWalletAmount
				c.ProtoizeVShareBindData(newWalletAmountVShareBind),                      // EncNewDestinationWalletAmountBind
				encAnonymizerBankTransferBlindingFactorVShare,                            // EncAnonymizerBankTransferBlindingFactor
				c.ProtoizeVShareBindData(anonimizerBankTransferBlindingFactorVShareBind), // EncAnonymizerBankTransferBlindingFactorBind
				c.ProtoizeBInt(transparentAmount.BigInt()),                               // BankTransparentAmount
				token,                       // Token
				protoTransferPCProof,        // TransferPCProof
				protoNewDstPCProof,          // NewDestinationPCProof
				encReceiveFundsVShare,       // the ciphertext of the vshare
				protoReceiveFundsVShareBind, // bind
			)

			fmt.Println("msg", c.PrettyPrint(msg))

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "receive funds", msg)

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argMnemonic, "mnemonic", "", "Account mnemonic for debugging purposes")

	return cmd
}
