package cli

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	//	"encoding/hex"
	//"encoding/json"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

	//	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	//	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdktypes "github.com/cosmos/cosmos-sdk/types"
	//sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	sdkerrors "cosmossdk.io/errors"
	"github.com/spf13/cobra"

	"errors"
	"math/big"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cometbft/cometbft/crypto/tmhash"
)

var _ = strconv.Itoa(0)

func CmdTransferFunds() *cobra.Command {
	var argAcceptPassword string
	var argMatchFirstName string
	var argMatchMiddleName string
	var argMatchLastName string
	var argNote string
	var argOptInReason string

	cmd := &cobra.Command{
		Use:   "transfer-funds [dst-wallet-id] [from-encrypted-amount (e.g. 13aqdn)] [from-transparent-amount (e.g. 0aqdn)]",
		Short: "Broadcast message TransferFunds",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// declare all available passed arguments here
			argDstWalletID := args[0]
			argHiddenTransferAmount := args[1]
			argTransparentTransferAmount := args[2]

			argMatchFirstName = strings.ToLower(strings.TrimSpace(argMatchFirstName))
			argMatchMiddleName = strings.ToLower(strings.TrimSpace(argMatchMiddleName))
			argMatchLastName = strings.ToLower(strings.TrimSpace(argMatchLastName))

			// parse the passed argument amount into a Coin struct
			hiddenAmountCoin, err := sdktypes.ParseCoinNormalized(argHiddenTransferAmount)
			if err != nil {
				return err
			}
			hiddenAmount := hiddenAmountCoin.Amount
			tokenDenom := hiddenAmountCoin.Denom

			fmt.Println("amount", hiddenAmount)
			fmt.Println("token", tokenDenom)

			if tokenDenom == types.AQadenaTokenDenom {
				tokenDenom = types.QadenaTokenDenom
			}

			// parse the passed argument amount into a Coin struct
			transparentAmountCoin, err := sdktypes.ParseCoinNormalized(argTransparentTransferAmount)
			if err != nil {
				return err
			}
			transparentAmount := transparentAmountCoin.Amount
			fmt.Println("transparentAmount", transparentAmount)

			// check if transparentAmountCoin.Denom is the same as hiddenAmountCoin.Denom
			if transparentAmountCoin.Denom != hiddenAmountCoin.Denom {
				return errors.New("transparent amount token must be the same as hidden amount token")
			}

			// generate a random transaction ID and nonce ID
			s1 := rand.NewSource(time.Now().UnixNano())
			r1 := rand.New(s1)

			txID := "tx-" + strconv.Itoa(r1.Intn(1000))
			nonce := "nonce-" + strconv.Itoa(r1.Intn(1000))

			// get the client context
			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// get source wallet ID, source public key in bytes, source public key and source private key hex
			srcWalletID, _, srcPubKey, srcPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			// generate source transaction private key
			srcTransactionPrivateKey := srcPrivKeyHex + "_privkhex:" + srcPubKey + "_privk"

			fmt.Println("srcPrivKeyHex", srcPrivKeyHex)
			fmt.Println("but will use priv key", srcTransactionPrivateKey)
			fmt.Println("srcWalletID", srcWalletID)
			fmt.Println("srcPubKey", srcPubKey)
			fmt.Println("eph dstWalletID (friendly name)", argDstWalletID)
			fmt.Println("txID", txID)
			fmt.Println("nonce", nonce)
			fmt.Println("transferAmount", argHiddenTransferAmount)

			_, _, srcCredPubKey, srcCredPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromName()+"-credential")
			if err != nil {
				return err
			}
			srcCredPrivateKey := srcCredPrivKeyHex + "_privkhex:" + srcCredPubKey + "_privk"

			// get wallet struct by source wallet ID
			srcWallet, err := c.GetWallet(ctx, srcWalletID)
			if err != nil {
				return err
			}

			fmt.Println("srcWallet", srcWallet)

			// initiate a new WalletAmount struct
			//var srcWA c.WalletAmount
			var srcEWA types.EncryptableWalletAmount

			// check whether the token is supported
			if _, ok := srcWallet.WalletAmount[tokenDenom]; ok {
				unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(srcWallet.WalletAmount[tokenDenom].WalletAmountVShareBind)
				err = c.VShareBDecryptAndProtoUnmarshal(srcTransactionPrivateKey, srcPubKey, unprotoWalletAmountVShareBind, srcWallet.WalletAmount[tokenDenom].EncWalletAmountVShare, &srcEWA)
				if err != nil {
					return err
				}

				if c.Debug {
					fmt.Println("decrypted wallet amount", srcEWA)
				}
			} else {
				srcEWA.Nonce = nonce
				srcEWA.TransactionID = txID
				srcEWA.PedersenCommit = c.ProtoizeEncryptablePedersenCommit(c.NewPedersenCommit(big.NewInt(0), nil))
			}

			// get service provider public key
			var srcServiceProviderIntervalPubK []string = make([]string, 0)

			for i := range srcWallet.ServiceProviderID {
				_, pubK, err := c.GetIntervalPublicKey(ctx, srcWallet.ServiceProviderID[i], types.ServiceProviderNodeType)
				if err != nil {
					fmt.Println("Couldn't get service provider interval public key")
					return err
				}

				srcServiceProviderIntervalPubK = append(srcServiceProviderIntervalPubK, pubK)
			}

			var dstWalletID string
			if strings.Index(argDstWalletID, "qadena") < 0 {
				dstWalletID, _, _, _, err = c.GetAddress(ctx, argDstWalletID)
				if err != nil {
					return err
				}
			} else {
				dstWalletID = argDstWalletID
			}

			fmt.Println("dstWalletID", dstWalletID)

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

			if dstWallet.EphemeralWalletAmountCount[tokenDenom] == types.QadenaRealWallet {
				return errors.New("dst-wallet-id needs to be an ephemeral address")
			}

			senderOptions := strings.Split(dstWallet.SenderOptions, ",")

			fmt.Println("senderOptions" + c.PrettyPrint(senderOptions))

			dstPubK, err := c.GetPublicKey(ctx, dstWalletID, types.TransactionPubKType)

			if err != nil {
				return err
			}

			if c.Debug {
				fmt.Println("dst transaction pubk", dstPubK)
				fmt.Println("src transaction pubk", srcPubKey)
			}

			srcPC := c.UnprotoizeEncryptablePedersenCommit(srcEWA.PedersenCommit) // first commitment, aka beginning hidden balance
			// if c.Debug print sourcePC
			if c.Debug {
				fmt.Println("srcPC", srcPC)
			}

			hiddenTransferPC := c.NewPedersenCommit(hiddenAmount.BigInt(), nil) // second commitment, aka transfer hidden value
			// if c.Debug print newSrcPC
			newSrcPC := c.SubPedersenCommit(srcPC, hiddenTransferPC) // third commitment, aka ending hidden balance
			if c.Debug {
				fmt.Println("newSrcPC", newSrcPC)
			}

			if c.Debug {
				fmt.Println("hiddenTransferPC", hiddenTransferPC)
			}

			//  validatePC(sourcePC - transferPC = newSourcePC)
			if c.ValidateSubPedersenCommit(srcPC, hiddenTransferPC, newSrcPC) {
				if c.Debug {
					fmt.Println("validated srcPC - hiddenTransferPC - newSrcPC = 0")
				}
			} else {
				return types.ErrGenericPedersen
			}

			transparentTransferBF, err := c.GenerateRandomBlindingFactor()

			if err != nil {
				fmt.Println("got error", err)
				return err
			}

			transparentTransferPC := c.NewPedersenCommit(transparentAmount.BigInt(), transparentTransferBF) // random blinding factor

			if c.Debug {
				if transparentTransferPC != nil {
					fmt.Println("transparentTransferPC", transparentTransferPC)
				}
			}

			if c.ValidatePedersenCommit(transparentTransferPC) {
				if c.Debug {
					fmt.Println("validated transparentTransferPC")
				}
			} else {
				return types.ErrGenericPedersen
			}

			// compute total of transparentTransfer + hiddenTransfer
			totalTransferPrimePC := c.AddPedersenCommit(transparentTransferPC, hiddenTransferPC)

			if c.Debug {
				fmt.Println("totalTransferPrimePC", totalTransferPrimePC)
				if totalTransferPrimePC != nil {
					fmt.Println("totalTransferPrimePC commitment", totalTransferPrimePC.C)
				}
			}

			if c.ValidateAddPedersenCommit(transparentTransferPC, hiddenTransferPC, totalTransferPrimePC) {
				if c.Debug {
					fmt.Println("validated transparentTransferPC + hiddenTransferPC == totalTransferPrimePC")
				}
			} else {
				if c.Debug {
					fmt.Println("INVALID: transparentTransferPC + hiddenTransferPC != totalTransferPrimePC")
				}
				return types.ErrGenericPedersen
			}

			// we could also use a rangeproof to hide the actual value from the JAR scanners (but we'd need to find a proof that commitments all encode the same values)
			// we should add a rangeproof that the transfer value is not out of bounds (i.e. not negative, would not roll-over sums, etc.)

			//var destWA c.WalletAmount
			var destEWA types.EncryptableWalletAmount
			destEWA.PedersenCommit = c.ProtoizeEncryptablePedersenCommit(totalTransferPrimePC)
			destEWA.Nonce = nonce
			destEWA.TransactionID = txID
			destEWA.Note = argNote

			var dstEWalletID types.EncryptableTransferFundsEWalletID
			dstEWalletID.Nonce = nonce
			dstEWalletID.WalletID = dstWalletID

			var tfExtraParms types.EncryptableTransferFundsEWalletIDExtraParms
			if argAcceptPassword != "" {
				if dstWallet.AcceptPasswordPedersenCommit == nil || dstWallet.AcceptPasswordPedersenCommit.C == nil {
					return errors.New("password provided but wallet does not need a password")
				}

				acceptPasswordPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(argAcceptPassword))), big.NewInt(0).SetBytes(tmhash.Sum([]byte(dstWalletID))))
				fmt.Println("computed acceptPasswordPC", c.PrettyPrint(acceptPasswordPC))
				fmt.Println("wallet passwordPC", c.PrettyPrint(dstWallet.AcceptPasswordPedersenCommit))
				unProtoPC := c.UnprotoizeBPedersenCommit(dstWallet.AcceptPasswordPedersenCommit)

				if c.ComparePedersenCommit(acceptPasswordPC, unProtoPC) {
					fmt.Println("PCs match!")
				} else {
					fmt.Println("PC", unProtoPC)
				}

				tfExtraParms.AcceptPasswordPC = c.ProtoizeBPedersenCommit(c.AddPedersenCommitNoMaxCheck(totalTransferPrimePC, acceptPasswordPC))
			}

			if findSenderOption(senderOptions, types.AcceptFirstNamePersonalInfoSenderOption) && argMatchFirstName == "" {
				fmt.Println("WARNING:  Wallet supports " + types.AcceptFirstNamePersonalInfoSenderOption + " but you did not provide a first-name")
			}

			if findSenderOption(senderOptions, types.AcceptMiddleNamePersonalInfoSenderOption) && argMatchMiddleName == "" {
				fmt.Println("WARNING:  Wallet supports " + types.AcceptMiddleNamePersonalInfoSenderOption + " but you did not provide a middle-name")
			}

			if findSenderOption(senderOptions, types.AcceptLastNamePersonalInfoSenderOption) && argMatchLastName == "" {
				fmt.Println("WARNING:  Wallet supports " + types.AcceptLastNamePersonalInfoSenderOption + " but you did not provide a last-name")
			}

			if argMatchFirstName != "" {
				if !findSenderOption(senderOptions, types.AcceptFirstNamePersonalInfoSenderOption) {
					return errors.New("Destination wallet doest not support " + types.AcceptFirstNamePersonalInfoSenderOption)
				}
				tfExtraParms.MatchFirstNameHashHex = tmhash.Sum([]byte(argMatchFirstName))
			}
			if argMatchMiddleName != "" {
				if !findSenderOption(senderOptions, types.AcceptMiddleNamePersonalInfoSenderOption) {
					return errors.New("Destination wallet doest not support " + types.AcceptMiddleNamePersonalInfoSenderOption)
				}
				tfExtraParms.MatchMiddleNameHashHex = tmhash.Sum([]byte(argMatchMiddleName))
			}
			if argMatchLastName != "" {
				if !findSenderOption(senderOptions, types.AcceptLastNamePersonalInfoSenderOption) {
					return errors.New("Destination wallet doest not support " + types.AcceptLastNamePersonalInfoSenderOption)
				}
				tfExtraParms.MatchLastNameHashHex = tmhash.Sum([]byte(argMatchLastName))
			}

			checkPIN := c.BigIntZero

			if findSenderOption(senderOptions, types.RequireSenderFirstNamePersonalInfoSenderOption) {
				fmt.Println("getting credential")
				// get wallet struct by source wallet ID
				credential, err := c.GetCredential(ctx, srcWallet.CredentialID, types.FirstNamePersonalInfoCredentialType)
				if err != nil {
					return err
				}

				// unproto credential.VShareBind
				unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
				var p types.EncryptableSingleContactInfo
				err = c.VShareBDecryptAndProtoUnmarshal(srcCredPrivateKey, srcCredPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
				fmt.Println("p", c.PrettyPrint(p))

				// checkPC will eventually be sent to the receiver
				checkPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(p.Details.Contact))), nil)
				pin, ok := big.NewInt(0).SetString(p.PIN, 10)
				if !ok {
					return errors.New("PIN was not an integer")
				}
				credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(p.Details.Contact))), pin)
				proofPC := c.SubPedersenCommitNoMinCheck(checkPC, credentialPC)
				fmt.Println(credential.CredentialPedersenCommit)
				fmt.Println("credentialPC " + c.PrettyPrint(credentialPC))
				fmt.Println("checkPC " + c.PrettyPrint(checkPC))
				fmt.Println("proofPC " + c.PrettyPrint(proofPC))

				checkPIN = checkPC.X

				if c.DebugAmounts {
				} else {
					proofPC.A = c.BigIntZero
					proofPC.X = c.BigIntZero
					checkPC.A = c.BigIntZero
					checkPC.X = c.BigIntZero
				}

				tfExtraParms.RequiredSenderFirstNameProofPC = c.ProtoizeBPedersenCommit(proofPC)
				tfExtraParms.RequiredSenderFirstNameCheckPC = c.ProtoizeBPedersenCommit(checkPC)
				destEWA.RequiredSenderFirstName = p.Details.Contact
				destEWA.RequiredSenderPIN = checkPIN.String()

			}

			if findSenderOption(senderOptions, types.RequireSenderMiddleNamePersonalInfoSenderOption) {
				fmt.Println("getting credential")
				// get wallet struct by source wallet ID
				credential, err := c.GetCredential(ctx, srcWallet.CredentialID, types.MiddleNamePersonalInfoCredentialType)
				if err != nil {
					return err
				}

				unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
				var p types.EncryptableSingleContactInfo
				err = c.VShareBDecryptAndProtoUnmarshal(srcCredPrivateKey, srcCredPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
				if err != nil {
					return err
				}
				fmt.Println("p", c.PrettyPrint(p))

				// checkPC will eventually be sent to the receiver
				checkPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(p.Details.Contact))), checkPIN)
				pin, ok := big.NewInt(0).SetString(p.PIN, 10)
				if !ok {
					return errors.New("PIN was not an integer")
				}
				credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(p.Details.Contact))), pin)
				proofPC := c.SubPedersenCommitNoMinCheck(checkPC, credentialPC)
				fmt.Println(credential.CredentialPedersenCommit)
				fmt.Println("credentialPC " + c.PrettyPrint(credentialPC))
				fmt.Println("checkPC " + c.PrettyPrint(checkPC))
				fmt.Println("proofPC " + c.PrettyPrint(proofPC))

				destEWA.RequiredSenderMiddleName = p.Details.Contact
				destEWA.RequiredSenderPIN = checkPC.X.String()

				if c.DebugAmounts {
				} else {
					proofPC.A = c.BigIntZero
					proofPC.X = c.BigIntZero
					checkPC.A = c.BigIntZero
					checkPC.X = c.BigIntZero
				}

				tfExtraParms.RequiredSenderMiddleNameProofPC = c.ProtoizeBPedersenCommit(proofPC)
				tfExtraParms.RequiredSenderMiddleNameCheckPC = c.ProtoizeBPedersenCommit(checkPC)
			}

			if findSenderOption(senderOptions, types.RequireSenderLastNamePersonalInfoSenderOption) {
				fmt.Println("getting credential")
				// get wallet struct by source wallet ID
				credential, err := c.GetCredential(ctx, srcWallet.CredentialID, types.LastNamePersonalInfoCredentialType)
				if err != nil {
					return err
				}

				unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
				var p types.EncryptableSingleContactInfo
				err = c.VShareBDecryptAndProtoUnmarshal(srcCredPrivateKey, srcCredPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
				if err != nil {
					return err
				}
				fmt.Println("p", c.PrettyPrint(p))

				// checkPC will eventually be sent to the receiver
				checkPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(p.Details.Contact))), checkPIN)
				pin, ok := big.NewInt(0).SetString(p.PIN, 10)
				if !ok {
					return errors.New("PIN was not an integer")
				}
				credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(p.Details.Contact))), pin)
				proofPC := c.SubPedersenCommitNoMinCheck(checkPC, credentialPC)
				fmt.Println(credential.CredentialPedersenCommit)
				fmt.Println("credentialPC " + c.PrettyPrint(credentialPC))
				fmt.Println("checkPC " + c.PrettyPrint(checkPC))
				fmt.Println("proofPC " + c.PrettyPrint(proofPC))

				destEWA.RequiredSenderLastName = p.Details.Contact
				destEWA.RequiredSenderPIN = checkPC.X.String()

				if c.DebugAmounts {
				} else {
					proofPC.A = c.BigIntZero
					proofPC.X = c.BigIntZero
					checkPC.A = c.BigIntZero
					checkPC.X = c.BigIntZero
				}

				tfExtraParms.RequiredSenderLastNameProofPC = c.ProtoizeBPedersenCommit(proofPC)
				tfExtraParms.RequiredSenderLastNameCheckPC = c.ProtoizeBPedersenCommit(checkPC)
			}

			//tfExtraParms_b, _ := json.Marshal(tfExtraParms)
			dstEWalletID.ExtraParms = &tfExtraParms

			dstCCPubK := []c.VSharePubKInfo{
				{PubK: dstPubK, NodeID: "", NodeType: ""},
			}

			// add optional service providers to ccPubK
			dstCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, dstCCPubK, srcWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
			if err != nil {
				return err
			}

			encNewDestinationWalletAmountVShare, newDestinationWalletAmountVShareBind := c.ProtoMarshalAndVShareBEncrypt(dstCCPubK, &destEWA)

			// note that we don't "zero-out" bankPC because the JAR needs to know bankPC so it can do transparent transfers

			totalTransferPrimePCTransparentTransferBF := types.EncryptableAnonTransferFunds{
				TotalTransferPrimePC:  c.ProtoizeEncryptablePedersenCommit(totalTransferPrimePC),
				TransparentTransferBF: c.ProtoizeBInt(transparentTransferBF),
			}

			// nodes who will be cc'd
			anonymizerCCPubK := make([]c.VSharePubKInfo, 0)

			anonymizerCCPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, anonymizerCCPubK, srcWallet.HomePioneerID, true) // excludeSSIntervalPubK
			if err != nil {
				return err
			}

			// add optional service providers to ccPubK
			anonymizerCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, anonymizerCCPubK, srcWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
			if err != nil {
				return err
			}

			encAnonymizerTotalTransferPrimePCTransparentTransferBFVShare, anonymizerTotalTransferPrimePCTransparentTransferBFVShareBind := c.ProtoMarshalAndVShareBEncrypt(anonymizerCCPubK, &totalTransferPrimePCTransparentTransferBF)

			srcEWA.PedersenCommit = c.ProtoizeEncryptablePedersenCommit(newSrcPC)
			srcEWA.Nonce = nonce
			srcEWA.TransactionID = txID

			srcCCPubK := []c.VSharePubKInfo{
				{PubK: srcPubKey, NodeID: "", NodeType: ""},
			}

			// add optional service providers to ccPubK
			srcCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, srcCCPubK, srcWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
			if err != nil {
				return err
			}

			encNewSrcWalletAmountVShare, newSrcWalletAmountVShareBind := c.ProtoMarshalAndVShareBEncrypt(srcCCPubK, &srcEWA)

			// uncomment these two lines if you want to test without range proofs
			// protoTransferPCProof := c.ProtoizeRangeProof(c.RangeProof{})
			// protoNewSrcPCProof := c.ProtoizeRangeProof(c.RangeProof{})

			// create the proof then "protoize" it before it gets zeroed-out below :P
			protoHiddenTransferPCProof := c.ProtoizeBRangeProof(c.NewRangeProofV2(c.GetVectorBase(), hiddenTransferPC))
			protoNewSrcPCProof := c.ProtoizeBRangeProof(c.NewRangeProofV2(c.GetVectorBase(), newSrcPC))
			/*
				// debug sanity check part 1 start
				transferPCProof := c.NewRangeProof(transferPC)
				newSourcePCProof := c.NewRangeProof(newSourcePC)

				protoTransferPCProof := c.ProtoizeRangeProof(transferPCProof)
				protoNewSrcPCProof := c.ProtoizeRangeProof(newSourcePCProof)

				if (!c.RPVerify(transferPCProof, *transferPC)) {
					fmt.Println("ERROR! RPVerify() failed for transferPCProof!")
				}

				if (!c.RPVerify(newSourcePCProof, *newSourcePC)) {
					fmt.Println("ERROR! RPVerify() failed for newSourcePC!")
				}
				// debug sanity check part 1 end

				// debug sanity check part 2 start
				transferPCProof = c.UnprotoizeRangeProof(protoTransferPCProof)
				newSourcePCProof = c.UnprotoizeRangeProof(protoNewSrcPCProof)

				if (!c.RPVerify(transferPCProof, *transferPC)) {
					fmt.Println("ERROR! RPVerify() failed for transferPCProof part2!")
				}

				if (!c.RPVerify(newSourcePCProof, *newSourcePC)) {
					fmt.Println("ERROR! RPVerify() failed for newSourcePC part2!")
				}
				// debug sanity check part 2 end
			*/

			// we need to save the full hiddenTransferPC because we need to send it to the vshare, and the code below clears the X value and the A value
			fullHiddenTransferPC := hiddenTransferPC

			// the vshare
			vShareTransferFunds := types.EncryptableTransferFunds{
				HiddenTransferPC: c.ProtoizeEncryptablePedersenCommit(fullHiddenTransferPC),
				DstEWalletID:     &dstEWalletID,
				OptInReason:      argOptInReason,
			}
			// print vs
			fmt.Println("vsHiddenTransferPCDstEWalletIDOptInReason", c.PrettyPrint(vShareTransferFunds))

			if c.DebugAmounts {
			} else {
				srcPC.A = c.BigIntZero
				srcPC.X = c.BigIntZero
				hiddenTransferPC.A = c.BigIntZero
				hiddenTransferPC.X = c.BigIntZero
				newSrcPC.A = c.BigIntZero
				newSrcPC.X = c.BigIntZero
			}

			fmt.Println("encNewDestinationWalletAmount", encNewDestinationWalletAmountVShare)
			fmt.Println("encAnonymizerTotalTransferPrimePCTransparentTransferBF", encAnonymizerTotalTransferPrimePCTransparentTransferBFVShare)
			fmt.Println("encNewWalletAmount", encNewSrcWalletAmountVShare)

			protoSrcPC := c.ProtoizeBPedersenCommit(srcPC)
			protoHiddenTransferPC := c.ProtoizeBPedersenCommit(hiddenTransferPC)
			protoNewSrcPC := c.ProtoizeBPedersenCommit(newSrcPC)

			// nodes who will be cc'd for the hiddenTransferPC, dstEWalletID, and argOptInReason
			transferFundsCCPubK := make([]c.VSharePubKInfo, 0)

			transferFundsCCPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, transferFundsCCPubK, srcWallet.HomePioneerID, false)
			if err != nil {
				return err
			}

			// add optional service providers to ccPubK
			transferFundsCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, transferFundsCCPubK, srcWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
			if err != nil {
				return err
			}

			// create S and E; session key and ciphertext, respectively
			encTransferFundsVShare, transferFundsVShareBind := c.ProtoMarshalAndVShareBEncrypt(transferFundsCCPubK, &vShareTransferFunds)

			if transferFundsVShareBind == nil {
				fmt.Println("ERROR! ProtoMarshalAndVShareBEncrypt() failed!")
				// return err
				return errors.New("could not ProtoMarshalAndVShareBEncrypt()")
			}

			// verify the bind data
			if !transferFundsVShareBind.VShareBVerify(encTransferFundsVShare) {
				fmt.Println("ERROR! VerifyBindData() failed!")
			} else {
				fmt.Println("VerifyBindData() succeeded!")
			}

			// create the "protoized" bind data
			protoTransferFundsVShareBind := c.ProtoizeVShareBindData(transferFundsVShareBind)

			msg := types.NewMsgTransferFunds(
				ctx.GetFromAddress().String(), // Creator
				txID,                          // TransactionID
				protoSrcPC,                    // SourcePC
				protoHiddenTransferPC,         // TransferPC
				protoNewSrcPC,                 // NewSourcePC
				encNewSrcWalletAmountVShare,   // EncNewWalletAmount
				c.ProtoizeVShareBindData(newSrcWalletAmountVShareBind), // NewSourceWalletAmountVShareBind
				encNewDestinationWalletAmountVShare,                    // EncNewDestinationWalletAmount
				c.ProtoizeVShareBindData(newDestinationWalletAmountVShareBind),
				encAnonymizerTotalTransferPrimePCTransparentTransferBFVShare, // EncAnonymizerTotalTransferPrimePC
				c.ProtoizeVShareBindData(anonymizerTotalTransferPrimePCTransparentTransferBFVShareBind),
				c.ProtoizeBInt(transparentAmount.BigInt()), // TransparentAmount
				transparentAmountCoin.Denom,                // TokenDenom
				protoHiddenTransferPCProof,                 // HiddenTransferPCProof
				protoNewSrcPCProof,                         // NewSrcPCProof
				encTransferFundsVShare,                     // the ciphertext of the vshare
				protoTransferFundsVShareBind,               // bind
			)

			fmt.Println("msg", c.PrettyPrint(msg)) // this will not print bind

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			err, res := qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "transfer funds", msg)

			if err != nil {
				var err2 *sdkerrors.Error
				if errors.As(err, &err2) {
					fmt.Println("err2", c.PrettyPrint(err2))
					fmt.Println("response", c.PrettyPrint(res))
					if err2.ABCICode() == types.ErrMismatchCredential.ABCICode() {
						fmt.Println("Transfer rejected because credentials didn't match")
						os.Exit(5)
						err = nil
					}
				} else {
					fmt.Println("err", err.Error())
					fmt.Println("response", c.PrettyPrint(res))
				}
			}
			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argAcceptPassword, "accept-password", "", "Accept-password needed to send to ephemeral wallet")
	cmd.Flags().StringVar(&argMatchFirstName, "match-first-name", "", "Only allow send if the ephemeral wallet has a first name and it matches")
	cmd.Flags().StringVar(&argMatchMiddleName, "match-middle-name", "", "Only allow send if the ephemeral wallet has a middle name and it matches")
	cmd.Flags().StringVar(&argMatchLastName, "match-last-name", "", "Only allow send if the ephemeral wallet has a last name and it matches")
	cmd.Flags().StringVar(&argNote, "transfer-note", "", "Note to the receiver of this transaction")
	cmd.Flags().StringVar(&argOptInReason, "opt-in-reason", "", "Reason for compliance purposes")

	return cmd
}
