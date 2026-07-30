package cli

import (
	"strconv"

	"errors"
	"math/big"

	"fmt"

	"github.com/cosmos/cosmos-sdk/client"

	//	"github.com/cosmos/cosmos-sdk/client/tx"
	// NOTE!  WE ARE USING OUR OWN VERSION OF client/tx
	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	proto "github.com/cosmos/gogoproto/proto"
	"github.com/spf13/cobra"
)

var _ = strconv.Itoa(0)

// reblindedCredential is the Pedersen material and re-encrypted payload the enclave needs in
// order to move a credential from the identity provider's blinding factor to the user's own.
// Claim and update build it identically -- see reblindCredential.
type reblindedCredential struct {
	encCredentialInfoVShare  []byte
	credentialInfoVShareBind *c.VShareBindData
	// blinded: the amount and blinding factor are stripped before this leaves the client
	newCredentialPC *c.PedersenCommit
	claimPC         *c.PedersenCommit
	// NOT blinded: the enclave needs zeroPC's A and X to check it commits to zero
	zeroPC *c.PedersenCommit
}

// reblindCredential re-encrypts a credential's plaintext under a fresh PIN and produces the three
// commitments that prove the result is the same data the identity provider issued:
//
//	newCredentialPC = commit(hash(details), newPin)      -- the user's own commitment
//	zeroPC          = ipCredentialPC - newCredentialPC   -- proves the plaintext is unchanged
//	claimPC         = walletPC + newCredentialPC         -- proves the user controls the wallet
//
// The identity provider's commitment is recomputed locally from the plaintext and the PIN it
// issued, rather than read off the chain, which is what makes zeroPC checkable at all.
func reblindCredential(credType string, contactDetails proto.Message, oldPin string, walletPC *c.PedersenCommit, innerCCPubK []c.VSharePubKInfo) (*reblindedCredential, error) {
	all, err := proto.Marshal(contactDetails)
	if err != nil {
		return nil, err
	}

	oldPinInt, ok := big.NewInt(0).SetString(oldPin, 10)
	if !ok {
		return nil, errors.New("pin not numeric")
	}

	ipCredentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(all)), oldPinInt)

	newPin, err := c.GenerateRandomBlindingFactor()
	if err != nil {
		return nil, err
	}

	var ret reblindedCredential

	switch credType {
	case types.PersonalInfoCredentialType:
		var p types.EncryptablePersonalInfo
		var details types.EncryptablePersonalInfoDetails
		if err := proto.Unmarshal(all, &details); err != nil {
			return nil, err
		}
		p.Details = &details
		p.PIN = newPin.String()
		ret.encCredentialInfoVShare, ret.credentialInfoVShareBind = c.ProtoMarshalAndVShareBEncrypt(innerCCPubK, &p)
		if c.Debug {
			fmt.Println("contact", p)
		}
	default:
		var p types.EncryptableSingleContactInfo
		var details types.EncryptableSingleContactInfoDetails
		if err := proto.Unmarshal(all, &details); err != nil {
			return nil, err
		}
		p.Details = &details
		p.PIN = newPin.String()
		ret.encCredentialInfoVShare, ret.credentialInfoVShareBind = c.ProtoMarshalAndVShareBEncrypt(innerCCPubK, &p)
		if c.Debug {
			fmt.Println("contact", p)
		}
	}

	ret.newCredentialPC = c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(all)), newPin)
	ret.claimPC = c.AddPedersenCommitNoMaxCheck(walletPC, ret.newCredentialPC)
	ret.zeroPC = c.SubPedersenCommitNoMinCheck(ipCredentialPC, ret.newCredentialPC)

	if c.Debug {
		fmt.Println("walletPC", c.PrettyPrint(walletPC), "\nnewCredentialPC", c.PrettyPrint(*ret.newCredentialPC), "\nclaimPC", c.PrettyPrint(*ret.claimPC))
	}

	if c.DebugAmounts {
	} else {
		c.BlindPedersenCommit(ret.claimPC)
		c.BlindPedersenCommit(ret.newCredentialPC)
		// NEED TO KEEP zeroPC's A & X
	}

	// Warn rather than fail, as the claim flow has always done: the enclave re-runs both checks
	// and is the authority on them, and DebugAmounts changes what is left unblinded here.
	if !c.ValidateSubPedersenCommit(ipCredentialPC, ret.newCredentialPC, ret.zeroPC) {
		fmt.Println("failed to validate credentialPC - newCredentialPC - zeroPC = 0")
	}

	if c.ValidateAddPedersenCommit(walletPC, ret.newCredentialPC, ret.claimPC) {
		fmt.Println("validated claimPC")
	}

	return &ret, nil
}

func createClaimContactInfoMessage(ctx client.Context, findCredentialPC *c.PedersenCommit, credWalletID string, credPubKey string, credType string, contactDetails proto.Message, oldPin string, credentialHash string, srcWalletID string, srcWallet types.Wallet, ewa types.EncryptableWalletAmount, recover bool) (*types.MsgClaimCredential, error) {

	address := ctx.GetFromAddress().String()

	var err error

	ccPubK := []c.VSharePubKInfo{
		{PubK: credPubKey, NodeID: "", NodeType: ""},
	}

	if !TESTskipRequiredChainCCPubK {
		ccPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, ccPubK, "", false)
		if err != nil {
			return nil, err
		}
	}

	// add optional service providers to ccPubK
	if !TESTskipOptionalCCPubK {
		ccPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, ccPubK, srcWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
		if err != nil {
			return nil, err
		}
	}

	outerCCPubK := ccPubK

	if TESTskipInnerCCPubK {
		ccPubK = []c.VSharePubKInfo{
			{PubK: credPubKey, NodeID: "", NodeType: ""},
		}
	}

	walletPC := c.UnprotoizeEncryptablePedersenCommit(ewa.PedersenCommit)

	reblinded, err := reblindCredential(credType, contactDetails, oldPin, walletPC, ccPubK)
	if err != nil {
		return nil, err
	}

	encWalletIDVShare, walletIDVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &types.EncryptableString{Value: srcWalletID})

	encCredentialHashVShare, credentialHashVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &types.EncryptableString{Value: credentialHash})

	encryptableClaimCredentialExtraParms := types.EncryptableClaimCredentialExtraParms{
		EncCredentialInfoVShare:  reblinded.encCredentialInfoVShare,
		CredentialInfoVShareBind: c.ProtoizeVShareBindData(reblinded.credentialInfoVShareBind),
		WalletID:                 srcWalletID,
		EncWalletIDVShare:        encWalletIDVShare,
		WalletIDVShareBind:       c.ProtoizeVShareBindData(walletIDVShareBind),
		EncCredentialHashVShare:  encCredentialHashVShare,
		CredentialHashVShareBind: c.ProtoizeVShareBindData(credentialHashVShareBind),
		FindCredentialPC:         c.ProtoizeBPedersenCommit(findCredentialPC),
		ClaimPC:                  c.ProtoizeBPedersenCommit(reblinded.claimPC),
		ZeroPC:                   c.ProtoizeEncryptablePedersenCommit(reblinded.zeroPC),
		NewCredentialPC:          c.ProtoizeBPedersenCommit(reblinded.newCredentialPC),
	}

	encClaimCredentialExtraParmsVShare, claimCredentialExtraParmsVShareBind := c.ProtoMarshalAndVShareBEncrypt(outerCCPubK, &encryptableClaimCredentialExtraParms)

	msg := types.NewMsgClaimCredential(
		address,
		credWalletID,
		credType,
		recover,
		encClaimCredentialExtraParmsVShare,
		c.ProtoizeVShareBindData(claimCredentialExtraParmsVShareBind),
	)

	return msg, msg.ValidateBasic()
}

func queryFindCredential(cmd *cobra.Command, argName string, findCredentialPC *c.PedersenCommit, argCredentialType string, p proto.Message, credentialID *string) error {

	ctx, err := client.GetClientTxContext(cmd)
	if err != nil {
		return err
	}

	argNameCredential := argName + "-credential"

	_, _, credPubKey, credPrivKeyHex, err := c.GetAddress(ctx, argNameCredential)
	if err != nil {
		return err
	}

	credPrivateKey := credPrivKeyHex + "_privkhex:" + credPubKey + "_privk"

	fmt.Println("credPubKey", credPubKey, "credPrivateKey", credPrivateKey)

	fmt.Println("findCredentialPC", c.PrettyPrint(findCredentialPC))

	proofPC := c.NewPedersenCommit(findCredentialPC.A, nil)

	checkPC := c.SubPedersenCommitNoMinCheck(findCredentialPC, proofPC)

	fmt.Println("proofPC", c.PrettyPrint(proofPC))

	fmt.Println("checkPC", c.PrettyPrint(checkPC))

	if c.DebugAmounts {
	} else {
		proofPC.A = c.BigIntZero
		proofPC.X = c.BigIntZero
	}

	if !c.ValidateSubPedersenCommit(findCredentialPC, proofPC, checkPC) {
		fmt.Println("failed to validate checkPC - credentialPC - proofPC = 0")
	}

	queryClient := types.NewQueryClient(ctx)

	ssIntervalPubKID, ssIntervalPubK, err := c.GetIntervalPublicKey(ctx, types.SSNodeID, types.SSNodeType)
	if err != nil {
		return err
	}

	fmt.Println("ssIntervalPubKID", ssIntervalPubKID)
	fmt.Println("ssIntervalPubK", ssIntervalPubK)

	encUserCredentialPubKIntervalSSPubK := c.MarshalAndBEncrypt(ssIntervalPubK, credPubKey)
	encProofPCIntervalSSPubK := c.ProtoMarshalAndBEncrypt(ssIntervalPubK, c.ProtoizeBPedersenCommit(proofPC))
	encCheckPCIntervalSSPubK := c.ProtoMarshalAndBEncrypt(ssIntervalPubK, c.ProtoizeEncryptablePedersenCommit(checkPC))
	credentialPC := findCredentialPC.C.Bytes()

	params := &types.QueryFindCredentialRequest{
		CredentialPC:                        credentialPC,
		CredentialType:                      argCredentialType,
		SSIntervalPubKID:                    ssIntervalPubKID,
		EncUserCredentialPubKSSIntervalPubK: encUserCredentialPubKIntervalSSPubK,
		EncProofPCSSIntervalPubK:            encProofPCIntervalSSPubK,
		EncCheckPCSSIntervalPubK:            encCheckPCIntervalSSPubK,
	}

	res, err := queryClient.FindCredential(cmd.Context(), params)
	if err != nil {
		return err
	}

	ctx.PrintProto(res)

	_, err = c.BDecryptAndProtoUnmarshal(credPrivateKey, res.EncPersonalInfoUserCredentialPubK, p)
	if err != nil {
		fmt.Println("couldn't get decrypt personal info")
		return err
	}

	fmt.Println("info", c.PrettyPrint(p))

	_, err = c.BDecryptAndUnmarshal(credPrivateKey, res.EncCredentialIDUserCredentialPubK, credentialID)
	if err != nil {
		fmt.Println("couldn't get decrypt credentialID")
		return err
	}

	fmt.Println("credentialID", credentialID)

	return nil
}

func CmdClaimCredential() *cobra.Command {
	var argRecover bool

	cmd := &cobra.Command{
		Use:   "claim-credential [find-credential-pc amount (e.g. 1234)] [find-credential-pc blinding-factor (e.g. 5678)] [credential-type e.g. personal-info, phone-contact-info, email-contact-info] [--from wallet-friendly-name e.g. ann, al]",
		Short: "Broadcast message ClaimCredential",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argFindCredentialA := args[0]
			argFindCredentialBF := args[1]
			argCredentialType := args[2]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			srcWalletID, _, srcPubKey, srcPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			argName := ctx.GetFromName()

			argCredentialID := argName + "-credential"

			fmt.Println("argCredentialID", argCredentialID)

			credentialID, _, credentialPubKey, _, err := c.GetAddress(ctx, argCredentialID)
			if err != nil {
				return err
			}

			var identityProviderCredentialID string

			var p types.EncryptablePersonalInfo
			var pSCI types.EncryptableSingleContactInfo

			var findCredentialPC *c.PedersenCommit
			findCredentialA, _ := big.NewInt(0).SetString(argFindCredentialA, 10)
			findCredentialBF, _ := big.NewInt(0).SetString(argFindCredentialBF, 10)
			findCredentialPC = c.NewPedersenCommit(findCredentialA, findCredentialBF)

			fmt.Println("findCredentialPC", c.PrettyPrint(findCredentialPC))

			switch argCredentialType {
			case types.PersonalInfoCredentialType:
				err = queryFindCredential(cmd, argName, findCredentialPC, argCredentialType, &p, &identityProviderCredentialID)
				if err != nil {
					return err
				}
			default:
				err = queryFindCredential(cmd, argName, findCredentialPC, argCredentialType, &pSCI, &identityProviderCredentialID)
				if err != nil {
					return err
				}
			}

			srcTransactionPrivateKey := srcPrivKeyHex + "_privkhex:" + srcPubKey + "_privk"
			//			credPrivKey := credentialPrivKeyHex + "_privkhex:" + credentialPubKey + "_privk"

			fmt.Println("srcPrivKeyHex", srcPrivKeyHex)
			fmt.Println("but will use priv key", srcTransactionPrivateKey)
			fmt.Println("srcWalletID", srcWalletID)

			credential, err := c.GetCredential(ctx, identityProviderCredentialID, argCredentialType)
			if err != nil {
				return err
			}
			fmt.Println("credential", c.PrettyPrint(credential))

			msgs := make([]sdk.Msg, 1)

			srcWallet, err := c.GetWallet(ctx, srcWalletID)
			if err != nil {
				return err
			}
			fmt.Println("srcWallet", c.PrettyPrint(srcWallet))

			//var wa c.WalletAmount
			var ewa types.EncryptableWalletAmount
			unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(srcWallet.WalletAmount[types.QadenaTokenDenom].WalletAmountVShareBind)
			err = c.VShareBDecryptAndProtoUnmarshal(srcTransactionPrivateKey, srcPubKey, unprotoWalletAmountVShareBind, srcWallet.WalletAmount[types.QadenaTokenDenom].EncWalletAmountVShare, &ewa)
			if err != nil {
				return err
			}
			if c.Debug {
				fmt.Println("decrypted wallet amount", ewa)
			}

			switch argCredentialType {
			case types.PersonalInfoCredentialType:
				fmt.Println("personal-info", c.PrettyPrint(p))

				credentialHash := c.CreateCredentialHash(p.Details)

				msg, err := createClaimContactInfoMessage(
					ctx,
					findCredentialPC,
					credentialID,
					credentialPubKey,
					argCredentialType,
					p.Details,
					p.PIN,
					credentialHash,
					srcWalletID,
					srcWallet,
					ewa,
					argRecover)

				if err != nil {
					return err
				}

				msgs[0] = msg

				fmt.Println("msg", c.PrettyPrint(msg))

				if !argRecover {
					err = queryFindCredential(cmd, argName, findCredentialPC, types.FirstNamePersonalInfoCredentialType, &pSCI, &identityProviderCredentialID)
					if err != nil {
						return err
					}

					msg, err := createClaimContactInfoMessage(
						ctx,
						findCredentialPC,
						credentialID,
						credentialPubKey,
						types.FirstNamePersonalInfoCredentialType,
						pSCI.Details,
						pSCI.PIN,
						"",
						srcWalletID,
						srcWallet,
						ewa,
						argRecover)

					if err != nil {
						return err
					}
					msgs = append(msgs, msg)

					err = queryFindCredential(cmd, argName, findCredentialPC, types.MiddleNamePersonalInfoCredentialType, &pSCI, &identityProviderCredentialID)
					if err != nil {
						return err
					}

					msg, err = createClaimContactInfoMessage(
						ctx,
						findCredentialPC,
						credentialID,
						credentialPubKey,
						types.MiddleNamePersonalInfoCredentialType,
						pSCI.Details,
						pSCI.PIN,
						"",
						srcWalletID,
						srcWallet,
						ewa,
						argRecover)

					if err != nil {
						return err
					}
					msgs = append(msgs, msg)

					err = queryFindCredential(cmd, argName, findCredentialPC, types.LastNamePersonalInfoCredentialType, &pSCI, &identityProviderCredentialID)
					if err != nil {
						return err
					}

					msg, err = createClaimContactInfoMessage(
						ctx,
						findCredentialPC,
						credentialID,
						credentialPubKey,
						types.LastNamePersonalInfoCredentialType,
						pSCI.Details,
						pSCI.PIN,
						"",
						srcWalletID,
						srcWallet,
						ewa,
						argRecover)

					if err != nil {
						return err
					}
					msgs = append(msgs, msg)
				}

			case types.PhoneContactCredentialType:
				fallthrough
			case types.EmailContactCredentialType:

				err = queryFindCredential(cmd, argName, findCredentialPC, argCredentialType, &pSCI, &identityProviderCredentialID)
				if err != nil {
					return err
				}

				msg, err := createClaimContactInfoMessage(
					ctx,
					findCredentialPC,
					credentialID,
					credentialPubKey,
					argCredentialType,
					pSCI.Details,
					pSCI.PIN,
					"",
					srcWalletID,
					srcWallet,
					ewa,
					argRecover)

				if err != nil {
					return err
				}

				msgs[0] = msg

			default:
				fmt.Println("unrecognized credential-type", argCredentialType)
				return errors.New("bad args")
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "claim credential", msgs...)

			return err
		},
	}

	//  fmt.Println("cmd", cmd)
	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().BoolVar(&argRecover, "recover-key", false, "Initiate wallet recovery")
	//  fmt.Println("cmd after addtxflags", cmd)

	return cmd
}
