package cli

import (
	"bytes"
	"strconv"

	"errors"

	"fmt"

	//"io"

	//"os/exec"

	//	"encoding/json"
	"math/rand"
	"strings"
	"time"

	//yaml "gopkg.in/yaml.v2"

	"cosmossdk.io/x/feegrant"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

	//	"github.com/cosmos/cosmos-sdk/crypto/hd"
	//"github.com/cosmos/cosmos-sdk/crypto/keyring"
	//cryptokeyring "github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/client/keys"

	//	bip39 "github.com/cosmos/go-bip39"

	c "qadena/x/qadena/common"
	"qadena/x/qadena/types"

	qadenatx "qadena/x/qadena/client/tx"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"math/big"

	"github.com/cometbft/cometbft/crypto/tmhash"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
)

var _ = strconv.Itoa(0)

// available output formats.
const (
	OutputFormatText = "text"
	OutputFormatJSON = "json"
)

var KeysCdc *codec.LegacyAmino

// THESE ARE FOR TESTING
const (
	TESTskipOptionalCCPubK      = false
	TESTskipRequiredChainCCPubK = false
	TESTskipInnerCCPubK         = false
)

func init() {
	KeysCdc = codec.NewLegacyAmino()
	cryptocodec.RegisterCrypto(KeysCdc)
	KeysCdc.Seal()
}

// marshal keys
func MarshalJSON(o interface{}) ([]byte, error) {
	return KeysCdc.MarshalJSON(o)
}

// unmarshal json
func UnmarshalJSON(bz []byte, ptr interface{}) error {
	return KeysCdc.UnmarshalJSON(bz, ptr)
}

func cleanupPublicKeys(ctx client.Context, friendlyName1, friendlyName2 string) {
	if friendlyName1 != "" {
		nerr := c.RemovePublicKey(ctx, friendlyName1)
		if nerr != nil {
			fmt.Println("err", nerr)
		} else {
			fmt.Println("Removed key", friendlyName1)
		}
	}

	if friendlyName2 != "" {
		nerr := c.RemovePublicKey(ctx, friendlyName2)
		if nerr != nil {
			fmt.Println("err", nerr)
		} else {
			fmt.Println("Removed key", friendlyName2)
		}
	}
}

func grantFee(ctx client.Context, flags *pflag.FlagSet, sponsorAddress string, grantee string) error {

	basicAllowance := &feegrant.BasicAllowance{}
	anyBasicAllowance, err := codectypes.NewAnyWithValue(basicAllowance)
	if err != nil {
		fmt.Println("error creating AnyBasicAllowance", err)
		return err
	}

	allowedMsgAllowance := &feegrant.AllowedMsgAllowance{
		Allowance: anyBasicAllowance,
		AllowedMessages: []string{
			"/qadena.qadena.MsgAddPublicKey",
			"/qadena.qadena.MsgCreateWallet",
		},
	}

	anyAllowance, err := codectypes.NewAnyWithValue(allowedMsgAllowance)
	if err != nil {
		fmt.Println("error creating AnyAllowedMsgAllowance", err)
		return err
	}

	msgCD := &feegrant.MsgGrantAllowance{
		Grantee:   grantee,
		Granter:   sponsorAddress,
		Allowance: anyAllowance,
	}

	// Broadcast transaction and handle response
	err, qadenaResponse := qadenatx.GenerateOrBroadcastTxCLISync(ctx, flags, "fee grant", msgCD)
	if err != nil {
		fmt.Println("err", err)
		return err
	}

	fmt.Println("fee grant response", qadenaResponse)
	return nil
}

func CmdCreateWallet() *cobra.Command {
	var argAcceptPassword string
	var argAcceptCredentialTypes string
	var argRequireSenderCredentialTypes string
	var argLinkToRealWalletName string
	var argAccountMnemonic string
	var argEphAccountIndex uint32
	var argServiceProviderID string

	cmd := &cobra.Command{
		Use:   "create-wallet [friendly-account-name] [home-pioneer-id (e.g. pioneer1)] [create-wallet-sponsor (e.g. pioneer1-create-wallet-sponsor)] [optional: link-to-real-wallet-name (e.g. al)]",
		Short: "Broadcast message CreateWallet",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argName := args[0]
			argHomePioneerID := args[1]
			argSponsorID := args[2]
			argLinkToName := argName

			argNameCredential := argName + "-credential"

			isEphemeral := false

			if argLinkToRealWalletName != "" {
				fmt.Println("Ephemeral wallet requested")
				isEphemeral = true
				argLinkToName = argLinkToRealWalletName
			}

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				fmt.Println("Couldn't create client tx context")
				return err
			}

			accountMnemonic := argAccountMnemonic
			if accountMnemonic == "" {
				mnemonic, err := c.GenerateNewMnemonic()
				if err != nil {
					fmt.Println("Couldn't create new mnemonic")
					return err
				}

				accountMnemonic = mnemonic
			}

			// if the wallet creation is for ephemeral and ephAccountIndex is not passed
			// execute this special condition
			if isEphemeral && argEphAccountIndex == 0 {
				kb := c.GetKeyring(ctx)

				algo, err := c.GetAlgo(kb)
				if err != nil {
					fmt.Println("Couldn't get keyring algo", err)
					return err
				}

				var bip39Passphrase = c.GetBip39PassPhrase()

				// let's start the loop in index 1 because index 0 is not ephemeral
				i := uint32(1)
				for {
					// get eph account address based on hierarchical deterministic wallet
					derrivedEphAccountAddress, err := c.GetEphAccountAddress(accountMnemonic, bip39Passphrase, types.TransactionWalletType, i, algo)
					if err != nil {
						fmt.Println("Couldn't get eph account address", err)
						return err
					}

					// check wether the derrived eph account address already exist on the chain
					// if yes, then we need to increment hd path and requery the wallet address
					// if not, then we use the current value of counter nad update argEphAccountIndex then proceed with wallet creation
					_, err = c.GetWallet(ctx, derrivedEphAccountAddress.String())
					if err != nil {
						argEphAccountIndex = i
						break
					}

					i++
				}
			}

			createPublicKeyForTrxReq := c.PublicKeyReq{
				FriendlyName:    argName,
				RecoverMnemonic: accountMnemonic,
				IsEphemeral:     isEphemeral,
				EphAccountIndex: argEphAccountIndex,
			}

			from, fromAddr, fromName, fromPubK, err := c.CreatePublicKey(ctx, createPublicKeyForTrxReq)
			if err != nil {
				fmt.Println("Couldn't create public key for", argName)
				return err
			}

			/*
			   fmt.Println("EXITING EARLY")
			   return nil
			*/

			createPublicKeyForCrdReq := c.PublicKeyReq{
				FriendlyName:    argNameCredential,
				RecoverMnemonic: accountMnemonic,
				IsEphemeral:     isEphemeral,
				EphAccountIndex: argEphAccountIndex,
			}

			_, _, _, fromPubKCredential, err := c.CreatePublicKey(ctx, createPublicKeyForCrdReq)
			if err != nil {
				fmt.Println("Couldn't create public key for", argNameCredential)
				cleanupPublicKeys(ctx, argName, "")
				return err
			}

			createWalletIncentiveCoin, createEphemeralWalletIncentiveCoin, createWalletTransparentIncentiveCoin, createEphemeralWalletTransparentIncentiveCoin, err := c.GetIncentives(ctx)
			if err != nil {
				fmt.Println("Couldn't get incentives")
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			// we need to do a feegrant from the pioneer to the new account, so we need to get the home pioneer's address
			kb := ctx.Keyring

			homePioneerInfo, err := kb.Key(argHomePioneerID)
			if err != nil {
				fmt.Println("Couldn't access private key", argHomePioneerID)
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			homePioneerInfoOutput, err := keys.MkAccKeyOutput(homePioneerInfo)
			if err != nil {
				fmt.Println("Couldn't convert key info into address", homePioneerInfo)
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			fmt.Println("homePioneerAddress", homePioneerInfoOutput.Address)

			sponsorInfo, err := kb.Key(argSponsorID)
			if err != nil {
				fmt.Println("Couldn't access private key", argSponsorID)
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			sponsorInfoOutput, err := keys.MkAccKeyOutput(sponsorInfo)
			if err != nil {
				fmt.Println("Couldn't convert key info into address", sponsorInfo)
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			fmt.Println("sponsorAddress", sponsorInfoOutput.Address)

			sponsorAccAddress, err := sdk.AccAddressFromBech32(sponsorInfoOutput.Address)
			if err != nil {
				fmt.Println("Couldn't convert key info into address", sponsorInfo)
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			newCtx := ctx.WithFrom(sponsorInfoOutput.Address).WithFromAddress(sponsorAccAddress).WithFromName(argSponsorID)

			err = grantFee(newCtx, cmd.Flags(), sponsorInfoOutput.Address, from)

			if err != nil {
				fmt.Println("Couldn't grant fee")
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			ctx = ctx.WithFrom(from).WithFromAddress(fromAddr).WithFromName(fromName)

			ctx = ctx.WithFeeGranterAddress(sponsorAccAddress)

			fmt.Println("new", "from", ctx.From, "fromname", ctx.FromName, "address", ctx.FromAddress)

			msgs := make([]sdk.Msg, 0)

			// add transaction pubk
			msg := types.NewMsgAddPublicKey(
				fromAddr.String(),
				fromPubK,
				types.TransactionPubKType,
			)
			if err := msg.ValidateBasic(); err != nil {
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}
			msgs = append(msgs, msg)

			// add credential pubk
			msg = types.NewMsgAddPublicKey(
				fromAddr.String(),
				fromPubKCredential,
				types.CredentialPubKType,
			)
			if err := msg.ValidateBasic(); err != nil {
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}
			msgs = append(msgs, msg)

			// find the wallet this eph is linked to
			linkToWalletID, _, linkToWalletPubKey, linkToWalletPrivKeyHex, err := c.GetAddress(ctx, argLinkToName)
			linkToWalletPrivateKey := linkToWalletPrivKeyHex + "_privkhex:" + linkToWalletPubKey + "_privk"

			_, _, linkToWalletCredPubKey, linkToWalletCredPrivKeyHex, err := c.GetAddress(ctx, argLinkToName+"-credential")
			linkToWalletCredPrivateKey := linkToWalletCredPrivKeyHex + "_privkhex:" + linkToWalletCredPubKey + "_privk"

			s1 := rand.NewSource(time.Now().UnixNano())
			r1 := rand.New(s1)

			txID := "tx-" + strconv.Itoa(r1.Intn(1000))
			nonce := "nonce-" + strconv.Itoa(r1.Intn(1000))

			var dstEWalletID types.EncryptableCreateWalletEWalletID
			dstEWalletID.Nonce = nonce
			dstEWalletID.WalletID = linkToWalletID

			var protoAcceptPasswordPC *types.BPedersenCommit = nil
			var senderOptionsTypeBuf bytes.Buffer
			var encAcceptValidatedCredentialsVShare []byte
			var acceptValidatedCredentialsVShareBind *c.VShareBindData

			var walletAmountPC *c.PedersenCommit
			var transparentWalletAmountPC *c.PedersenCommit

			serviceProviderID := make([]string, 0)

			if argServiceProviderID != "" {
				// append to serviceProviderID
				serviceProviderID = append(serviceProviderID, argServiceProviderID)
			}

			if isEphemeral {
				// set up all the wallet amounts
				walletAmountPC = c.NewPedersenCommit(createEphemeralWalletIncentiveCoin.Amount.BigInt(), nil)
				transparentWalletAmountPC = c.NewPedersenCommit(createEphemeralWalletTransparentIncentiveCoin.Amount.BigInt(), nil)

				// WE NEED TO PROVE THAT THE ONE WHO CREATED THE EPH WALLET HAS A KEY TO THE REAL WALLET!
				linkToWallet, err := c.GetWallet(ctx, linkToWalletID)
				if err != nil {
					cleanupPublicKeys(ctx, argName, argNameCredential)
					return err
				}

				// VPDN handling, we must use the same service provider as the main wallet
				//
				serviceProviderID = linkToWallet.ServiceProviderID

				if _, ok := linkToWallet.WalletAmount[types.QadenaTokenDenom]; ok {
					//var wa c.WalletAmount
					var ewa types.EncryptableWalletAmount
					unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(linkToWallet.WalletAmount[types.QadenaTokenDenom].WalletAmountVShareBind)
					err = c.VShareBDecryptAndProtoUnmarshal(linkToWalletPrivateKey, linkToWalletPubKey, unprotoWalletAmountVShareBind, linkToWallet.WalletAmount[types.QadenaTokenDenom].EncWalletAmountVShare, &ewa)
					if err != nil {
						cleanupPublicKeys(ctx, argName, argNameCredential)
						return err
					}
					if c.Debug {
						fmt.Println("decrypted wallet amount", ewa)
					}

					hashPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(fromAddr.String()))), big.NewInt(0))

					var cwExtraParms types.EncryptableCreateWalletEWalletIDExtraParms
					cwExtraParms.ProofPC = c.ProtoizeBPedersenCommit(c.AddPedersenCommitNoMaxCheck(c.UnprotoizeEncryptablePedersenCommit(ewa.PedersenCommit), hashPC))

					//s_b, _ := json.Marshal(cwExtraParms)
					dstEWalletID.ExtraParms = &cwExtraParms
				}

				var acceptPasswordPC *c.PedersenCommit
				if argAcceptPassword != "" {
					// build the accept credential type buffer
					senderOptionsTypeBuf.WriteString(types.RequirePasswordSenderOption)
					acceptPasswordPC = c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(argAcceptPassword))), big.NewInt(0).SetBytes(tmhash.Sum([]byte(fromAddr.String()))))

					if c.DebugAmounts {
					} else {
						acceptPasswordPC.A = c.BigIntZero
						acceptPasswordPC.X = c.BigIntZero
						protoized := c.ProtoizeBPedersenCommit(acceptPasswordPC)
						protoAcceptPasswordPC = protoized
					}
				}

				if argAcceptCredentialTypes != "" {
					// build the accept credential type buffer
					credentialTypes := strings.Split(argAcceptCredentialTypes, ",")

					var validatedCredentials types.EncryptableValidatedCredentials
					for i := range credentialTypes {
						credentialType := credentialTypes[i]
						credential, err := c.GetCredential(ctx, linkToWallet.CredentialID, credentialType)
						if err != nil {
							cleanupPublicKeys(ctx, argName, argNameCredential)
							return err
						}

						if senderOptionsTypeBuf.Len() > 0 {
							senderOptionsTypeBuf.WriteString("," + types.AcceptOption + credentialType)
						} else {
							senderOptionsTypeBuf.WriteString(types.AcceptOption + credentialType)
						}

						// unproto credential.VShareBind

						unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)

						var p types.EncryptableSingleContactInfo
						err = c.VShareBDecryptAndProtoUnmarshal(linkToWalletCredPrivateKey, linkToWalletCredPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
						fmt.Println("p", c.PrettyPrint(p))
						if err != nil {
							cleanupPublicKeys(ctx, argName, argNameCredential)
							return err
						}
						fmt.Println("credential", credential)
						var vc types.EncryptableValidatedCredential
						vc.CredentialType = credentialType
						vc.PIN = p.PIN
						vc.CredentialPC = credential.CredentialPedersenCommit
						validatedCredentials.Credentials = append(validatedCredentials.Credentials, &vc)
					}
					// nodes who will be cc'd for the dstEWalletID
					validatedCredentialsCCPubK := []c.VSharePubKInfo{
						{PubK: fromPubK, NodeID: "", NodeType: ""},
					}

					if !TESTskipRequiredChainCCPubK {
						validatedCredentialsCCPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, validatedCredentialsCCPubK, "", false)
						if err != nil {
							cleanupPublicKeys(ctx, argName, argNameCredential)
							return err
						}
					}

					if !TESTskipOptionalCCPubK {
						validatedCredentialsCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, validatedCredentialsCCPubK, serviceProviderID, []string{types.FinanceServiceProvider})
						if err != nil {
							cleanupPublicKeys(ctx, argName, argNameCredential)
							return err
						}
					}

					encAcceptValidatedCredentialsVShare, acceptValidatedCredentialsVShareBind = c.ProtoMarshalAndVShareBEncrypt(validatedCredentialsCCPubK, &validatedCredentials)
				}

				if argRequireSenderCredentialTypes != "" {
					// build the require sender credential type buffer
					credentialTypes := strings.Split(argRequireSenderCredentialTypes, ",")

					for i := range credentialTypes {
						credentialType := credentialTypes[i]

						if senderOptionsTypeBuf.Len() > 0 {
							senderOptionsTypeBuf.WriteString("," + types.RequireSenderOption + credentialType)
						} else {
							senderOptionsTypeBuf.WriteString(types.RequireSenderOption + credentialType)
						}
					}
				}

			} else {
				walletAmountPC = c.NewPedersenCommit(createWalletIncentiveCoin.Amount.BigInt(), nil)
				transparentWalletAmountPC = c.NewPedersenCommit(createWalletTransparentIncentiveCoin.Amount.BigInt(), nil)
			}

			var ewa types.EncryptableWalletAmount
			ewa.Nonce = nonce
			ewa.TransactionID = txID
			ewa.PedersenCommit = c.ProtoizeEncryptablePedersenCommit(walletAmountPC)
			//ewabytes, _ := ewa.Marshal()

			// print size of ewabytes
			// len of ewabytes

			//fmt.Println("ewabytes size", len(ewabytes))

			//marshalstring, _ := json.Marshal(wa)
			//fmt.Println("json size", len(marshalstring))

			//encWalletAmountUserCredentialPubK := c.MarshalAndEncrypt(fromPubK, wa)

			// nodes who will be cc'd for the dstEWalletID
			walletAmountCCPubK := []c.VSharePubKInfo{
				{PubK: fromPubK, NodeID: "", NodeType: ""},
			}

			if !TESTskipOptionalCCPubK {
				walletAmountCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, walletAmountCCPubK, serviceProviderID, []string{types.FinanceServiceProvider})
				if err != nil {
					cleanupPublicKeys(ctx, argName, argNameCredential)
					return err
				}
			}

			encWalletAmountVShare, walletAmountVShareBind := c.ProtoMarshalAndVShareBEncrypt(walletAmountCCPubK, &ewa)

			// nodes who will be cc'd for the dstEWalletID
			createWalletCCPubK := []c.VSharePubKInfo{
				{PubK: fromPubK, NodeID: "", NodeType: ""},
			}

			if !TESTskipRequiredChainCCPubK {
				createWalletCCPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, createWalletCCPubK, argHomePioneerID, false)
				if err != nil {
					cleanupPublicKeys(ctx, argName, argNameCredential)
					return err
				}
			}

			if !TESTskipOptionalCCPubK {
				createWalletCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, createWalletCCPubK, serviceProviderID, []string{types.FinanceServiceProvider})
				if err != nil {
					cleanupPublicKeys(ctx, argName, argNameCredential)
					return err
				}
			}

			vShareCreateWallet := types.EncryptableCreateWallet{
				DstEWalletID: &dstEWalletID,
			}

			// marshal and encrypt the create wallet vshare
			encCreateWalletVShare, createWalletVShareBind := c.ProtoMarshalAndVShareBEncrypt(createWalletCCPubK, &vShareCreateWallet)

			if createWalletVShareBind == nil {
				fmt.Println("ERROR! ProtoMarshalAndVShareBEncrypt() failed!")
				// return err
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return errors.New("could not ProtoMarshalAndVShareBEncrypt()")
			}

			protoTransparentWalletAmountPC := c.ProtoizeEncryptablePedersenCommit(transparentWalletAmountPC)

			// WE SPECIFICALLY DO NOT DO BELOW BECAUSE EVERYONE KNOWS THE INCENTIVES ANYWAY?
			//        walletAmountPC.A = c.BigIntZero
			//        walletAmountPC.X = c.BigIntZero

			protoWalletAmountPedersenCommit := c.ProtoizeEncryptablePedersenCommit(walletAmountPC)

			// create the "protoized" bind data
			protoCreateWalletVShareBind := c.ProtoizeVShareBindData(createWalletVShareBind)

			msgCW := types.NewMsgCreateWallet(
				fromAddr.String(),
				argHomePioneerID,
				serviceProviderID,
				encCreateWalletVShare,
				protoCreateWalletVShareBind,
				protoAcceptPasswordPC,
				encAcceptValidatedCredentialsVShare,
				c.ProtoizeVShareBindData(acceptValidatedCredentialsVShareBind),
				protoWalletAmountPedersenCommit,
				encWalletAmountVShare,
				c.ProtoizeVShareBindData(walletAmountVShareBind),
				protoTransparentWalletAmountPC,
				senderOptionsTypeBuf.String(),
			)

			if err := msgCW.ValidateBasic(); err != nil {
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}
			msgs = append(msgs, msgCW)

			flagSet := cmd.Flags()

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, flagSet, "create wallet", msgs...)

			if err != nil {
				cleanupPublicKeys(ctx, argName, argNameCredential)
				return err
			}

			return nil
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argAcceptPassword, "accept-password", "", "Must be an ephemeral wallet; only accept incoming transfers if they use this password")
	cmd.Flags().StringVar(&argLinkToRealWalletName, "link-to-real-wallet", "", "Create an ephemeral wallet, linked to this real wallet")
	cmd.Flags().StringVar(&argAcceptCredentialTypes, "accept-credential-types", "", "Must be an ephemeral wallet; comma-separated - if sender requires credentials to match, match against these (e.g. first-name-personal-info or first-name-personal-info,last-name-personal-info or middle-name-personal-info etc.)")
	cmd.Flags().StringVar(&argRequireSenderCredentialTypes, "require-sender-credential-types", "", "Must be an ephemeral wallet; comma-separated - sender must provide validated credentials (e.g. first-name-personal-info or first-name-personal-info,last-name-personal-info or middle-name-personal-info etc.)")
	cmd.Flags().StringVar(&argAccountMnemonic, "account-mnemonic", "", "The account's mnemonic")
	cmd.Flags().StringVar(&argServiceProviderID, "service-provider", "", "The account's initial service provider")
	cmd.Flags().Uint32Var(&argEphAccountIndex, "eph-account-index", 0, "The account's ephemeral index")

	return cmd
}
