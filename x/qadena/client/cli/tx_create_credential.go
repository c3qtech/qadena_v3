package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"errors"
	"math/big"
	"math/rand"

	//	"encoding/hex"
	qadenatx "qadena/x/qadena/client/tx"

	c "qadena/x/qadena/common"
	"qadena/x/qadena/types"

	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	proto "github.com/cosmos/gogoproto/proto"
	"github.com/pariz/gountries"
	"github.com/spf13/cobra"
)

var _ = strconv.Itoa(0)

func createSingleContactInfoMessage(address string, credWalletID string, credentialType string, nonce string, findCredentialPC *c.PedersenCommit, contact string, ccPubK []c.VSharePubKInfo) (*types.MsgCreateCredential, error) {
	sci := new(types.EncryptableSingleContactInfo)
	sci.Details = new(types.EncryptableSingleContactInfoDetails)

	pin, err := c.GenerateRandomBlindingFactor()
	if err != nil {
		return nil, err
	}

	sci.Nonce = nonce
	sci.PIN = pin.String()
	sci.Details.Contact = contact

	all, _ := proto.Marshal(sci.Details)

	encCredentialInfoVShare, credentialInfoVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, sci)

	if credentialInfoVShareBind == nil {
		fmt.Println("ERROR! ProtoMarshalAndVShareBEncrypt() failed!")
		// return err
		return nil, errors.New("could not ProtoMarshalAndVShareBEncrypt()")
	}

	credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(all)), pin)

	if c.DebugAmounts {
	} else {
		findCredentialPC.A = c.BigIntZero
		findCredentialPC.X = c.BigIntZero

		credentialPC.A = c.BigIntZero
		credentialPC.X = c.BigIntZero
	}

	findCredentialProtoPC := c.ProtoizeBPedersenCommit(findCredentialPC)
	credentialProtoPC := c.ProtoizeBPedersenCommit(credentialPC)

	// create the "protoized" bind data
	protoCredentialInfoVShareBind := c.ProtoizeVShareBindData(credentialInfoVShareBind)

	msg := types.NewMsgCreateCredential(
		address,
		credWalletID,
		credentialType,
		credentialProtoPC,
		protoCredentialInfoVShareBind,
		encCredentialInfoVShare,
		nil,
		nil,
		findCredentialProtoPC,
		"",
		"",
	)

	return msg, msg.ValidateBasic()
}

func CmdCreateCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-credential [find-credential-pc amount (e.g. 1234)] [find-credential-pc blinding-factor (e.g. 5678)] [credential-type e.g. personal-info, phone-contact-info, email-contact-info] [...credential args depends on credential-type...] [--from provider-friendly-name e.g. secidentitysrvprv]",
		Short: "Broadcast message CreateCredential",
		Args:  cobra.MinimumNArgs(4),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argFindCredentialA := args[0]
			argFindCredentialBF := args[1]
			argCredentialType := args[2]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			credWalletID := ctx.GetFromAddress().String() + "-" + strconv.FormatInt(time.Now().UnixMilli(), 16)
			if err != nil {
				return err
			}

			fmt.Println("'unclaimed' credWalletID", credWalletID)

			var findCredentialPC *c.PedersenCommit
			findCredentialA, _ := big.NewInt(0).SetString(argFindCredentialA, 10)
			findCredentialBF, _ := big.NewInt(0).SetString(argFindCredentialBF, 10)
			findCredentialPC = c.NewPedersenCommit(findCredentialA, findCredentialBF)

			// get source wallet ID, source public key in bytes, source public key and source private key hex
			srcWalletID, _, srcPubKey, _, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			fmt.Println("srcWalletID", srcWalletID)
			fmt.Println("srcPubKey", srcPubKey)

			ccPubK := []c.VSharePubKInfo{
				{PubK: srcPubKey, NodeID: ctx.GetFromName(), NodeType: types.ServiceProviderNodeType},
			}

			ccPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, ccPubK, "", false)
			if err != nil {
				return err
			}

			nonce := "nonce-" + strconv.Itoa(rand.Intn(1000))

			msgs := make([]sdk.Msg, 1)

			switch argCredentialType {
			case types.PersonalInfoCredentialType:
				if len(args) != 10 {
					fmt.Println("personal-info:  [first-name] [middle-name] [last-name] [birthdate (e.g. 02-Jan-2006)] [citizenship (e.g. US or PH or AU or US,PH or US,AU  ...)] [residency (e.g. US or PH or US,PH  ...)] [gender (e.g. m/f/n)]")
					return errors.New("bad args")
				}

				pin, err := c.GenerateRandomBlindingFactor()
				if err != nil {
					return err
				}

				p := new(types.EncryptablePersonalInfo)
				p.Details = new(types.EncryptablePersonalInfoDetails)
				p.PIN = pin.String()
				p.Nonce = nonce
				p.Details.FirstName = strings.TrimSpace(strings.ToLower(args[3]))
				p.Details.MiddleName = strings.TrimSpace(strings.ToLower(args[4]))
				p.Details.LastName = strings.TrimSpace(strings.ToLower(args[5]))
				p.Details.Birthdate = args[6]
				p.Details.Citizenship = args[7]
				p.Details.Residency = args[8]
				p.Details.Gender = strings.ToLower(strings.TrimSpace(args[9]))

				/*
					var credentialHash string
					firstMiddleLast := p.Details.LastName + "," + p.Details.MiddleName + "," + p.Details.FirstName

					//				if c.DemoEncrypt {
					//					credentialHash = "Hash(" + firstMiddleLast + ")"
					//				} else {
					//					credentialHash = hex.EncodeToString(tmhash.Sum([]byte(firstMiddleLast)))
					//				}
					credentialHash = c.Hash(firstMiddleLast)
				*/

				const shortForm = "2006-Jan-02"
				t, err := time.Parse(shortForm, p.Details.Birthdate)
				if err != nil {
					return err
				}
				p.Details.Birthdate = t.Format(shortForm)

				if !types.ValidateGender(p.Details.Gender) {
					return errors.New("invalid gender")
				}

				query := gountries.New()

				countries := strings.Split(p.Details.Citizenship, ",")
				normalizedCountries := make([]string, len(countries))
				for i := range countries {
					country, err := query.FindCountryByAlpha(countries[i])
					if err != nil {
						return err
					}
					//          fmt.Println("Country", c.PrettyPrint(country))
					normalizedCountries[i] = country.Alpha2
				}
				p.Details.Citizenship = strings.Join(normalizedCountries, ",")

				countries = strings.Split(p.Details.Residency, ",")
				normalizedCountries = make([]string, len(countries))
				for i := range countries {
					country, err := query.FindCountryByAlpha(countries[i])
					if err != nil {
						return err
					}
					//          fmt.Println("Country", c.PrettyPrint(country))
					normalizedCountries[i] = country.Alpha2
				}
				p.Details.Residency = strings.Join(normalizedCountries, ",")

				// CREATE ALL PERSONAL-INFO

				all, err := proto.Marshal(p.Details)

				// note that the pin is not included in the hash for credentialPC

				if err != nil {
					return errors.New("invalid data, couldn't marshal")
				}

				credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(all)), pin)

				// add the pin when encrypting
				encCredentialInfoVShare, credentialInfoVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, p)

				//				encCredentialHashVShare, credentialHashVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &types.EncryptableString{Value: credentialHash})

				if c.DebugAmounts {
				} else {
					findCredentialPC.A = c.BigIntZero
					findCredentialPC.X = c.BigIntZero

					credentialPC.A = c.BigIntZero
					credentialPC.X = c.BigIntZero
				}

				findCredentialProtoPC := c.ProtoizeBPedersenCommit(findCredentialPC)
				credentialProtoPC := c.ProtoizeBPedersenCommit(credentialPC)

				// create the "protoized" bind data
				protoCredentialInfoVShareBind := c.ProtoizeVShareBindData(credentialInfoVShareBind)
				// protoCredentialHashVShareBind := c.ProtoizeVShareBindData(credentialHashVShareBind)

				msg := types.NewMsgCreateCredential(
					ctx.GetFromAddress().String(),
					credWalletID,
					argCredentialType,
					credentialProtoPC,
					protoCredentialInfoVShareBind,
					encCredentialInfoVShare,
					nil, //protoCredentialHashVShareBind,
					nil, // encCredentialHashVShare,
					findCredentialProtoPC,
					"",
					"",
				)
				if err := msg.ValidateBasic(); err != nil {
					return err
				}

				msgs[0] = msg

				if true {

					// CREATE PERSONAL-INFO-FIRST-NAME
					msg, err = createSingleContactInfoMessage(ctx.GetFromAddress().String(), credWalletID, types.FirstNamePersonalInfoCredentialType, nonce, findCredentialPC, p.Details.FirstName, ccPubK)

					if err != nil {
						return err
					}

					msgs = append(msgs, msg)

					// CREATE PERSONAL-INFO-MIDDLE-NAME
					msg, err = createSingleContactInfoMessage(ctx.GetFromAddress().String(), credWalletID, types.MiddleNamePersonalInfoCredentialType, nonce, findCredentialPC, p.Details.MiddleName, ccPubK)

					if err != nil {
						return err
					}

					msgs = append(msgs, msg)

					// CREATE PERSONAL-INFO-LAST-NAME
					msg, err = createSingleContactInfoMessage(ctx.GetFromAddress().String(), credWalletID, types.LastNamePersonalInfoCredentialType, nonce, findCredentialPC, p.Details.LastName, ccPubK)

					if err != nil {
						return err
					}

					msgs = append(msgs, msg)
				}

			case types.PhoneContactCredentialType:
				if len(args) != 4 {
					fmt.Println("phone-contact-info:  phone-number")
					return errors.New("bad args")
				}

				msg, err := createSingleContactInfoMessage(ctx.GetFromAddress().String(), credWalletID, argCredentialType, nonce, findCredentialPC, args[3], ccPubK)
				if err != nil {
					return err
				}

				msgs[0] = msg

			case types.EmailContactCredentialType:
				if len(args) != 4 {
					fmt.Println("email-contact-info:  email-address")
					return errors.New("bad args")
				}

				msg, err := createSingleContactInfoMessage(ctx.GetFromAddress().String(), credWalletID, argCredentialType, nonce, findCredentialPC, args[3], ccPubK)
				if err != nil {
					return err
				}

				msgs[0] = msg

			default:
				fmt.Println("unrecognized credential-type", argCredentialType)
				return errors.New("bad args")
			}

			fmt.Println("msg", c.PrettyPrint(msgs))

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "create credential", msgs...)

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
