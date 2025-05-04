package cli

import (
	"strconv"

	"fmt"
	"math/big"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	//  "math/rand"
	"strings"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
)

var _ = strconv.Itoa(0)

func CmdFindCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "find-credential [friendly-account-name e.g. ann, al] [find-credential-pc amount.blinding-factor (e.g. 123.567)] [credential-type e.g. personal-info, phone-contact-info, email-contact-info]",
		Short: "Query FindCredential",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argName := args[0]
			argFindCredentialABF := args[1]

			argCredentialType := args[2]

			argNameCredential := argName + "-credential"

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			_, _, credPubKey, credPrivKeyHex, err := c.GetAddress(ctx, argNameCredential)
			if err != nil {
				return err
			}

			credPrivateKey := credPrivKeyHex + "_privkhex:" + credPubKey + "_privk"

			fmt.Println("credPubKey", credPubKey, "credPrivateKey", credPrivateKey)

			pinABF := strings.Split(argFindCredentialABF, ".")

			var pinPC *c.PedersenCommit
			pinA, _ := big.NewInt(0).SetString(pinABF[0], 10)
			pinBF, _ := big.NewInt(0).SetString(pinABF[1], 10)
			pinPC = c.NewPedersenCommit(pinA, pinBF)

			fmt.Println("pinPC", c.PrettyPrint(pinPC))

			proofPC := c.NewPedersenCommit(pinA, nil)

			checkPC := c.SubPedersenCommitNoMinCheck(pinPC, proofPC)

			fmt.Println("proofPC", c.PrettyPrint(proofPC))

			fmt.Println("checkPC", c.PrettyPrint(checkPC))

			if c.DebugAmounts {
			} else {
				pinPC.A = c.BigIntZero
				pinPC.X = c.BigIntZero
				proofPC.A = c.BigIntZero
				proofPC.X = c.BigIntZero
			}

			if !c.ValidateSubPedersenCommit(pinPC, proofPC, checkPC) {
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
			encCheckPCIntervalSSPubK := c.ProtoMarshalAndBEncrypt(ssIntervalPubK, c.ProtoizeBPedersenCommit(checkPC))
			// credentialPC := pinPC.C.X.String() + "." + pinPC.C.Y.String()
			credentialPC := pinPC.C.Bytes()

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

			switch argCredentialType {
			case types.PersonalInfoCredentialType:
				var personalInfo types.EncryptablePersonalInfo
				_, err = c.BDecryptAndProtoUnmarshal(credPrivateKey, res.EncPersonalInfoUserCredentialPubK, &personalInfo)
				if err != nil {
					fmt.Println("couldn't get decrypt personal info")
					return err
				}

				fmt.Println("personalInfo", c.PrettyPrint(personalInfo))
			default:
				var p types.EncryptableSingleContactInfo
				_, err = c.BDecryptAndProtoUnmarshal(credPrivateKey, res.EncPersonalInfoUserCredentialPubK, &p)
				if err != nil {
					fmt.Println("couldn't get decrypt personal info")
					return err
				}

				fmt.Println("info", c.PrettyPrint(p))
			}

			var credentialID string
			_, err = c.BDecryptAndUnmarshal(credPrivateKey, res.EncCredentialIDUserCredentialPubK, &credentialID)
			if err != nil {
				fmt.Println("couldn't get decrypt credentialID")
				return err
			}

			fmt.Println("credentialID", credentialID)

			return nil
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
