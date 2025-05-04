package cli

import (
	"math/big"
	"strconv"

	"errors"
	"fmt"

	nstypes "github.com/c3qtech/qadena_v3/x/nameservice/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	proto "github.com/cosmos/gogoproto/proto"
)

var _ = strconv.Itoa(0)

func CmdBindCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bind-credential [real-wallet-friendly-name e.g. al, ann] [credential-type e.g. personal-info, phone-contact-info, email-contact-info] [--from ephemeral-wallet-friendly-name e.g. al-eph, ann-eph]",
		Short: "Broadcast message BindCredential",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argName := args[0]
			argCredentialType := args[1]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			srcWalletID, _, srcPubKey, srcPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			argCredentialID := argName + "-credential"

			fmt.Println("argCredentialID", argCredentialID)

			credentialID, _, credentialPubKey, credentialPrivKeyHex, err := c.GetAddress(ctx, argCredentialID)
			if err != nil {
				return err
			}

			srcTransactionPrivateKey := srcPrivKeyHex + "_privkhex:" + srcPubKey + "_privk"
			credPrivKey := credentialPrivKeyHex + "_privkhex:" + credentialPubKey + "_privk"

			fmt.Println("srcPrivKeyHex", srcPrivKeyHex)
			fmt.Println("but will use priv key", srcTransactionPrivateKey)
			fmt.Println("srcWalletID", srcWalletID)

			credential, err := c.GetCredential(ctx, credentialID, argCredentialType)
			if err != nil {
				return err
			}
			fmt.Println("credential", c.PrettyPrint(credential))

			var pinInt *big.Int

			var pinPC *c.PedersenCommit

			var credBytes []byte
			var credString string

			switch argCredentialType {
			case "email-contact-info":
				fallthrough
			case "phone-contact-info":
				var p types.EncryptableSingleContactInfo
				unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
				err = c.VShareBDecryptAndProtoUnmarshal(credPrivKey, credentialPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
				fmt.Println("phone-contact-info", c.PrettyPrint(p))
				var ok bool
				pinInt, ok = big.NewInt(0).SetString(p.PIN, 10)
				if !ok {
					return errors.New("pin not numerical")
				}
				credBytes, _ = proto.Marshal(p.Details)
				credString = p.Details.Contact
			default:
				fmt.Println("unrecognized credential-type", argCredentialType)
				return errors.New("bad args")
			}

			fmt.Println("credBytes", credBytes)
			fmt.Println("credString", credString)
			hashInt := big.NewInt(0).SetBytes(tmhash.Sum(credBytes))
			fmt.Println("hash of credBytes", hashInt)
			pinPC = c.NewPedersenCommit(hashInt, pinInt)

			//			pinInt, _ := strconv.ParseInt(argPIN, 10, 0)

			//      rand.Seed(pinInt)
			//
			//			pinPC := c.NewPedersenCommit(big.NewInt(pinInt), big.NewInt(rand.Int63()))

			pc := c.NewPedersenCommit(hashInt, c.BigIntZero)
			proofPC := c.SubPedersenCommitNoMinCheck(pc, pinPC)

			if c.Debug {
				fmt.Println("pc", c.PrettyPrint(pc), "\npinPC", c.PrettyPrint(*pinPC), "\nproofPC", c.PrettyPrint(*proofPC))
			}

			if c.ValidateSubPedersenCommit(pc, pinPC, proofPC) {
				fmt.Println("validated proofPC")
			}

			if c.DebugAmounts {
			} else {
				proofPC.A = c.BigIntZero
				proofPC.X = c.BigIntZero
			}

			protoProofPC := c.NSProtoizeBPedersenCommit(*proofPC)
			_ = protoProofPC

			msg := nstypes.NewMsgBindCredential(
				srcWalletID,
				argCredentialType,
				credString,
				&protoProofPC,
			)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			fmt.Println("msg", c.PrettyPrint(msg))

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "bind credential", msg)

			//			err = c.CheckTxCLIResponse(ctx, err, res, "bind credential")

			return err

		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
