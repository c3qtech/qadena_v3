package cli

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	dsvstypes "github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

var _ = strconv.Itoa(0)

func CmdSignDocument() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign-document [document-1] [document-2] [signatory-email] [signatory-phone]",
		Short: "Broadcast message SignDocument",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argDocument1 := args[0]
			argDocument2 := args[1]
			argSignatoryEmail := args[2]
			argSignatoryPhone := args[3]

			// Check if hash flag is set
			useHash, _ := cmd.Flags().GetBool("hash")
			
			var currentHashBytes []byte
			var currentHash string
			var newHashBytes []byte
			var newHash string

			if useHash {
				// Decode the first hex string
				currentHashBytes, err = hex.DecodeString(argDocument1)
				if err != nil {
					return fmt.Errorf("failed to decode current hash hex string: %v", err)
				}
				currentHash = argDocument1

				// Decode the second hex string
				newHashBytes, err = hex.DecodeString(argDocument2)
				if err != nil {
					return fmt.Errorf("failed to decode new hash hex string: %v", err)
				}
				newHash = argDocument2
			} else {
				// hash the first file contents
				currentHashBytes, currentHash, err = hashFile(argDocument1)
				if err != nil {
					return err
				}

				// hash the second file contents
				newHashBytes, newHash, err = hashFile(argDocument2)
				if err != nil {
					return err
				}
			}

			fmt.Printf("Current file hash: %s\n", currentHash)
			fmt.Printf("New file hash: %s\n", newHash)

			if currentHash == newHash {
				return fmt.Errorf("hashes match, documents are the same")
			}

			argSignatory := types.EncryptableSignatory{
				Nonce:       c.Nonce(),
				Email:       argSignatoryEmail,
				PhoneNumber: argSignatoryPhone,
			}

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// get source wallet ID, source public key in bytes, source public key and source private key hex
			srcWalletID, _, srcPubKey, srcPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			// get wallet struct by source wallet ID
			srcWallet, err := c.GetWallet(ctx, srcWalletID)
			if err != nil {
				return err
			}

			fmt.Println("srcWallet", srcWallet)

			// generate source transaction private key
			srcTransactionPrivateKey := srcPrivKeyHex + "_privkhex:" + srcPubKey + "_privk"

			fmt.Println("srcPrivKeyHex", srcPrivKeyHex)
			fmt.Println("but will use priv key", srcTransactionPrivateKey)
			fmt.Println("srcWalletID", srcWalletID)
			fmt.Println("srcPubKey", srcPubKey)

			_, _, srcCredPubKey, _, err := c.GetAddress(ctx, ctx.GetFromName()+"-credential")
			if err != nil {
				return err
			}

			ccPubK := []c.VSharePubKInfo{
				{PubK: srcCredPubKey, NodeID: "", NodeType: ""},
			}

			ccPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, ccPubK, "", false)
			if err != nil {
				return err
			}

			// add required service providers to ccPubK
			ccPubK, err = c.ClientAppendRequiredServiceProvidersCCPubK(ctx, ccPubK, srcWallet.ServiceProviderID, []string{types.DSVSServiceProvider})
			if err != nil {
				return err
			}

			encryptedSignatory, bind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &argSignatory)
			fmt.Println("encryptedDocument", encryptedSignatory)
			fmt.Println("bind", bind)
			if !bind.VShareBVerify(encryptedSignatory) {
				return fmt.Errorf("failed to verify bind")
			}

			protoizedVShareBind := c.DSVSProtoizeVShareBindData(bind)

			requiredSignatory := &dsvstypes.VShareSignatory{
				EncSignatoryVShare:  encryptedSignatory,
				SignatoryVShareBind: protoizedVShareBind,
			}

			// sign a document
			msgSD := dsvstypes.MsgSignDocument{
				Creator:            ctx.GetFromAddress().String(),
				CompletedSignatory: requiredSignatory,
				CurrentHash:        currentHashBytes,
				Hash:               newHashBytes,
			}

			if err := msgSD.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "sign document", &msgSD)

			return err

		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().Bool("hash", false, "If set, document-1 and document-2 are treated as hexadecimal hashes instead of file paths")

	return cmd
}
