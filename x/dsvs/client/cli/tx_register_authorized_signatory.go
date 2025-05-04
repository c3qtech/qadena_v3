package cli

import (
	"fmt"

	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	dsvstypes "qadena_v3/x/dsvs/types"
	c "qadena_v3/x/qadena/common"

	qadenatx "qadena_v3/x/qadena/client/tx"
	"qadena_v3/x/qadena/types"
)

var _ = strconv.Itoa(0)

func CmdRegisterAuthorizedSignatory() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register-authorized-signatory [eph-wallet-id]",
		Short: "Broadcast message RegisterAuthorizedSignatory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argEphWalletID := args[0]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// resolve argEphWalletID
			ephWalletID, _, _, _, err := c.GetAddress(ctx, argEphWalletID)
			if err != nil {
				return err
			}

			// EncryptableAuthorizedSignatory
			authorizedSignatory := types.EncryptableAuthorizedSignatory{
				Nonce:    c.Nonce(),
				WalletID: ephWalletID,
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

			encryptedDocument, bind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &authorizedSignatory)
			fmt.Println("encryptedDocument", encryptedDocument)
			fmt.Println("bind", bind)
			if !bind.VShareBVerify(encryptedDocument) {
				return fmt.Errorf("failed to verify bind")
			}

			protoizedVShareBind := c.DSVSProtoizeVShareBindData(bind)

			vShareAuthorizedSignatory := &dsvstypes.VShareAuthorizedSignatory{
				EncAuthorizedSignatoryVShare:  encryptedDocument,
				AuthorizedSignatoryVShareBind: protoizedVShareBind,
			}

			// register authorized signatory
			msgRAS := dsvstypes.MsgRegisterAuthorizedSignatory{
				Creator:                   ctx.GetFromAddress().String(),
				VShareAuthorizedSignatory: vShareAuthorizedSignatory,
			}

			if err := msgRAS.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "register authorized signatory", &msgRAS)

			return err

		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
