package cli

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	c "qadena_v3/x/qadena/common"

	"qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

	qadenatx "qadena_v3/x/qadena/client/tx"

	"github.com/spf13/cobra"
)

var _ = strconv.Itoa(0)

func CmdSignRecoverKey() *cobra.Command {
	var argIsUser bool

	cmd := &cobra.Command{
		Use:   "sign-recover-key [wallet-id]",
		Short: "Broadcast message SignRecoverKey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argWalletID := args[0]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// generate a random transaction ID and nonce ID
			s1 := rand.NewSource(time.Now().UnixNano())
			r1 := rand.New(s1)

			nonce := "nonce-" + strconv.Itoa(r1.Intn(1000))

			dstWalletID, _, _, _, err := c.GetAddress(ctx, argWalletID)
			if err != nil {
				return err
			}

			fmt.Println("dstWalletID", dstWalletID)

			var recoverShare types.RecoverShare

			if argIsUser {
				srcWalletID, _, _, _, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
				if err != nil {
					return err
				}
				_, _, srcCredPubKey, srcCredPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromName()+"-credential")
				if err != nil {
					return err
				}
				// get wallet struct by source wallet ID
				sourceWallet, err := c.GetWallet(ctx, srcWalletID)
				if err != nil {
					return err
				}

				fmt.Println("sourceWallet", sourceWallet)

				pioneerWalletID, _, err := c.GetIntervalPublicKey(ctx, sourceWallet.HomePioneerID, types.PioneerNodeType)
				if err != nil {
					fmt.Println("GetIntervalPublicKey failed")
					return err
				}

				pioneerEnclavePubK, err := c.GetPublicKey(ctx, pioneerWalletID, types.EnclavePubKType)
				if err != nil {
					fmt.Println("GetPublicKey enclave failed")
					return err
				}
				srcCredPrivateKey := srcCredPrivKeyHex + "_privkhex:" + srcCredPubKey + "_privk"
				encWalletPubKShare, threshold, err := c.GetProtectKey(ctx, dstWalletID, ctx.GetFromAddress().String())
				if err != nil {
					fmt.Println("GetProtectKey failed")
					return err
				}

				if threshold == 1 {
					var seedPhrase string
					_, err = c.BDecryptAndUnmarshal(srcCredPrivateKey, encWalletPubKShare, &seedPhrase)
					encShare := c.MarshalAndBEncrypt(pioneerEnclavePubK, seedPhrase)
					recoverShare = types.RecoverShare{WalletID: sourceWallet.HomePioneerID,
						EncWalletPubKShare: encShare,
					}
				} else {
					var stringShare string
					_, err = c.BDecryptAndUnmarshal(srcCredPrivateKey, encWalletPubKShare, &stringShare)
					encShare := c.MarshalAndBEncrypt(pioneerEnclavePubK, stringShare)
					recoverShare = types.RecoverShare{WalletID: sourceWallet.HomePioneerID,
						EncWalletPubKShare: encShare,
					}
				}
			}

			var dstEWalletID types.EncryptableSignRecoverKeyEWalletID
			dstEWalletID.Nonce = nonce
			dstEWalletID.WalletID = dstWalletID

			ccPubK := make([]c.VSharePubKInfo, 0)

			ccPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, ccPubK, "", false)
			if err != nil {
				return err
			}

			encDstEWalletIDVShare, dstEWalletIDVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &dstEWalletID)

			msg := types.NewMsgSignRecoverPrivateKey(
				ctx.GetFromAddress().String(),
				encDstEWalletIDVShare,
				c.ProtoizeVShareBindData(dstEWalletIDVShareBind),
				&recoverShare,
			)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "sign recover key", msg)

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().BoolVar(&argIsUser, "is-user", false, "Is a user, send recoverShare")

	return cmd
}
