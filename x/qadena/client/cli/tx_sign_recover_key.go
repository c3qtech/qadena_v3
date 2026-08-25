package cli

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"

	"github.com/spf13/cobra"
)

var _ = strconv.Itoa(0)

func CmdSignRecoverKey() *cobra.Command {
	var argIsUser bool
	var argIsServiceProvider bool
	var argGuardianCredentialHash string

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
				fmt.Println("isUser")
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
					if err != nil {
						fmt.Println("BDecryptAndUnmarshal failed", err)
						return err
					}

					encShare := c.MarshalAndBEncrypt(pioneerEnclavePubK, seedPhrase)
					recoverShare = types.RecoverShare{WalletID: sourceWallet.HomePioneerID,
						EncWalletPubKShare: encShare,
					}
				} else {
					var stringShare string
					_, err = c.BDecryptAndUnmarshal(srcCredPrivateKey, encWalletPubKShare, &stringShare)
					if err != nil {
						fmt.Println("BDecryptAndUnmarshal failed", err)
						return err
					}
					fmt.Println("stringShare", stringShare)
					encShare := c.MarshalAndBEncrypt(pioneerEnclavePubK, stringShare)
					recoverShare = types.RecoverShare{WalletID: sourceWallet.HomePioneerID,
						EncWalletPubKShare: encShare,
					}
				}

			} else if argIsServiceProvider {
				fmt.Println("isServiceProvider", ctx.GetFromName())
				homePioneerID, err := c.GetServiceProviderHomePioneerID(ctx, ctx.GetFromName())
				if err != nil {
					fmt.Println("GetServiceProviderHomePioneerID failed")
					return err
				}

				fmt.Println("homePioneerID", homePioneerID)

				pioneerWalletID, _, err := c.GetIntervalPublicKey(ctx, homePioneerID, types.PioneerNodeType)
				if err != nil {
					fmt.Println("GetIntervalPublicKey failed")
					return err
				}

				pioneerEnclavePubK, err := c.GetPublicKey(ctx, pioneerWalletID, types.EnclavePubKType)
				if err != nil {
					fmt.Println("GetPublicKey enclave failed")
					return err
				}

				encWalletPubKShare, threshold, err := c.GetProtectKey(ctx, dstWalletID, ctx.GetFromName())
				if err != nil {
					fmt.Println("GetProtectKey failed")
					return err
				}

				// srcCredPrivateKey will be used to decrypt the share that was retrieved
				_, _, srcCredPubKey, srcCredPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromName()+"-credential")
				if err != nil {
					return err
				}
				srcCredPrivateKey := srcCredPrivKeyHex + "_privkhex:" + srcCredPubKey + "_privk"

				if threshold == 1 {
					var seedPhrase string
					_, err = c.BDecryptAndUnmarshal(srcCredPrivateKey, encWalletPubKShare, &seedPhrase)
					if err != nil {
						fmt.Println("BDecryptAndUnmarshal failed", err)
						return err
					}
					encShare := c.MarshalAndBEncrypt(pioneerEnclavePubK, seedPhrase)
					recoverShare = types.RecoverShare{WalletID: homePioneerID,
						EncWalletPubKShare: encShare,
					}
				} else {
					var stringShare string
					_, err = c.BDecryptAndUnmarshal(srcCredPrivateKey, encWalletPubKShare, &stringShare)
					if err != nil {
						fmt.Println("BDecryptAndUnmarshal failed", err)
						return err
					}
					fmt.Println("stringShare", stringShare)
					encShare := c.MarshalAndBEncrypt(pioneerEnclavePubK, stringShare)
					recoverShare = types.RecoverShare{WalletID: homePioneerID,
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

			// THE IDENTITY THIS GUARDIAN VERIFIED, when it has one.
			//
			// Institutional guardians in production get this from their app server, which computes
			// it from the user it actually authenticated.  Here it is a flag, because this CLI is
			// an operator and test tool: it is what lets a test drive the matching case, the
			// mismatched case (someone else's hash) and the absent case against each mode.
			//
			// Sent bound to the SAME ccPubK as the destination wallet id, so the SS node can read
			// it -- without that the enclave's getSSPrivK returns "" and the assertion is
			// unreadable, which the enclave treats as a mismatch.
			var encGuardianHashVShare []byte
			var guardianHashVShareBind *types.VShareBindData
			if argGuardianCredentialHash != "" {
				encHash, hashBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK,
					&types.EncryptableString{Value: argGuardianCredentialHash})
				encGuardianHashVShare = encHash
				guardianHashVShareBind = c.ProtoizeVShareBindData(hashBind)
			}

			msg := types.NewMsgSignRecoverPrivateKey(
				ctx.GetFromAddress().String(),
				encDstEWalletIDVShare,
				c.ProtoizeVShareBindData(dstEWalletIDVShareBind),
				&recoverShare,
				encGuardianHashVShare,
				guardianHashVShareBind,
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
	cmd.Flags().BoolVar(&argIsServiceProvider, "is-service-provider", false, "Is a service provider, send recoverShare")
	cmd.Flags().StringVar(&argGuardianCredentialHash, "guardian-credential-hash", "",
		"Hex CreateCredentialHash of the identity this guardian verified.  Institutional guardians "+
			"are required to send it once sign_recover_key_guardian_assertion_mode is 2 (enforce); "+
			"individual guardians are exempt in every mode.")

	return cmd
}
