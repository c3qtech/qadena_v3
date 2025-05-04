package cli

import (
	"strconv"

	"github.com/hashicorp/vault/shamir"

	"qadena/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"errors"
	"fmt"

	qadenatx "qadena/x/qadena/client/tx"
	c "qadena/x/qadena/common"
)

var _ = strconv.Itoa(0)

func duplicateInArray(arr []string) bool {
	visited := make(map[string]bool, 0)
	for i := 0; i < len(arr); i++ {
		if visited[arr[i]] {
			return true
		} else {
			visited[arr[i]] = true
		}
	}
	return false
}

func CmdProtectKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "protect-key [account-mnemonic] [minimum-number-recovery-partners (e.g. 3)] [recovery-partner-phone-number/email-address (e.g. 5551212, anncuisia@c3qtech.com)] [recovery-partner-pioneer (e.g. pioneer1)] [ ... pioneer2 ]...",
		Short: "Broadcast message ProtectKey",
		Args:  cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			var recoverShares []*types.RecoverShare

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			accountMnemonic := args[0]

			threshold, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}

			walletPubKs := make([]string, 0)
			walletIDs := make([]string, 0)

			recoveryPartners := len(args) - 2

			if recoveryPartners < threshold {
				return errors.New("Not enough recovery partners")
			}

			if recoveryPartners > 1 && threshold < 2 {
				return errors.New("Threshold needs to be at least 2")
			}

			for i := 2; i < len(args); i++ {
				id := args[i]
				var walletPubK string
				// check if an address

				isPioneerID := false

				walletID, _, _, _, err := c.GetAddress(ctx, id)

				if err == nil {
					fmt.Println("GetAddress success")
					_, _, err = c.GetIntervalPublicKey(ctx, id, types.PioneerNodeType)
					if err == nil {
						fmt.Println("it's a pioneer ID")
						isPioneerID = true
					}
				} else {
					fmt.Println("GetAddress failed")
					// check if it's a pioneer name
					walletID, walletPubK, err = c.GetIntervalPublicKey(ctx, id, types.PioneerNodeType)
					if err != nil {
						fmt.Println("GetIntervalPublicKey failed")
						// check via naming service
						walletID, err = c.FindSubWallet(ctx, id, types.PhoneContactCredentialType)
						if err != nil {
							fmt.Println("FindSubWallet 'phone' failed")
							walletID, err = c.FindSubWallet(ctx, id, types.EmailContactCredentialType)
							if err != nil {
								fmt.Println("FindSubWallet 'email' failed")
								return err
							} else {
								fmt.Println("FindSubWallet 'email' success")
							}
						} else {
							fmt.Println("FindSubWallet 'phone' success")
						}
					} else {
						fmt.Println("GetIntervalPublicKey success, it's a pioneer ID")
						isPioneerID = true
					}
				}
				walletPubK, err = c.GetPublicKey(ctx, walletID, types.EnclavePubKType)
				if err != nil {
					fmt.Println("GetPublicKey 'enclave' failed")
					walletPubK, err = c.GetPublicKey(ctx, walletID, types.CredentialPubKType)

					if err != nil {
						fmt.Println("GetPublicKey 'credential' failed")
						return err
					} else {
						fmt.Println("GetPublicKey 'credential' success")
					}
				} else {
					fmt.Println("GetPublicKey 'enclave' success")
				}

				fmt.Println("walletID", walletID, "walletPubK", walletPubK)

				if isPioneerID {
					walletIDs = append(walletIDs, id)
				} else {
					walletIDs = append(walletIDs, walletID)
				}

				walletPubKs = append(walletPubKs, walletPubK)
			}

			if duplicateInArray(walletIDs) {
				return errors.New("Duplicates in walletIDs not allowed")
			}

			if recoveryPartners == 1 {
				// only one recovery partner
				encShare := c.MarshalAndBEncrypt(walletPubKs[0], accountMnemonic)
				share := &types.RecoverShare{WalletID: walletIDs[0],
					EncWalletPubKShare: encShare,
				}
				recoverShares = append(recoverShares, share)
			} else {
				// create shares
				var byteShares [][]byte
				byteShares, err := shamir.Split([]byte(accountMnemonic), recoveryPartners, threshold)

				if err != nil {
					fmt.Println("err creating shamir share " + err.Error())
					return err
				}
				for i, byteShare := range byteShares {
					encShare := c.MarshalAndBEncrypt(walletPubKs[i], string(byteShare))
					share := &types.RecoverShare{WalletID: walletIDs[i],
						EncWalletPubKShare: encShare,
					}
					recoverShares = append(recoverShares, share)
				}
			}

			msg := types.NewMsgProtectPrivateKey(
				ctx.GetFromAddress().String(),
				int32(threshold),
				recoverShares,
			)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "protect key", msg)

			return err

		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
