package cli

import (
	"context"
	"fmt"
	"strings"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"
)

func CmdListProtectKey() *cobra.Command {
	var credentialID string

	cmd := &cobra.Command{
		Use:   "list-protect-key",
		Short: "list all ProtectKey",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllProtectKeyRequest{
				Pagination:   pageReq,
				CredentialID: credentialID,
			}

			res, err := queryClient.ProtectKeyAll(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&credentialID, "credential-id", "", "")

	return cmd
}

// printDecryptedRecoverShare opens the recovery share that belongs to decryptAs.
//
// protect-key seals each share to the partner's enclave key when it has one and only
// falls back to the credential key otherwise, so this can open the shares held by
// ordinary users but not the ones held by a pioneer or service provider -- those are
// sealed to an enclave that never exports its private key.
func printDecryptedRecoverShare(clientCtx client.Context, protectKey types.ProtectKey, decryptAs string) error {
	bech32Addr, _, _, _, friendlyName, err := c.GetAddressAndFriendlyName(clientCtx, decryptAs)
	if err != nil {
		return err
	}

	// protect-key files a pioneer's or service provider's share under the ID it was
	// handed on the command line and everyone else's under the resolved wallet ID, so
	// match against every name this account answers to.
	candidates := map[string]bool{decryptAs: true, bech32Addr: true, friendlyName: true}
	delete(candidates, "")

	var encShare []byte
	walletIDs := make([]string, 0, len(protectKey.RecoverShare))
	for _, recoverShare := range protectKey.RecoverShare {
		walletIDs = append(walletIDs, recoverShare.WalletID)
		if candidates[recoverShare.WalletID] {
			encShare = recoverShare.EncWalletPubKShare
		}
	}

	fmt.Println()
	fmt.Println("------------------- QADENA Protect Key Decrypted Info --------------------")

	if encShare == nil {
		fmt.Println(c.RedText("no recovery share for "+decryptAs), "valid decrypt-as:", strings.Join(walletIDs, " "))
		return nil
	}

	// The share is encrypted to the partner's credential key, not its account key.
	_, _, credPubK, credPrivKHex, err := c.GetAddress(clientCtx, friendlyName+"-credential")
	if err != nil {
		return err
	}
	credPrivateKey := credPrivKHex + "_privkhex:" + credPubK + "_privk"

	var share string
	if _, err := c.BDecryptAndUnmarshal(credPrivateKey, encShare, &share); err != nil {
		fmt.Println(c.RedText("can't decrypt " + decryptAs + "'s share -- it is probably sealed to an enclave"))
		return nil
	}

	fmt.Println("Recovery partner", decryptAs)
	fmt.Println("Threshold", protectKey.Threshold)

	// A lone recovery partner holds the whole mnemonic; no Shamir split happened.
	// ValidateBasic rejects a threshold below 2 for any larger set, so threshold 1
	// is exactly the one-partner case -- this is the same test sign-recover-key makes.
	if protectKey.Threshold == 1 {
		fmt.Println(c.WhiteUnderlineText("Account mnemonic"), c.GreenText(share))
	} else {
		fmt.Println(c.WhiteUnderlineText("Shamir share")+" (base64)", c.GreenText(share))
	}

	return nil
}

func CmdShowProtectKey() *cobra.Command {
	var argDecryptAs string

	cmd := &cobra.Command{
		Use:   "show-protect-key [wallet-id]",
		Short: "shows a ProtectKey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argWalletID := args[0]

			params := &types.QueryGetProtectKeyRequest{
				WalletID: argWalletID,
			}

			res, err := queryClient.ProtectKey(context.Background(), params)
			if err != nil {
				return err
			}

			if err := clientCtx.PrintProto(res); err != nil {
				return err
			}

			if argDecryptAs == "" {
				return nil
			}

			return printDecryptedRecoverShare(clientCtx, res.GetProtectKey(), argDecryptAs)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Recovery partner to decrypt this account's share as")

	return cmd
}
