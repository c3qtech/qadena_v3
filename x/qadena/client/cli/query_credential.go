package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"
)

// printCredential prints credential information in a nicely formatted way
func printCredential(credential *types.Credential, decryptAsPrivKeyHex, decryptAsPubKey string) error {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("CREDENTIAL: %s\n", credential.CredentialID)
	fmt.Println(strings.Repeat("=", 60))

	// Basic Information
	fmt.Printf("Type:                    %s\n", credential.CredentialType)
	if credential.WalletID != "" {
		fmt.Printf("CLAIMED BY Wallet ID:               %s\n", credential.WalletID)
	}
	if credential.ProviderWalletID != "" {
		fmt.Printf("Provider Wallet ID:      %s\n", credential.ProviderWalletID)
	}
	if credential.IdentityOwnerWalletID != "" {
		fmt.Printf("Identity Owner Wallet:   %s\n", credential.IdentityOwnerWalletID)
	}
	if credential.EkycAppWalletID != "" {
		fmt.Printf("eKYC App Wallet ID:      %s\n", credential.EkycAppWalletID)
	}
	if credential.ReferenceCredentialID != "" {
		fmt.Printf("Reference Credential:    %s\n", credential.ReferenceCredentialID)
	}

	fmt.Println(strings.Repeat("-", 40))

	// Pedersen Commits
	if credential.CredentialPedersenCommit != nil {
		fmt.Println("Credential Pedersen Commit:")
		fmt.Printf("  %s\n", c.PrettyPrint(credential.CredentialPedersenCommit))
	}
	if credential.FindCredentialPedersenCommit != nil {
		fmt.Println("Find Credential Pedersen Commit:")
		fmt.Printf("  %s\n", c.PrettyPrint(credential.FindCredentialPedersenCommit))
	}

	// Encrypted Data Information
	if len(credential.EncCredentialInfoVShare) > 0 {
		fmt.Printf("Encrypted Info VShare:   %d bytes\n", len(credential.EncCredentialInfoVShare))
	}
	if len(credential.EncCredentialHashVShare) > 0 {
		fmt.Printf("Encrypted Hash VShare:   %d bytes\n", len(credential.EncCredentialHashVShare))
	}

	// VShare Bind Data
	if credential.CredentialInfoVShareBind != nil {
		fmt.Println("Info VShare Bind Data:")
		fmt.Printf("  %s\n", c.PrettyPrint(credential.CredentialInfoVShareBind))
	}
	if credential.CredentialHashVShareBind != nil {
		fmt.Println("Hash VShare Bind Data:")
		fmt.Printf("  %s\n", c.PrettyPrint(credential.CredentialHashVShareBind))
	}

	// Decrypt and display credential content if decryption keys are provided
	if decryptAsPrivKeyHex != "" && decryptAsPubKey != "" {
		fmt.Println(strings.Repeat("-", 40))
		fmt.Println("DECRYPTED CONTENT:")

		// Decrypt credential info
		if credential.CredentialInfoVShareBind != nil && len(credential.EncCredentialInfoVShare) > 0 {
			unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)

			switch credential.CredentialType {
			case "personal-info":
				var p types.EncryptablePersonalInfo
				err := c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
				if err != nil {
					fmt.Printf("Failed to decrypt personal-info: %v\n", err)
				} else {
					fmt.Println("Personal Info:")
					fmt.Printf("  %s\n", c.PrettyPrint(p))
				}
			case qadenatypes.FirstNamePersonalInfoCredentialType,
				qadenatypes.MiddleNamePersonalInfoCredentialType,
				qadenatypes.LastNamePersonalInfoCredentialType,
				qadenatypes.PhoneContactCredentialType,
				qadenatypes.EmailContactCredentialType:
				var p types.EncryptableSingleContactInfo
				err := c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
				if err != nil {
					fmt.Printf("Failed to decrypt %s: %v\n", credential.CredentialType, err)
				} else {
					fmt.Printf("%s Info:\n", strings.Title(credential.CredentialType))
					fmt.Printf("  %s\n", c.PrettyPrint(p))
				}
			default:
				fmt.Printf("Unknown credential type for decryption: %s\n", credential.CredentialType)
			}
		}

		// Decrypt credential hash if available
		if credential.CredentialHashVShareBind != nil && len(credential.EncCredentialHashVShare) > 0 {
			unprotoCredentialHashVShareBind := c.UnprotoizeVShareBindData(credential.CredentialHashVShareBind)
			var credentialHash types.EncryptableString
			err := c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoCredentialHashVShareBind, credential.EncCredentialHashVShare, &credentialHash)
			if err != nil {
				fmt.Printf("Failed to decrypt credential hash: %v\n", err)
			} else {
				fmt.Println("Credential Hash:")
				fmt.Printf("  %s\n", c.PrettyPrint(credentialHash))
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	return nil
}

func CmdListCredential() *cobra.Command {
	var argDecryptAs string
	cmd := &cobra.Command{
		Use:   "list-credential",
		Short: "list all Credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := qadenatypes.NewQueryClient(clientCtx)

			params := &qadenatypes.QueryAllCredentialRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.CredentialAll(context.Background(), params)
			if err != nil {
				return err
			}

			if argDecryptAs != "" {

				var decryptAsPrivKeyHex string
				var decryptAsPubKey string

				if argDecryptAs != "" {
					_, _, decryptAsPubKey, decryptAsPrivKeyHex, err = c.GetAddress(clientCtx, argDecryptAs)
					if err != nil {
						fmt.Println("Failed to get decryptAs address:", err)
						return err
					}
				}

				for _, credential := range res.Credential {
					err = printCredential(&credential, decryptAsPrivKeyHex, decryptAsPubKey)
					if err != nil {
						return err
					}
				}
				return nil
			} else {
				return clientCtx.PrintProto(res)
			}

		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}

func CmdShowCredential() *cobra.Command {
	var argDecryptAs string

	cmd := &cobra.Command{
		Use:   "show-credential [credential-id] [(optional)credential-type]",
		Short: "shows a Credential",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			argName := args[0]
			argNameCredential := argName + "-credential"
			argCredentialType := ""
			if len(args) > 1 {
				argCredentialType = args[1]
			}

			credentialID, _, _, _, err := c.GetAddress(clientCtx, argNameCredential)
			if err != nil {
				credentialID, _, _, _, err = c.GetAddress(clientCtx, argName)
				if err != nil {
					fmt.Println("Couldn't resolve", argName, "and", argNameCredential, ", assuming", argName, "is the credentialID")
					credentialID = argName
				}
			}

			var decryptAsPrivKeyHex string
			var decryptAsPubKey string

			if argDecryptAs != "" {
				_, _, decryptAsPubKey, decryptAsPrivKeyHex, err = c.GetAddress(clientCtx, argDecryptAs)
				if err != nil {
					return err
				}
			}

			tryCredentialTypes := []string{qadenatypes.PersonalInfoCredentialType, qadenatypes.FirstNamePersonalInfoCredentialType, qadenatypes.MiddleNamePersonalInfoCredentialType, qadenatypes.LastNamePersonalInfoCredentialType, qadenatypes.PhoneContactCredentialType, qadenatypes.EmailContactCredentialType}

			if argCredentialType != "" {
				tryCredentialTypes = []string{argCredentialType}
			}

			// cycle through tryCredentialTypes
			for _, argCredentialType := range tryCredentialTypes {
				credential, err := c.GetCredential(clientCtx, credentialID, argCredentialType)
				if err != nil {
					continue
				}

				err = printCredential(&credential, decryptAsPrivKeyHex, decryptAsPubKey)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}
