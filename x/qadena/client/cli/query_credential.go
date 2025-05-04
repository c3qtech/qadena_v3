package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"
)

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
					// unproto credential.VShareBind
					unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)

					switch credential.CredentialType {
					case "personal-info":
						var p types.EncryptablePersonalInfo
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
						if err != nil {
							fmt.Println("Failed to decrypt personal-info for ", credential.CredentialID)
							continue
						}
						fmt.Println(credential.CredentialID, credential.CredentialType, c.PrettyPrint(p))
					case qadenatypes.FirstNamePersonalInfoCredentialType:
						fallthrough
					case qadenatypes.MiddleNamePersonalInfoCredentialType:
						fallthrough
					case qadenatypes.LastNamePersonalInfoCredentialType:
						fallthrough
					case qadenatypes.PhoneContactCredentialType:
						fallthrough
					case qadenatypes.EmailContactCredentialType:
						var p types.EncryptableSingleContactInfo
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
						if err != nil {
							fmt.Println("Failed to decrypt personal-info for ", credential.CredentialID)
							continue
						}
						fmt.Println(credential.CredentialID, credential.CredentialType, c.PrettyPrint(p))
					default:
						fmt.Println("unrecognized credential-type", credential.CredentialType)
						return errors.New("bad args")
					}

					if credential.CredentialHashVShareBind != nil {
						unprotoCredentialHashVShareBind := c.UnprotoizeVShareBindData(credential.CredentialHashVShareBind)
						var credentialHash types.EncryptableString
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoCredentialHashVShareBind, credential.EncCredentialHashVShare, &credentialHash)
						if err != nil {
							fmt.Println("Failed to decrypt personal-info for ", credential.CredentialID)
							continue
						}
						fmt.Println("CredentialHash", credential.CredentialID, c.PrettyPrint(credentialHash))
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

				if credential.WalletID != "" {
					fmt.Println(credentialID, "CREDENTIAL CLAIMED BY", credential.WalletID)
				}

				if argDecryptAs != "" {
					// unproto credential.VShareBind
					unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)

					switch argCredentialType {
					case "personal-info":
						var p types.EncryptablePersonalInfo
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
						if err == nil {
							fmt.Println(credentialID, argCredentialType, c.PrettyPrint(p))
						}
					case qadenatypes.FirstNamePersonalInfoCredentialType:
						fallthrough
					case qadenatypes.MiddleNamePersonalInfoCredentialType:
						fallthrough
					case qadenatypes.LastNamePersonalInfoCredentialType:
						fallthrough
					case qadenatypes.PhoneContactCredentialType:
						fallthrough
					case qadenatypes.EmailContactCredentialType:
						var p types.EncryptableSingleContactInfo
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
						if err == nil {
							fmt.Println(credentialID, argCredentialType, c.PrettyPrint(p))
						}
					default:
						fmt.Println("unrecognized credential-type", argCredentialType)
						return errors.New("bad args")
					}

					if credential.CredentialHashVShareBind != nil {
						unprotoCredentialHashVShareBind := c.UnprotoizeVShareBindData(credential.CredentialHashVShareBind)
						var credentialHash types.EncryptableString
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoCredentialHashVShareBind, credential.EncCredentialHashVShare, &credentialHash)
						if err == nil {
							fmt.Println(credentialID, "CredentialHash", c.PrettyPrint(credentialHash))
						}
					}
				} else {
					fmt.Println("Credential")
					fmt.Println(c.PrettyPrint(credential))
				}
			}

			return nil
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}
