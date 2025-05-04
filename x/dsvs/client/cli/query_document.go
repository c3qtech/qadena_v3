package cli

import (
	"context"
	"encoding/hex"

	dsvstypes "qadena_v3/x/dsvs/types"
	"qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"fmt"
	c "qadena_v3/x/qadena/common"
)

func CmdListDocument() *cobra.Command {
	var argDecryptAs string

	cmd := &cobra.Command{
		Use:   "list-document",
		Short: "list all Documents",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			var decryptAsPrivKeyHex string
			var decryptAsPubKey string

			if argDecryptAs != "" {
				_, _, decryptAsPubKey, decryptAsPrivKeyHex, err = c.GetAddress(clientCtx, argDecryptAs)
				if err != nil {
					return err
				}
			}

			queryClient := dsvstypes.NewQueryClient(clientCtx)

			params := &dsvstypes.QueryAllDocumentRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.DocumentAll(context.Background(), params)
			if err != nil {
				return err
			}

			for _, doc := range res.Document {
				fmt.Println("Document ID:", doc.DocumentID)
				fmt.Println("  Document Type:", doc.DocumentType)
				fmt.Println("  Company Name:", doc.CompanyName)
				// hashes
				for i, hash := range doc.Hash {
					fmt.Println("  Hash", i+1, ":", hex.EncodeToString(hash.Hash))
				}

				if argDecryptAs != "" {
					fmt.Println("  Required Signatories:")
					for i, signatory := range doc.RequiredSignatory {
						var vShareSignatory types.EncryptableSignatory
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind), signatory.EncSignatoryVShare, &vShareSignatory)
						fmt.Println("  ", i+1)
						if err != nil {
							fmt.Println("    Can't decrypt", c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind).GetValidDecryptAsAddresses())
						} else {
							fmt.Println("    Email:", vShareSignatory.Email)
							fmt.Println("    Phone Number:", vShareSignatory.PhoneNumber)
						}
					}
					fmt.Println("  Completed Signatories:")
					for i, signatory := range doc.CompletedSignatory {
						var vShareSignatory types.EncryptableSignatory
						fmt.Println("  ", i+1)
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind), signatory.EncSignatoryVShare, &vShareSignatory)
						if err != nil {
							fmt.Println("    Can't decrypt", c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind).GetValidDecryptAsAddresses())
						} else {
							fmt.Println("    Email:", vShareSignatory.Email)
							fmt.Println("    Phone Number:", vShareSignatory.PhoneNumber)
						}
					}
				}
			}

			return nil
		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}

func CmdShowDocument() *cobra.Command {
	var argVerbose bool
	var argDecryptAs string

	cmd := &cobra.Command{
		Use:   "show-document [id]",
		Short: "Shows a Document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := dsvstypes.NewQueryClient(clientCtx)

			argId := args[0]

			params := &dsvstypes.QueryGetDocumentRequest{
				DocumentID: argId,
			}

			var decryptAsPrivKeyHex string
			var decryptAsPubKey string

			if argDecryptAs != "" {
				_, _, decryptAsPubKey, decryptAsPrivKeyHex, err = c.GetAddress(clientCtx, argDecryptAs)
				if err != nil {
					return err
				}
			}

			res, err := queryClient.Document(context.Background(), params)
			if err != nil {
				return err
			}

			if argVerbose {
				err = clientCtx.PrintProto(res)
			} else {
				if argDecryptAs != "" {
					fmt.Println("Document")
					fmt.Println("ID:", res.Document.DocumentID)
					fmt.Println("Type:", res.Document.DocumentType)
					fmt.Println("Company Name:", res.Document.CompanyName)
					fmt.Println("Document Hashes:")
					for i, hash := range res.Document.Hash {
						fmt.Println("  ", i+1, "Hash:", hex.EncodeToString(hash.Hash))
					}
					fmt.Println("Required Signatories:")
					for i, signatory := range res.Document.RequiredSignatory {
						var vShareSignatory types.EncryptableSignatory
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind), signatory.EncSignatoryVShare, &vShareSignatory)
						fmt.Println("  ", i+1)
						if err != nil {
							fmt.Println("    Can't decrypt", c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind).GetValidDecryptAsAddresses())
						} else {
							fmt.Println("    Email:", vShareSignatory.Email)
							fmt.Println("    Phone Number:", vShareSignatory.PhoneNumber)
						}
					}
					fmt.Println("Completed Signatories:")
					for i, signatory := range res.Document.CompletedSignatory {
						var vShareSignatory types.EncryptableSignatory
						fmt.Println("  ", i+1)
						err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind), signatory.EncSignatoryVShare, &vShareSignatory)
						if err != nil {
							fmt.Println("    Can't decrypt", c.DSVSUnprotoizeVShareBindData(signatory.SignatoryVShareBind).GetValidDecryptAsAddresses())
						} else {
							fmt.Println("    Email:", vShareSignatory.Email)
							fmt.Println("    Phone Number:", vShareSignatory.PhoneNumber)
						}
					}
				} else {
					fmt.Println("Document")
					fmt.Println(c.PrettyPrint(res.Document))
				}
			}

			return err
		},
	}

	flags.AddQueryFlagsToCmd(cmd)
	cmd.Flags().BoolVar(&argVerbose, "verbose", false, "Print out all info about authorized signatory")
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}
