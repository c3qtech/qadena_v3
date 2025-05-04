package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	//	"io/fs"
	//"math/big"
	"os"
	"strconv"

	//"errors"
	//"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	dsvstypes "qadena/x/dsvs/types"
	c "qadena/x/qadena/common"

	qadenatx "qadena/x/qadena/client/tx"
	"qadena/x/qadena/types"
	// proto "github.com/cosmos/gogoproto/proto"
)

var _ = strconv.Itoa(0)

func hashFile(filePath string) ([]byte, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	hasher := sha256.New()
	buffer := make([]byte, 32*1024) // 32KB chunks

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			hasher.Write(buffer[:n])
		}
		if err != nil {
			break
		}
	}

	hashBytes := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	return hashBytes, hashString, nil
}

func CmdCreateDocument() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-document [document-id] [document-type e.g. ByLaws, ArticlesOfIncorporation, etc.] [company-name] [document] [signatory-1-email] [signatory-1-phone] ...",
		Short: "Broadcast message CreateDocument",
		Args:  cobra.MinimumNArgs(6),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argDocumentID := args[0]
			argDocumentType := args[1]
			argCompanyName := args[2]
			argDocument := args[3]

			// hash the file contents
			fileHashBytes, fileHash, err := hashFile(argDocument)
			if err != nil {
				return err
			}
			fmt.Printf("File hash: %s\n", fileHash)

			// EncryptableSignatory array
			argSignatories := make([]types.EncryptableSignatory, 0)

			for i := 4; i < len(args); i += 2 {
				argSignatories = append(argSignatories, types.EncryptableSignatory{
					Nonce:       c.Nonce(),
					Email:       args[i],
					PhoneNumber: args[i+1],
				})
			}

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// get source wallet ID, source public key in bytes, source public key and source private key hex
			srcWalletID, _, srcPubKey, _, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			fmt.Println("srcWalletID", srcWalletID)
			fmt.Println("srcPubKey", srcPubKey)

			ccPubK := make([]c.VSharePubKInfo, 0)

			ccPubK = append(ccPubK, c.VSharePubKInfo{PubK: srcPubKey, NodeID: ctx.GetFromName(), NodeType: types.ServiceProviderNodeType})

			ccPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, ccPubK, "", false)
			if err != nil {
				return err
			}

			requiredSignatory := make([]*dsvstypes.VShareSignatory, 0)

			// for each signatory, sign the document
			for _, signatory := range argSignatories {
				// sign the document
				encryptedDocument, bind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &signatory)
				fmt.Println("encryptedDocument", encryptedDocument)
				fmt.Println("bind", bind)
				if !bind.VShareBVerify(encryptedDocument) {
					return fmt.Errorf("failed to verify bind")
				}

				protoizedVShareBind := c.DSVSProtoizeVShareBindData(bind)

				requiredSignatory = append(requiredSignatory, &dsvstypes.VShareSignatory{
					EncSignatoryVShare:  encryptedDocument,
					SignatoryVShareBind: protoizedVShareBind,
				})
			}

			// create a document
			msgCD := dsvstypes.MsgCreateDocument{
				Creator:           ctx.GetFromAddress().String(),
				DocumentID:        argDocumentID,
				DocumentType:      argDocumentType,
				CompanyName:       argCompanyName,
				RequiredSignatory: requiredSignatory,
				Hash:              fileHashBytes,
			}

			if err := msgCD.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "create document", &msgCD)

			return err

		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
