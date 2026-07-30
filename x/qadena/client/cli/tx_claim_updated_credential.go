package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func CmdClaimUpdatedCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claim-updated-credential [linked-wallet-friendly-name e.g. al] [--from ephemeral-wallet-friendly-name]",
		Short: "Broadcast message ClaimUpdatedCredential",
		Long: `Re-point an ephemeral wallet's accept-list at the credentials as they stand now.

An ephemeral wallet's accept-list pins each accepted credential's Pedersen commitment at the time
the ephemeral wallet was published.  An update-credential that changes a name moves that
commitment, and the ephemeral wallet then rejects everything until this is run for it.  Run it once
per ephemeral wallet you hold; only the client knows which those are.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argLinkToName := args[0]

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			ephWalletID, _, ephPubK, _, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			ephWallet, err := c.GetWallet(ctx, ephWalletID)
			if err != nil {
				return err
			}

			acceptedTypes := acceptedCredentialTypes(ephWallet.SenderOptions)
			if len(acceptedTypes) == 0 {
				return errors.New("ephemeral wallet " + ephWalletID + " does not accept any credentials, nothing to refresh")
			}

			fmt.Println("refreshing accept-list for", ephWalletID, acceptedTypes)

			linkToWalletID, _, _, _, err := c.GetAddress(ctx, argLinkToName)
			if err != nil {
				return err
			}

			_, _, linkToWalletCredPubKey, linkToWalletCredPrivKeyHex, err := c.GetAddress(ctx, argLinkToName+"-credential")
			if err != nil {
				return err
			}
			linkToWalletCredPrivateKey := linkToWalletCredPrivKeyHex + "_privkhex:" + linkToWalletCredPubKey + "_privk"

			linkToWallet, err := c.GetWallet(ctx, linkToWalletID)
			if err != nil {
				return err
			}

			if linkToWallet.CredentialID == "" {
				return errors.New("wallet " + linkToWalletID + " has no credential")
			}

			// Rebuild the accept-list from the credentials as they are right now.  The enclave
			// checks every commitment against its own copy, so there is no point sending anything
			// but the current values.
			var validatedCredentials types.EncryptableValidatedCredentials
			for _, credentialType := range acceptedTypes {
				credential, err := c.GetCredential(ctx, linkToWallet.CredentialID, credentialType)
				if err != nil {
					return err
				}

				unprotoVShareBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)

				var p types.EncryptableSingleContactInfo
				err = c.VShareBDecryptAndProtoUnmarshal(linkToWalletCredPrivateKey, linkToWalletCredPubKey, unprotoVShareBind, credential.EncCredentialInfoVShare, &p)
				if err != nil {
					fmt.Println("couldn't decrypt", credentialType, "of", linkToWallet.CredentialID)
					return err
				}

				fmt.Println("  ", credentialType, "generation", credential.UpdateGeneration)

				validatedCredentials.Credentials = append(validatedCredentials.Credentials, &types.EncryptableValidatedCredential{
					CredentialType: credentialType,
					PIN:            p.PIN,
					CredentialPC:   credential.CredentialPedersenCommit,
				})
			}

			// same audience as the accept-list CreateWallet published, or the enclave could not
			// decrypt the replacement
			validatedCredentialsCCPubK := []c.VSharePubKInfo{
				{PubK: ephPubK, NodeID: "", NodeType: ""},
			}

			if !TESTskipRequiredChainCCPubK {
				validatedCredentialsCCPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, validatedCredentialsCCPubK, "", false)
				if err != nil {
					return err
				}
			}

			if !TESTskipOptionalCCPubK {
				validatedCredentialsCCPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, validatedCredentialsCCPubK, ephWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
				if err != nil {
					return err
				}
			}

			encAcceptValidatedCredentialsVShare, acceptValidatedCredentialsVShareBind := c.ProtoMarshalAndVShareBEncrypt(validatedCredentialsCCPubK, &validatedCredentials)

			msg := types.NewMsgClaimUpdatedCredential(
				ctx.GetFromAddress().String(),
				encAcceptValidatedCredentialsVShare,
				c.ProtoizeVShareBindData(acceptValidatedCredentialsVShareBind),
			)

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "claim updated credential", []sdk.Msg{msg}...)

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// acceptedCredentialTypes pulls the accept-<type> entries out of a wallet's senderOptions, which
// is where CreateWallet records which credentials an ephemeral wallet accepts.
func acceptedCredentialTypes(senderOptions string) []string {
	credentialTypes := make([]string, 0)
	for _, option := range strings.Split(senderOptions, ",") {
		option = strings.TrimSpace(option)
		if after, ok := strings.CutPrefix(option, types.AcceptOption); ok && after != "" {
			credentialTypes = append(credentialTypes, after)
		}
	}
	return credentialTypes
}
