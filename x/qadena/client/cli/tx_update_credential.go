package cli

import (
	"bufio"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	proto "github.com/cosmos/gogoproto/proto"
	"github.com/spf13/cobra"

	qadenatx "github.com/c3qtech/qadena_v3/x/qadena/client/tx"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// nameSubCredentialTypes are the sub-credentials that ride along inside a personal-info update.
// They must move together with the personal-info row or the transfer-time name proof would attest
// to a name that is not in the identity hash.
var nameSubCredentialTypes = []string{
	types.FirstNamePersonalInfoCredentialType,
	types.MiddleNamePersonalInfoCredentialType,
	types.LastNamePersonalInfoCredentialType,
}

func CmdUpdateCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-credential [find-credential-pc amount (e.g. 1234)] [find-credential-pc blinding-factor (e.g. 5678)] [credential-type e.g. personal-info, phone-contact-info, email-contact-info] [--from wallet-friendly-name e.g. ann, al]",
		Short: "Broadcast message UpdateCredential",
		Long: `Fold corrected data, re-issued by an identity provider under a fresh claim code, into a
credential this wallet already owns.  The credentialID, the wallet and the recovery material all
stay as they are; key recovery keeps working with the OLD information.

For personal-info the chain enforces that the change looks like a correction or a recognised life
event: at most one of first/middle/last name, birthdate or gender may move per update.  A contact
credential is a single value with no identity hash behind it, so any new value is accepted -- but the
old value keeps naming you in the nameservice until you unbind it, which this command will remind
you to do.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			argFindCredentialA := args[0]
			argFindCredentialBF := args[1]
			argCredentialType := args[2]

			switch argCredentialType {
			case types.PersonalInfoCredentialType, types.PhoneContactCredentialType, types.EmailContactCredentialType:
			default:
				return errors.New("update-credential does not support " + argCredentialType)
			}

			ctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			srcWalletID, _, srcPubKey, srcPrivKeyHex, err := c.GetAddress(ctx, ctx.GetFromAddress().String())
			if err != nil {
				return err
			}

			argName := ctx.GetFromName()

			// CHECKED, unlike before.  SetString returns nil on a non-numeric argument, and
			// NewPedersenCommit treats a nil blinding factor as "generate a random one"
			// (x/qadena/common/ecpedersen.go), so a typo silently produced a commitment nothing
			// could recompute -- surfacing later as ErrCredentialNotExists, which names neither
			// the argument nor the parse.  See docs/TESTING-BACKLOG.md item 41.
			findCredentialA, okA := big.NewInt(0).SetString(argFindCredentialA, 10)
			if !okA {
				return fmt.Errorf("find-credential amount must be a base-10 integer, got %q", argFindCredentialA)
			}
			findCredentialBF, okBF := big.NewInt(0).SetString(argFindCredentialBF, 10)
			if !okBF {
				return fmt.Errorf("find-credential blinding factor must be a base-10 integer, got %q", argFindCredentialBF)
			}
			findCredentialPC := c.NewPedersenCommit(findCredentialA, findCredentialBF)

			fmt.Println("findCredentialPC", c.PrettyPrint(findCredentialPC))

			srcWallet, err := c.GetWallet(ctx, srcWalletID)
			if err != nil {
				return err
			}

			if srcWallet.CredentialID == "" {
				return errors.New("this wallet has no credential to update")
			}

			isPersonalInfo := argCredentialType == types.PersonalInfoCredentialType

			// The identity provider's corrected data, fetched exactly the way a claim fetches it --
			// QueryFindCredential does not care that we already hold a credential.
			var newPI types.EncryptablePersonalInfo
			var newContact types.EncryptableSingleContactInfo
			var identityProviderCredentialID string
			// the contact being retired, needed after broadcast for the unbind reminder
			var oldContactForReminder string

			if isPersonalInfo {
				if err := queryFindCredential(cmd, argName, findCredentialPC, argCredentialType, &newPI, &identityProviderCredentialID); err != nil {
					return err
				}

				if err := c.ValidatePersonalInfoDetails(newPI.Details); err != nil {
					return fmt.Errorf("the identity provider's corrected personal info is not valid: %w", err)
				}

				// The user's existing row, decrypted only so we can show a diff and pre-check the
				// policy.  The enclave recomputes all of this from its own copy and trusts nothing
				// sent from here.
				oldPI, err := decryptOwnPersonalInfo(ctx, argName, srcWallet.CredentialID)
				if err != nil {
					return err
				}

				verdict, err := c.ClassifyPersonalInfoUpdate(oldPI.Details, newPI.Details, c.DefaultUpdatePolicy())
				if err != nil {
					// Fail here rather than spend a transaction on a rejection.  The chain's own
					// params may be stricter than the defaults used for this pre-check, so a pass
					// here is not a guarantee -- a failure, however, is decisive.
					return err
				}

				printPersonalInfoDiff(oldPI.Details, newPI.Details, verdict)
			} else {
				if err := queryFindCredential(cmd, argName, findCredentialPC, argCredentialType, &newContact, &identityProviderCredentialID); err != nil {
					return err
				}

				if newContact.Details == nil || newContact.Details.Contact == "" {
					return errors.New("the identity provider's corrected " + argCredentialType + " is empty")
				}

				oldContact, err := decryptOwnContactInfo(ctx, argName, srcWallet.CredentialID, argCredentialType)
				if err != nil {
					return err
				}

				oldContactForReminder = oldContact.Details.GetContact()

				printContactDiff(argCredentialType, oldContactForReminder, newContact.Details.Contact)
			}

			// --yes comes from AddTxFlagsToCmd (flags.FlagSkipConfirmation) and lands here as
			// ctx.SkipConfirm; this command must not define a flag of its own by that name.
			if !ctx.SkipConfirm {
				confirmed, err := confirmUpdate(cmd)
				if err != nil {
					return err
				}
				if !confirmed {
					return errors.New("aborted")
				}
			}

			srcTransactionPrivateKey := srcPrivKeyHex + "_privkhex:" + srcPubKey + "_privk"

			var ewa types.EncryptableWalletAmount
			unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(srcWallet.WalletAmount[types.QadenaTokenDenom].WalletAmountVShareBind)
			err = c.VShareBDecryptAndProtoUnmarshal(srcTransactionPrivateKey, srcPubKey, unprotoWalletAmountVShareBind, srcWallet.WalletAmount[types.QadenaTokenDenom].EncWalletAmountVShare, &ewa)
			if err != nil {
				return err
			}

			credentialID, _, credentialPubKey, _, err := c.GetAddress(ctx, argName+"-credential")
			if err != nil {
				return err
			}
			if credentialID != srcWallet.CredentialID {
				return errors.New("keyring credential " + credentialID + " is not this wallet's credential " + srcWallet.CredentialID)
			}

			// Collect the identity provider's corrected name sub-credentials under the same claim
			// code.  They travel inside the one message so the enclave can police them against
			// the personal-info diff.  A contact credential has none.
			subUpdates := make([]subCredentialSource, 0, len(nameSubCredentialTypes))
			if isPersonalInfo {
				for _, subType := range nameSubCredentialTypes {
					var pSCI types.EncryptableSingleContactInfo
					var ignored string
					if err := queryFindCredential(cmd, argName, findCredentialPC, subType, &pSCI, &ignored); err != nil {
						return err
					}
					subUpdates = append(subUpdates, subCredentialSource{
						credentialType: subType,
						details:        pSCI.Details,
						pin:            pSCI.PIN,
					})
				}
			}

			var msg *types.MsgUpdateCredential
			if isPersonalInfo {
				msg, err = createUpdateCredentialMessage(
					ctx,
					findCredentialPC,
					srcWallet.CredentialID,
					credentialPubKey,
					argCredentialType,
					newPI.Details,
					newPI.PIN,
					subUpdates,
					srcWalletID,
					srcWallet,
					ewa)
			} else {
				msg, err = createUpdateCredentialMessage(
					ctx,
					findCredentialPC,
					srcWallet.CredentialID,
					credentialPubKey,
					argCredentialType,
					newContact.Details,
					newContact.PIN,
					nil,
					srcWalletID,
					srcWallet,
					ewa)
			}
			if err != nil {
				return err
			}

			err, _ = qadenatx.GenerateOrBroadcastTxCLISync(ctx, cmd.Flags(), "update credential", []sdk.Msg{msg}...)
			if err != nil {
				return err
			}

			if !isPersonalInfo {
				printUnbindReminder(argCredentialType, oldContactForReminder)
			}

			return nil
		},
	}

	// this already provides --yes, which doubles as "skip the diff confirmation"
	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// subCredentialSource is one name sub-credential as the identity provider issued it.
type subCredentialSource struct {
	credentialType string
	details        *types.EncryptableSingleContactInfoDetails
	pin            string
}

func createUpdateCredentialMessage(ctx client.Context, findCredentialPC *c.PedersenCommit, credentialID string, credPubKey string, credentialType string, newDetails proto.Message, newPin string, subs []subCredentialSource, srcWalletID string, srcWallet types.Wallet, ewa types.EncryptableWalletAmount) (*types.MsgUpdateCredential, error) {
	address := ctx.GetFromAddress().String()

	var err error

	ccPubK := []c.VSharePubKInfo{
		{PubK: credPubKey, NodeID: "", NodeType: ""},
	}

	if !TESTskipRequiredChainCCPubK {
		ccPubK, err = c.ClientAppendRequiredChainCCPubK(ctx, ccPubK, "", false)
		if err != nil {
			return nil, err
		}
	}

	if !TESTskipOptionalCCPubK {
		ccPubK, err = c.ClientAppendOptionalServiceProvidersCCPubK(ctx, ccPubK, srcWallet.ServiceProviderID, []string{types.FinanceServiceProvider})
		if err != nil {
			return nil, err
		}
	}

	outerCCPubK := ccPubK

	if TESTskipInnerCCPubK {
		ccPubK = []c.VSharePubKInfo{
			{PubK: credPubKey, NodeID: "", NodeType: ""},
		}
	}

	walletPC := c.UnprotoizeEncryptablePedersenCommit(ewa.PedersenCommit)

	// Each credential gets its own fresh PIN and its own claimPC against the same walletPC,
	// exactly as the four-message claim flow does with a shared ewa.
	reblinded, err := reblindCredential(credentialType, newDetails, newPin, walletPC, ccPubK)
	if err != nil {
		return nil, err
	}

	// Only personal-info has an identity hash; the enclave does not even look at the field for a
	// contact credential.
	var encCredentialHashVShare []byte
	var credentialHashVShareBind *c.VShareBindData
	if personalInfoDetails, ok := newDetails.(*types.EncryptablePersonalInfoDetails); ok {
		credentialHash := c.CreateCredentialHash(personalInfoDetails)
		encCredentialHashVShare, credentialHashVShareBind = c.ProtoMarshalAndVShareBEncrypt(ccPubK, &types.EncryptableString{Value: credentialHash})
	}

	protoSubUpdates := make([]*types.EncryptableUpdateSubCredential, 0, len(subs))
	for _, sub := range subs {
		subReblinded, err := reblindCredential(sub.credentialType, sub.details, sub.pin, walletPC, ccPubK)
		if err != nil {
			return nil, err
		}

		protoSubUpdates = append(protoSubUpdates, &types.EncryptableUpdateSubCredential{
			CredentialType:           sub.credentialType,
			EncCredentialInfoVShare:  subReblinded.encCredentialInfoVShare,
			CredentialInfoVShareBind: c.ProtoizeVShareBindData(subReblinded.credentialInfoVShareBind),
			FindCredentialPC:         c.ProtoizeBPedersenCommit(findCredentialPC),
			NewCredentialPC:          c.ProtoizeBPedersenCommit(subReblinded.newCredentialPC),
			ZeroPC:                   c.ProtoizeEncryptablePedersenCommit(subReblinded.zeroPC),
			ClaimPC:                  c.ProtoizeBPedersenCommit(subReblinded.claimPC),
		})
	}

	parms := types.EncryptableUpdateCredentialExtraParms{
		EncCredentialInfoVShare:  reblinded.encCredentialInfoVShare,
		CredentialInfoVShareBind: c.ProtoizeVShareBindData(reblinded.credentialInfoVShareBind),
		WalletID:                 srcWalletID,
		EncCredentialHashVShare:  encCredentialHashVShare,
		CredentialHashVShareBind: c.ProtoizeVShareBindData(credentialHashVShareBind),
		FindCredentialPC:         c.ProtoizeBPedersenCommit(findCredentialPC),
		NewCredentialPC:          c.ProtoizeBPedersenCommit(reblinded.newCredentialPC),
		ZeroPC:                   c.ProtoizeEncryptablePedersenCommit(reblinded.zeroPC),
		ClaimPC:                  c.ProtoizeBPedersenCommit(reblinded.claimPC),
		SubUpdates:               protoSubUpdates,
	}

	encParmsVShare, parmsVShareBind := c.ProtoMarshalAndVShareBEncrypt(outerCCPubK, &parms)

	msg := types.NewMsgUpdateCredential(
		address,
		credentialID,
		credentialType,
		encParmsVShare,
		c.ProtoizeVShareBindData(parmsVShareBind),
	)

	return msg, msg.ValidateBasic()
}

// decryptOwnPersonalInfo reads and decrypts the caller's current personal-info row.  Used only to
// show a diff and pre-check the policy locally.
func decryptOwnPersonalInfo(ctx client.Context, argName string, credentialID string) (types.EncryptablePersonalInfo, error) {
	var pi types.EncryptablePersonalInfo

	_, _, credPubKey, credPrivKeyHex, err := c.GetAddress(ctx, argName+"-credential")
	if err != nil {
		return pi, err
	}
	credPrivateKey := credPrivKeyHex + "_privkhex:" + credPubKey + "_privk"

	credential, err := c.GetCredential(ctx, credentialID, types.PersonalInfoCredentialType)
	if err != nil {
		return pi, err
	}

	unprotoBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
	err = c.VShareBDecryptAndProtoUnmarshal(credPrivateKey, credPubKey, unprotoBind, credential.EncCredentialInfoVShare, &pi)
	if err != nil {
		fmt.Println("couldn't decrypt your existing credential; is", argName+"-credential", "the right key?")
		return pi, err
	}

	return pi, nil
}

// decryptOwnContactInfo reads and decrypts one of the caller's current contact credentials, for the
// diff and the unbind reminder.
func decryptOwnContactInfo(ctx client.Context, argName string, credentialID string, credentialType string) (types.EncryptableSingleContactInfo, error) {
	var contact types.EncryptableSingleContactInfo

	_, _, credPubKey, credPrivKeyHex, err := c.GetAddress(ctx, argName+"-credential")
	if err != nil {
		return contact, err
	}
	credPrivateKey := credPrivKeyHex + "_privkhex:" + credPubKey + "_privk"

	credential, err := c.GetCredential(ctx, credentialID, credentialType)
	if err != nil {
		return contact, err
	}

	unprotoBind := c.UnprotoizeVShareBindData(credential.CredentialInfoVShareBind)
	err = c.VShareBDecryptAndProtoUnmarshal(credPrivateKey, credPubKey, unprotoBind, credential.EncCredentialInfoVShare, &contact)
	if err != nil {
		fmt.Println("couldn't decrypt your existing", credentialType)
		return contact, err
	}

	return contact, nil
}

func printContactDiff(credentialType, oldContact, newContact string) {
	fmt.Println()
	fmt.Println("This will overwrite your", credentialType, "in place:")
	fmt.Printf("  --> %q -> %q\n", oldContact, newContact)
	fmt.Println()
	fmt.Println("your identity hash is not affected, so key recovery is unchanged")
	fmt.Println()
}

// printUnbindReminder tells the user about the one thing this command cannot do for them.  Name
// bindings are keyed by the cleartext contact and are signed by the ephemeral wallet that created
// them, so neither this command nor the enclave can retire the old value: only the client knows
// which ephemeral wallets bound it, and only they can sign.
func printUnbindReminder(credentialType, oldContact string) {
	if oldContact == "" {
		return
	}

	fmt.Println()
	fmt.Println("NOTE:", oldContact, "still resolves to your wallet in the nameservice.")
	fmt.Println("From each ephemeral wallet that bound it, run:")
	fmt.Println("  tx nameservice unbind-credential", credentialType, oldContact, "--from <eph-wallet>")
	fmt.Println("and then bind the new value:")
	fmt.Println("  tx nameservice bind-credential <real-wallet>", credentialType, "--from <eph-wallet>")
	fmt.Println()
}

func printPersonalInfoDiff(oldDetails, newDetails *types.EncryptablePersonalInfoDetails, verdict c.UpdateVerdict) {
	fields := []struct {
		name     string
		old, new string
	}{
		{"first name", oldDetails.FirstName, newDetails.FirstName},
		{"middle name", oldDetails.MiddleName, newDetails.MiddleName},
		{"last name", oldDetails.LastName, newDetails.LastName},
		{"birthdate", oldDetails.Birthdate, newDetails.Birthdate},
		{"gender", oldDetails.Gender, newDetails.Gender},
		{"citizenship", oldDetails.Citizenship, newDetails.Citizenship},
		{"residency", oldDetails.Residency, newDetails.Residency},
	}

	fmt.Println()
	fmt.Println("This will overwrite your identity data in place:")
	for _, f := range fields {
		if f.old == f.new {
			fmt.Printf("      %-12s %s\n", f.name, f.old)
			continue
		}
		fmt.Printf("  --> %-12s %q -> %q\n", f.name, f.old, f.new)
	}
	fmt.Println()
	fmt.Println("classified as:", verdict.Kind.String())
	if verdict.HashChanged {
		fmt.Println("this changes your identity hash; the old one keeps working for key recovery")
	}
	fmt.Println()
}

func confirmUpdate(cmd *cobra.Command) (bool, error) {
	fmt.Print("Proceed? [y/N]: ")

	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
