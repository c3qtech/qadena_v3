package cli

import (
	"context"
	"strconv"

	"fmt"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
)

func CmdListSuspiciousTransaction() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-suspicious-transaction [regulator-privkey-hex]",
		Short: "list all SuspiciousTransaction",
		Long: "List suspicious transactions.\n\n" +
			"If you provide the optional argument regulator-privkey-hex (hex-encoded private key for the regulator), " +
			"the command will attempt to decrypt and display the source/destination personal info and amounts for each suspicious transaction.\n\n" +
			"If you omit the argument, it prints the raw protobuf response.",
		Example: "  qadenad query qadena list-suspicious-transaction\n" +
			"  qadenad query qadena list-suspicious-transaction <hex-encoded-regulator-private-key>",
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			c.Debug = false

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllSuspiciousTransactionRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.SuspiciousTransactionAll(context.Background(), params)
			if err != nil {
				return err
			}

			if len(args) == 1 {
				/*
					argName := args[0]
					argNameCredential := argName

					_, _, pubKey, privKeyHex, err := c.GetAddress(clientCtx, argNameCredential)

					if err != nil {
						fmt.Println("Couldn't get private key for", argNameCredential)
						return err
					}
				*/

				privKey := args[0]
				for _, st := range res.GetSuspiciousTransaction() {
					fmt.Println("-------------- Suspicious Transaction " + strconv.Itoa(int(st.Id+1)) + " --------------------")

					srcLines, err := describeReportParty(privKey, st.SourceKind,
						st.EncSourcePersonalInfoRegulatorPubK, st.EncSourceContractInfoRegulatorPubK)
					if err != nil {
						fmt.Println("couldn't decrypt the source party")
						return err
					}

					dstLines, err := describeReportParty(privKey, st.DestinationKind,
						st.EncDestinationPersonalInfoRegulatorPubK, st.EncDestinationContractInfoRegulatorPubK)
					if err != nil {
						fmt.Println("couldn't decrypt the destination party")
						return err
					}

					var eAmount types.EncryptableESuspiciousAmount
					_, err = c.BDecryptAndProtoUnmarshal(privKey, st.EncEAmountRegulatorPubK, &eAmount)
					if err != nil {
						fmt.Println("couldn't decrypt the amount")
						return err
					}
					if eAmount.CoinAmount.Denom != "" {
						decCoin := sdk.NewDecCoinFromCoin(*eAmount.CoinAmount)
						//            fmt.Println("decCoin", decCoin)
						qadenaCoin, err := sdk.ConvertDecCoin(decCoin, types.QadenaTokenDenom)
						attoUsdDecCoin := sdk.NewDecCoinFromCoin(*eAmount.USDCoinAmount)
						usdCoin := sdk.NewDecCoinFromDec(types.USDFiatDenom, attoUsdDecCoin.Amount.Quo(math.LegacyNewDecFromBigInt(c.GetDenomAtomicFactor(18))))

						if err == nil {
							fmt.Println("Time", c.RedText(st.Time.String()))
							fmt.Println("Reason", c.RedText(st.Reason))
							fmt.Println("USDAmount", c.RedText(usdCoin.String()))
							fmt.Println("Amount", c.RedText(qadenaCoin.String()))
							fmt.Println("Source")
							for _, line := range srcLines {
								fmt.Println(line)
							}
							fmt.Println("Destination")
							for _, line := range dstLines {
								fmt.Println(line)
							}
						}
					}
					fmt.Println()
				}
			} else {
				clientCtx.PrintProto(res)
			}

			return nil
		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// describeReportParty decrypts whichever descriptor one side of a report actually carries, and
// renders it for the regulator.
//
// A report names a WALLET by identity and everything else by address, and SourceKind/DestinationKind
// say which.  Reading the personal-info blob unconditionally -- as this used to -- fails with
// "invalid length of message" the moment a treasury or a contract appears in a report, because the
// field it reaches for is empty.  That was unreachable while non-wallet parties were exempt from
// scanning and could never be reported; it became reachable the moment they were not.
//
// WALLET is the zero value, so a report written before party kinds existed still decodes as a pair
// of wallets, which is what it was.
func describeReportParty(privKey string, kind types.SuspiciousPartyKind, encPI, encCI []byte) ([]string, error) {
	if kind == types.SuspiciousPartyKind_SUSPICIOUS_PARTY_KIND_WALLET {
		var pi types.EncryptablePersonalInfo
		if _, err := c.BDecryptAndProtoUnmarshal(privKey, encPI, &pi); err != nil {
			return nil, err
		}
		if pi.Details == nil {
			return []string{"  " + c.RedText("(no personal info in the report)")}, nil
		}
		return []string{
			"  First Name " + c.RedText(pi.Details.FirstName),
			"  Middle Name " + c.RedText(pi.Details.MiddleName),
			"  Last Name " + c.RedText(pi.Details.LastName),
			"  Birthdate " + c.RedText(pi.Details.Birthdate),
			"  Citizenship " + c.RedText(pi.Details.Citizenship),
			"  Residency " + c.RedText(pi.Details.Residency),
			"  Gender " + c.RedText(pi.Details.Gender),
		}, nil
	}

	var ci types.EncryptableContractInfo
	if _, err := c.BDecryptAndProtoUnmarshal(privKey, encCI, &ci); err != nil {
		return nil, err
	}

	// The two non-wallet kinds are told apart deliberately.  A CONTRACT was approved by governance
	// and carries a reason a reviewer wrote; an ADDRESS_ONLY party was never approved and has none,
	// so presenting them the same way would imply a scrutiny that never happened.
	if kind == types.SuspiciousPartyKind_SUSPICIOUS_PARTY_KIND_ADDRESS_ONLY {
		return []string{
			"  " + c.RedText("(no identity on record -- named by address)"),
			"  Address " + c.RedText(ci.Address),
		}, nil
	}

	lines := []string{
		"  " + c.RedText("(whitelisted non-wallet party)"),
		"  Address " + c.RedText(ci.Address),
	}
	if ci.CodeID != 0 {
		lines = append(lines, "  Wasm Code ID "+c.RedText(strconv.FormatUint(ci.CodeID, 10)))
	}
	if ci.Reason != "" {
		lines = append(lines, "  Whitelisted Because "+c.RedText(ci.Reason))
	}
	return lines, nil
}

func CmdShowSuspiciousTransaction() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-suspicious-transaction [id] [regulator-privkey-hex]",
		Short: "shows a SuspiciousTransaction",
		Long: "Show a suspicious transaction by id.\n\n" +
			"If you provide the optional argument regulator-privkey-hex (hex-encoded private key for the regulator), " +
			"the command will attempt to decrypt and display the source/destination personal info and amounts for this suspicious transaction.\n\n" +
			"If you omit the argument, it prints the raw protobuf response.",
		Example: "  qadenad query qadena show-suspicious-transaction 1\n" +
			"  qadenad query qadena show-suspicious-transaction 1 <hex-encoded-regulator-private-key>",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return err
			}

			params := &types.QueryGetSuspiciousTransactionRequest{
				Id: id,
			}

			res, err := queryClient.SuspiciousTransaction(context.Background(), params)
			if err != nil {
				return err
			}

			if len(args) == 2 {
				privKey := args[1]
				st := res.GetSuspiciousTransaction()
				fmt.Println("-------------- Suspicious Transaction --------------------")
				srcLines, err := describeReportParty(privKey, st.SourceKind,
					st.EncSourcePersonalInfoRegulatorPubK, st.EncSourceContractInfoRegulatorPubK)
				if err != nil {
					fmt.Println("couldn't decrypt the source party")
					return err
				}

				dstLines, err := describeReportParty(privKey, st.DestinationKind,
					st.EncDestinationPersonalInfoRegulatorPubK, st.EncDestinationContractInfoRegulatorPubK)
				if err != nil {
					fmt.Println("couldn't decrypt the destination party")
					return err
				}

				var eAmount types.EncryptableESuspiciousAmount
				_, err = c.BDecryptAndProtoUnmarshal(privKey, st.EncEAmountRegulatorPubK, &eAmount)
				if err != nil {
					fmt.Println("couldn't decrypt amount")
					return err
				}

				if eAmount.CoinAmount.Denom != "" {
					decCoin := sdk.NewDecCoinFromCoin(*eAmount.CoinAmount)
					qadenaCoin, err := sdk.ConvertDecCoin(decCoin, types.QadenaTokenDenom)
					attoUsdDecCoin := sdk.NewDecCoinFromCoin(*eAmount.USDCoinAmount)
					usdCoin := sdk.NewDecCoinFromDec(types.USDFiatDenom, attoUsdDecCoin.Amount.Quo(math.LegacyNewDecFromBigInt(c.GetDenomAtomicFactor(18))))
					if err == nil {
						fmt.Println("Time", c.RedText(st.Time.String()))
						fmt.Println("Reason", c.RedText(st.Reason))
						fmt.Println("USDAmount", c.RedText(usdCoin.String()))
						fmt.Println("Amount", c.RedText(qadenaCoin.String()))
						fmt.Println("Source")
						for _, line := range srcLines {
							fmt.Println(line)
						}
						fmt.Println("Destination")
						for _, line := range dstLines {
							fmt.Println(line)
						}
					}
				}
				fmt.Println()
				return nil
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
