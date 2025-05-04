package cli

import (
	"context"
	"strconv"

	"fmt"

	c "qadena/x/qadena/common"
	"qadena/x/qadena/types"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
)

func CmdListSuspiciousTransaction() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-suspicious-transaction",
		Short: "list all SuspiciousTransaction",
		Args:  cobra.MinimumNArgs(0),
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
					var srcPI types.EncryptablePersonalInfo
					_, err := c.BDecryptAndProtoUnmarshal(privKey, st.EncSourcePersonalInfoRegulatorPubK, &srcPI)
					if err != nil {
						fmt.Println("couldn't get decrypt source credential")
						return err
					}

					var dstPI types.EncryptablePersonalInfo
					_, err = c.BDecryptAndProtoUnmarshal(privKey, st.EncDestinationPersonalInfoRegulatorPubK, &dstPI)
					if err != nil {
						fmt.Println("couldn't get decrypt destination credential")
						return err
					}

					var eAmount types.EncryptableESuspiciousAmount
					_, err = c.BDecryptAndProtoUnmarshal(privKey, st.EncEAmountRegulatorPubK, &eAmount)
					if err != nil {
						fmt.Println("couldn't get decrypt destination credential")
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
							fmt.Println("Source Personal Info")
							fmt.Println("  First Name", c.RedText(srcPI.Details.FirstName))
							fmt.Println("  Middle Name", c.RedText(srcPI.Details.MiddleName))
							fmt.Println("  Last Name", c.RedText(srcPI.Details.LastName))
							fmt.Println("  Birthdate", c.RedText(srcPI.Details.Birthdate))
							fmt.Println("  Citizenship", c.RedText(srcPI.Details.Citizenship))
							fmt.Println("  Residency", c.RedText(srcPI.Details.Residency))
							fmt.Println("  Gender", c.RedText(srcPI.Details.Gender))
							fmt.Println("Destination Personal Info")
							fmt.Println("  First Name", c.RedText(dstPI.Details.FirstName))
							fmt.Println("  Middle Name", c.RedText(dstPI.Details.MiddleName))
							fmt.Println("  Last Name", c.RedText(dstPI.Details.LastName))
							fmt.Println("  Birthdate", c.RedText(dstPI.Details.Birthdate))
							fmt.Println("  Citizenship", c.RedText(dstPI.Details.Citizenship))
							fmt.Println("  Residency", c.RedText(dstPI.Details.Residency))
							fmt.Println("  Gender", c.RedText(dstPI.Details.Gender))
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

func CmdShowSuspiciousTransaction() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-suspicious-transaction [id]",
		Short: "shows a SuspiciousTransaction",
		Args:  cobra.ExactArgs(1),
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

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
