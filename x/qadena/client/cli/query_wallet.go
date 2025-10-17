package cli

import (
	"context"
	//	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	//	ibctransfertypes "github.com/cosmos/ibc-go/v10/modules/apps/transfer/types"

	//"math/big"

	//	"cosmossdk.io/math"
	//	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

func CmdListWallet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-wallet",
		Short: "list all Wallet",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryAllWalletRequest{
				Pagination: pageReq,
			}

			res, err := queryClient.WalletAll(context.Background(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

func displayWalletAmount(walletAmount *types.WalletAmount, decryptAsPrivKeyHex string, decryptAsPubKey string) error {
	note := ""
	var ewa types.EncryptableWalletAmount
	unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(walletAmount.WalletAmountVShareBind)
	err := c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoWalletAmountVShareBind, walletAmount.EncWalletAmountVShare, &ewa)
	if err != nil {
		fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.RedText("can't decrypt "+unprotoWalletAmountVShareBind.GetValidDecryptAsAddresses()))
	} else {

		note = ""

		if ewa.Note != "" {
			note = ewa.Note
		}

		decryptedAmount := c.UnprotoizeBInt(ewa.PedersenCommit.A)

		if decryptedAmount != nil {
			decryptedDenom := types.AQadenaTokenDenom
			coin, err := sdk.ParseDecCoin(decryptedAmount.String() + decryptedDenom)
			if err != nil {
				return err
			}
			qadenaCoin, err := sdk.ConvertDecCoin(coin, types.QadenaTokenDenom)
			if err != nil {
				return err
			}

			fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText(qadenaCoin.Amount.String()+qadenaCoin.Denom) /*, "[Encryption-"+c.TruncateText(hex.EncodeToString(wallet.WalletAmount[types.QadenaTokenDenom].EncWalletAmountVShare), 20)+"...]" */)
		}
		if note != "" {
			fmt.Println(c.WhiteUnderlineText("Note")+" ", c.GreenText(note))
		}
	}
	return nil
}

func CmdShowWallet() *cobra.Command {
	var argDecryptAs string
	var argMnemonic string
	cmd := &cobra.Command{
		Use:   "show-wallet [wallet-id]",
		Short: "shows a Wallet",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {

			c.Debug = true

			clientCtx := client.GetClientContextFromCmd(cmd)

			var decryptAsPrivKeyHex string
			var decryptAsPubKey string

			var argWalletID string = args[0]

			if argMnemonic == "" {
				argWalletID, _, _, _, err = c.GetAddress(clientCtx, args[0])
				if err != nil {
					argWalletID = args[0]
				}

				if argDecryptAs != "" {
					_, _, decryptAsPubKey, decryptAsPrivKeyHex, err = c.GetAddress(clientCtx, argDecryptAs)
					if err != nil {
						return err
					}
				}

			} else {
				kb := c.GetKeyring(clientCtx)

				algo, err := c.GetAlgo(kb)
				if err != nil {
					fmt.Println("Couldn't get keyring algo", err)
					return err
				}

				var bip39Passphrase = c.GetBip39PassPhrase()

				hdPath := hd.CreateHDPath(sdk.GetConfig().GetCoinType(), 0, 1).String()

				// create master key and derive first key for keyring
				derivedPriv, err := algo.Derive()(argMnemonic, bip39Passphrase, hdPath)
				if err != nil {
					return err
				}

				privKey := algo.Generate()(derivedPriv)
				decryptAsPrivKeyHex = hex.EncodeToString(privKey.Bytes())
				decryptAsPubKey = base64.StdEncoding.EncodeToString(privKey.PubKey().Bytes())
				argWalletID = sdk.AccAddress(privKey.PubKey().Address()).String()
			}

			fmt.Println("Getting transparent bank balance")
			queryBankClient := banktypes.NewQueryClient(clientCtx)
			addr, err := sdk.AccAddressFromBech32(argWalletID)
			if err != nil {
				return err
			}

			ctx := cmd.Context()

			allBalancesParams := banktypes.NewQueryAllBalancesRequest(addr, &query.PageRequest{}, false) /* TODO TODO check if resolvedenom should be true or false */
			allBalancesRes, err := queryBankClient.AllBalances(ctx, allBalancesParams)
			if err != nil {
				return err
			}

			/*
				queryIbcClient := ibctransfertypes.NewQueryClient(clientCtx)
				denomTracesParams := &ibctransfertypes.QueryDenomTracesRequest{
					Pagination: &query.PageRequest{},
				}
				denomTracesRes, err := queryIbcClient.DenomTraces(ctx, denomTracesParams)
				if err != nil {
					return err
				}
			*/

			wallet, err := c.GetWallet(clientCtx, argWalletID)

			if err != nil {
				for _, coin := range allBalancesRes.Balances {
					if strings.Index(coin.Denom, "erc20") > -1 {
						continue
					}

					// check wether the token is the primary token "aqdn"
					if coin.Denom == types.AQadenaTokenDenom {
						qadenaCoin, err := sdk.ConvertDecCoin(sdk.NewDecCoinFromCoin(coin), types.QadenaTokenDenom)
						if err != nil {
							return err
						}
						fmt.Println(c.WhiteUnderlineText("Transparent")+" balance", c.GreenText(qadenaCoin.Amount.String()+qadenaCoin.Denom))

						continue
					}
				}

				return nil
			}

			if argDecryptAs != "" {
				fmt.Println()
				fmt.Println("------------------- QADENA Wallet Decrypted Info --------------------")
				fmt.Println("Name", args[0])
				fmt.Println("WalletID", argWalletID)
				//				fmt.Println("PrivateKey", decryptAsPrivKeyHex)
				//				fmt.Println("PublicKey", decryptAsPubKey)

				fmt.Println("CredentialID", wallet.CredentialID)
				fmt.Print("Service Provider ID: ")
				for _, id := range wallet.ServiceProviderID {
					fmt.Print(id, " ")
				}
				fmt.Println()

				unprotoCreateWalletVShareBind := c.UnprotoizeVShareBindData(wallet.CreateWalletVShareBind)
				// decrypt the destination wallet id
				var vShareCreateWallet types.EncryptableCreateWallet

				err := c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoCreateWalletVShareBind, wallet.EncCreateWalletVShare, &vShareCreateWallet)
				if err != nil {
					fmt.Println("Wallet Type:  Can't decrypt", unprotoCreateWalletVShareBind.GetValidDecryptAsAddresses())
				} else {
					if vShareCreateWallet.DstEWalletID.WalletID == wallet.WalletID {
						fmt.Println("Wallet Type:  Primary")
					} else {
						fmt.Println("Wallet Type:  Ephemeral (linked to " + vShareCreateWallet.DstEWalletID.WalletID + ")")
					}
				}

				for _, coin := range allBalancesRes.Balances {
					if strings.Index(coin.Denom, "erc20") > -1 {
						continue
					}

					// check wether the token is the primary token "aqdn"
					if coin.Denom == types.AQadenaTokenDenom {

						if _, ok := wallet.WalletAmount[types.QadenaTokenDenom]; ok {
							displayWalletAmount(wallet.WalletAmount[types.QadenaTokenDenom], decryptAsPrivKeyHex, decryptAsPubKey)
						}

						// if there are queued wallet amounts
						if len(wallet.QueuedWalletAmount[types.QadenaTokenDenom].WalletAmounts) > 0 {
							fmt.Println(c.WhiteUnderlineText("*Queued*"))
							for _, queuedWalletAmount := range wallet.QueuedWalletAmount[types.QadenaTokenDenom].WalletAmounts {
								displayWalletAmount(queuedWalletAmount, decryptAsPrivKeyHex, decryptAsPubKey)
							}
						}

						if _, ok := wallet.WalletAmount[types.QadenaTokenDenom]; ok {
						} else {
							fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText("0"+types.QadenaTokenDenom))
						}

						qadenaCoin, err := sdk.ConvertDecCoin(sdk.NewDecCoinFromCoin(coin), types.QadenaTokenDenom)
						if err != nil {
							return err
						}
						fmt.Println(c.WhiteUnderlineText("Transparent")+" balance", c.GreenText(qadenaCoin.Amount.String()+qadenaCoin.Denom))

						continue
					}

					/*
							fmt.Println("")
							for i, d := range denomTracesRes.DenomTraces {
								// check if the coin is an IBC coin
								if strings.EqualFold(coin.Denom, d.IBCDenom()) {
									if _, ok := wallet.WalletAmount[coin.Denom]; ok {
										//var wa c.WalletAmount
										var ewa types.EncryptableWalletAmount
										//_, err = c.DecryptAndUnmarshal(transactionPrivKey, wallet.WalletAmount[coin.Denom].EncWalletAmountUserCredentialPubK, &wa)
										unprotoWalletAmountVShareBind := c.UnprotoizeVShareBindData(wallet.WalletAmount[coin.Denom].WalletAmountVShareBind)
										err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, unprotoWalletAmountVShareBind, wallet.WalletAmount[coin.Denom].EncWalletAmountVShare, &ewa)

										if err != nil {
											return err
										}

										if ewa.Note != "" {
											note = ewa.Note
										}

										decryptedAmount = c.UnprotoizeBInt(ewa.PedersenCommit.A)

										if decryptedAmount != nil {
											decryptedDenom = "a" + coin.Denom
											coin, err := sdk.ParseDecCoin(decryptedAmount.String() + decryptedDenom)
											if err != nil {
												return err
											}

											fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText(coin.Amount.String()+d.GetBaseDenom()), "[Encryption-"+c.TruncateText(hex.EncodeToString(wallet.WalletAmount[coin.Denom].EncWalletAmountVShare), 20)+"...]")
										}
									} else {
										fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText("0"+d.GetBaseDenom()))
									}

									coin, err := sdk.ParseDecCoin(coin.Amount.String() + "a" + coin.Denom)
									if err != nil {
										return err
									}

									fmt.Println(c.WhiteUnderlineText("Transparent")+" balance", c.GreenText(coin.Amount.String()+" "+d.GetBaseDenom()+"("+coin.Denom+")"))

									if note != "" {
										fmt.Println(c.WhiteUnderlineText("Note")+" ", c.GreenText(note))
									}

									break
								}

								// when the coin is a non-IBC coin (i.e. erc20 token, etc.)
								if i == len(denomTracesRes.DenomTraces)-1 {
									// check if there are other denoms available on chain
									denomMetadataParams := banktypes.QueryDenomMetadataRequest{Denom: coin.Denom}
									denomMetadataRes, err := queryBankClient.DenomMetadata(ctx, &denomMetadataParams)
									if err != nil {
										return err
									}

									// get the token symbol
									symbol := strings.Split(denomMetadataRes.Metadata.Symbol, "/")[0]

									if _, ok := wallet.WalletAmount[coin.Denom]; ok {
										//var wa c.WalletAmount
										var ewa types.EncryptableWalletAmount
										//_, err = c.DecryptAndUnmarshal(transactionPrivKey, wallet.WalletAmount[coin.Denom].EncWalletAmountUserCredentialPubK, &wa)
										err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.UnprotoizeVShareBindData(wallet.WalletAmount[coin.Denom].WalletAmountVShareBind), wallet.WalletAmount[coin.Denom].EncWalletAmountVShare, &ewa)
										if err != nil {
											return err
										}

										if ewa.Note != "" {
											note = ewa.Note
										}

										decryptedAmount = c.UnprotoizeBInt(ewa.PedersenCommit.A)

										if decryptedAmount != nil {
											decryptedDenom = "a" + coin.Denom
											coin, err := sdk.ParseDecCoin(decryptedAmount.String() + decryptedDenom)
											if err != nil {
												return err
											}

											// register display denom
											if err := sdk.RegisterDenom(coin.Denom, math.LegacyOneDec()); err != nil {
												panic(err)
											}

											// register base denom
											prec := int64(denomMetadataRes.Metadata.DenomUnits[1].Exponent)
											if err := sdk.RegisterDenom("a"+coin.Denom, math.LegacyNewDecWithPrec(1, prec)); err != nil {
												panic(err)
											}
											otherCoin, err := sdk.ConvertDecCoin(coin, coin.Denom)
											if err != nil {
												return err
											}

											fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText(otherCoin.Amount.String()+symbol), "[Encryption-"+c.TruncateText(hex.EncodeToString(wallet.WalletAmount[otherCoin.Denom].EncWalletAmountVShare), 20)+"...]")
										}
									} else {
										fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText("0"+symbol))
									}

									coin, err := sdk.ParseDecCoin(coin.Amount.String() + "a" + coin.Denom)
									if err != nil {
										return err
									}

									otherCoin, err := sdk.ConvertDecCoin(coin, coin.Denom)
									if err != nil {
										return err
									}

									fmt.Println(c.WhiteUnderlineText("Transparent")+" balance", c.GreenText(otherCoin.Amount.String()+symbol+"("+otherCoin.Denom+")"))

									if note != "" {
										fmt.Println(c.WhiteUnderlineText("Note")+" ", c.GreenText(note))
									}

									break
								}
							}
						}

						// check if there are other denoms available on chain
						denomsMetadataParams := banktypes.QueryDenomsMetadataRequest{Pagination: &query.PageRequest{}}
						denomsMetadataRes, err := queryBankClient.DenomsMetadata(ctx, &denomsMetadataParams)
						if err != nil {
							return err
						}

						additionalDenoms := denomsMetadataRes.Metadatas
						if len(additionalDenoms) > 0 {
							for _, metadata := range denomsMetadataRes.Metadatas {
								if metadata.Base != types.AQadenaTokenDenom {

									fmt.Println("")

									// get the denom for other native coins
									baseDenom := metadata.Base

									// get the token symbol
									symbol := strings.Split(metadata.Symbol, "/")[0]

									bankparams := banktypes.NewQueryBalanceRequest(addr, baseDenom)
									bankres, err := queryBankClient.Balance(ctx, bankparams)
									if err != nil {
										return err
									}
									err = clientCtx.PrintProto(bankres.Balance)
									if err != nil {
										return err
									}

									// register display denom
									if err := sdk.RegisterDenom(bankres.Balance.Denom, math.LegacyOneDec()); err != nil {
										panic(err)
									}

									// register base denom
									prec := int64(metadata.DenomUnits[1].Exponent)
									if err := sdk.RegisterDenom("a"+bankres.Balance.Denom, math.LegacyNewDecWithPrec(1, prec)); err != nil {
										panic(err)
									}

									note = ""

									// check whether the other native denom has already inside a wallet
									if _, ok := wallet.WalletAmount[baseDenom]; ok {
										//var wa c.WalletAmount
										var ewa types.EncryptableWalletAmount
										err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.UnprotoizeVShareBindData(wallet.WalletAmount[baseDenom].WalletAmountVShareBind), wallet.WalletAmount[baseDenom].EncWalletAmountVShare, &ewa)
										if err != nil {
											return err
										}

										decryptedAmount = c.UnprotoizeBInt(ewa.PedersenCommit.A)
										//							decryptedAmount = wa.PedersenCommit.A.String()

										if decryptedAmount != nil {
											coin, err := sdk.ParseDecCoin(decryptedAmount.String() + "a" + baseDenom)
											if err != nil {
												return err
											}

											if ewa.Note != "" {
												note = ewa.Note
											}

											otherNativeCoin, err := sdk.ConvertDecCoin(coin, baseDenom)
											if err != nil {
												return err
											}

											fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText(otherNativeCoin.Amount.String()+symbol), "[Encryption-"+c.TruncateText(hex.EncodeToString(wallet.WalletAmount[baseDenom].EncWalletAmountVShare), 20)+"...]")
										}
									} else {
										fmt.Println(c.WhiteUnderlineText("Encrypted")+" balance", c.GreenText("0"+symbol))
									}

									coin, err := sdk.ParseDecCoin(bankres.Balance.Amount.String() + "a" + baseDenom)
									if err != nil {
										return err
									}

									otherCoin, err := sdk.ConvertDecCoin(coin, baseDenom)
									if err != nil {
										return err
									}

									fmt.Println(c.WhiteUnderlineText("Transparent")+" balance", c.GreenText(otherCoin.Amount.String()+symbol+"("+otherCoin.Denom+")"))

									if note != "" {
										fmt.Println(c.WhiteUnderlineText("Note")+" ", c.GreenText(note))
									}
								}
							}
					*/
				}
				// decrypt validatedcredential
				if wallet.AcceptValidatedCredentialsVShareBind != nil && wallet.EncAcceptValidatedCredentialsVShare != nil && len(wallet.EncAcceptValidatedCredentialsVShare) > 0 {
					var vc types.EncryptableValidatedCredentials
					err = c.VShareBDecryptAndProtoUnmarshal(decryptAsPrivKeyHex, decryptAsPubKey, c.UnprotoizeVShareBindData(wallet.AcceptValidatedCredentialsVShareBind), wallet.EncAcceptValidatedCredentialsVShare, &vc)
					if err != nil {
						fmt.Println("Accept Validated Credentials: Can't decrypt", c.UnprotoizeVShareBindData(wallet.AcceptValidatedCredentialsVShareBind).GetValidDecryptAsAddresses())
					} else {
						fmt.Println("Validated Credentials:")
						fmt.Println(c.PrettyPrint(vc))
					}
				}
				fmt.Println("SenderOptions: ", wallet.SenderOptions)
			} else {
				fmt.Println("Wallet")
				fmt.Println(c.PrettyPrint(wallet))
				fmt.Println("All Balances")
				fmt.Println(c.PrettyPrint(allBalancesRes))
				//fmt.Println("Denom Traces")
				//fmt.Println(c.PrettyPrint(denomTracesRes))
			}

			return err
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().StringVar(&argMnemonic, "mnemonic", "", "Account mnemonic for debugging purposes")
	cmd.Flags().StringVar(&argDecryptAs, "decrypt-as", "", "Account to decrypt as")

	return cmd
}
