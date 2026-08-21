package cli

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	ethsecp256k1 "github.com/cosmos/evm/crypto/ethsecp256k1"
	"github.com/hashicorp/vault/shamir"
	"github.com/spf13/cobra"
)

// this actually goes into the enclave
func CmdShowRecoverKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-recover-key [recover-wallet-id]",
		Short: "shows a RecoverKey",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx := client.GetClientContextFromCmd(cmd)

			queryClient := types.NewQueryClient(clientCtx)

			argWalletID, _, tranPubKey, tranPrivKeyHex, err := c.GetAddress(clientCtx, args[0])
			if err != nil {
				return err
			}

			// get timestamp
			timestamp := time.Now().Unix()
			// sign the timestamp with the transaction private key
			tsBytes := []byte(strconv.FormatInt(timestamp, 10))
			privBytes, err := hex.DecodeString(tranPrivKeyHex)
			if err != nil {
				return fmt.Errorf("failed to decode tranPrivKeyHex: %w", err)
			}
			if len(privBytes) != 32 {
				return fmt.Errorf("unexpected private key length: got %d, want 32", len(privBytes))
			}
			// eth_secp256k1, NOT cosmos secp256k1 -- THE TWO HALVES MUST AGREE.
			//
			// The keeper verifies this signature with evmsecp256k1 (query_recover_key.go), which
			// keccak256-hashes the message; cosmos secp256k1 signs a SHA-256 digest and produces a
			// bare 64-byte [R||S].  Signing here with the wrong one produces a signature the chain
			// rejects as "invalid timestamp signature", and the caller sees no seed phrase released
			// rather than a signing error -- the failure surfaces a whole request later, on the
			// server, in a different process.
			//
			// This chain's keys ARE eth_secp256k1 (crypto/keyring/options.go), so the private key
			// bytes are the same 32 either way; only the hash and encoding differ.
			privKey := ethsecp256k1.PrivKey{Key: privBytes}
			sig, err := privKey.Sign(tsBytes)
			if err != nil {
				return fmt.Errorf("failed to sign timestamp: %w", err)
			}
			fmt.Println("timestamp", timestamp)
			fmt.Println("timestamp_signature_hex", hex.EncodeToString(sig))
			fmt.Println("timestamp_pubkey", tranPubKey)

			params := &types.QueryGetRecoverKeyRequest{
				WalletID:           argWalletID,
				Timestamp:          timestamp,
				TimestampSignature: sig,
			}

			res, err := queryClient.RecoverKey(context.Background(), params)
			if err != nil {
				return err
			}

			recoverKey := res.GetRecoverKey()

			fmt.Println("recoverKey", c.PrettyPrint(recoverKey))

			_, _, credPubKey, credPrivKeyHex, err := c.GetAddress(clientCtx, args[0]+"-credential")
			if err != nil {
				return err
			}
			credPrivateKey := credPrivKeyHex + "_privkhex:" + credPubKey + "_privk"

			if len(recoverKey.RecoverShare) == 1 {
				var seedPhrase string
				_, err := c.BDecryptAndUnmarshal(credPrivateKey, recoverKey.RecoverShare[0].EncWalletPubKShare, &seedPhrase)
				if err != nil {
					fmt.Println("couldn't decrypt " + err.Error())
					return err
				}
				fmt.Println("seed phrase", seedPhrase)
			} else {
				// assemble!
				var byteShares [][]byte
				var shareString string
				for _, rShare := range recoverKey.RecoverShare {
					_, err := c.BDecryptAndUnmarshal(credPrivateKey, rShare.EncWalletPubKShare, &shareString)
					if err != nil {
						fmt.Println("couldn't decrypt " + err.Error())
						return err
					}
					fmt.Println("shareString base64", shareString)
					shareBytes, err := base64.StdEncoding.DecodeString(shareString)
					if err != nil {
						fmt.Println("couldn't decode " + err.Error())
						return err
					}
					byteShares = append(byteShares, shareBytes)
				}
				seedPhrase, err := shamir.Combine(byteShares)
				if err != nil {
					fmt.Println("error from shamir", err.Error())
					return err
				}

				fmt.Println("seed phrase:", string(seedPhrase))
			}

			return nil
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}
