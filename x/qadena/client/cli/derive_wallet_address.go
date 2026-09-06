package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

	"github.com/cosmos/go-bip39"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// CmdDeriveWalletAddress prints the address a mnemonic will produce at a given ephemeral index,
// WITHOUT a chain, a keyring, or any state.
//
// WHY THIS EXISTS.  The foundation can pre-grant a wallet's fee allowance before the wallet is
// created -- a grant is keyed on the grantee ADDRESS, and addresses are a pure function of the
// mnemonic.  That removes the last reason the foundation sponsor's private key had to sit in the
// keyring that runs create-wallet.  But pre-granting is only sound if the address the operator
// derives is EXACTLY the one create-wallet will later derive.  Shelling out to
// `keys add --dry-run --index i` happens to match today only because TransactionWalletType == 0
// coincides with the standard account field and the BIP39 passphrase is empty -- an equivalence
// maintained by nothing.  This command calls the same GetEphAccountAddress that create-wallet
// itself uses (tx_create_wallet.go:208), so the two agree by construction, not by coincidence.
//
// OFFLINE ON PURPOSE.  The mnemonic arrives on STDIN, never as an argument (arguments land in
// shell history and `ps`), and nothing here dials a node: a mnemonic must not travel to wherever
// --node points.
//
// REGISTERED UNDER `debug`, beside `debug addr`: that family is cosmos's established home for
// offline conversion utilities -- no chain, no fees, no keys -- and this is the same species one
// level up (mnemonic -> address at an HD index).  `tx` would imply a broadcast and `query` a node
// round-trip; both would say something false.  Only keyring flags are registered: the keyring
// supplies the signing ALGORITHM (eth_secp256k1) and nothing else -- no key is read or written.
func CmdDeriveWalletAddress() *cobra.Command {
	var argCredential bool
	var argCount uint32

	cmd := &cobra.Command{
		Use:   "derive-wallet-address [eph-account-index]",
		Short: "Derive the address a mnemonic (on stdin) yields at an ephemeral index; offline",
		Long: `Reads a mnemonic from stdin and prints the address create-wallet will derive for it.

Index 0 is the main wallet; 1..N are the --eph-account-index wallets.  --count N prints
indexes 0..N in one call ("index address" per line).  Uses the SAME derivation as
create-wallet (GetEphAccountAddress), so the output is what the chain will see -- suitable
for the foundation to pre-grant fee allowances against.

    echo "$mnemonic" | qadenad debug derive-wallet-address 3
    echo "$mnemonic" | qadenad debug derive-wallet-address --count 30`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := bufio.NewReader(os.Stdin)
			mnemonic, err := reader.ReadString('\n')
			if err != nil && mnemonic == "" {
				return fmt.Errorf("no mnemonic on stdin: %w", err)
			}
			mnemonic = strings.TrimSpace(mnemonic)
			// A wrong mnemonic derives a perfectly valid-looking address that nothing will ever
			// control.  A pre-grant against it burns the foundation's transaction and strands the
			// allowance, and the mistake surfaces only when create-wallet derives something else.
			if !bip39.IsMnemonicValid(mnemonic) {
				return fmt.Errorf("stdin is not a valid BIP39 mnemonic (%d words)",
					len(strings.Fields(mnemonic)))
			}

			accountType := types.TransactionWalletType
			if argCredential {
				accountType = types.CredentialWalletType
			}

			// The keyring is consulted ONLY for the signing algorithm (eth_secp256k1 on this
			// chain); no key is read or written.
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			algo, err := c.GetAlgo(clientCtx.Keyring)
			if err != nil {
				return err
			}

			indexes := []uint32{0}
			if len(args) == 1 {
				var idx uint32
				if _, err := fmt.Sscanf(args[0], "%d", &idx); err != nil {
					return fmt.Errorf("eph-account-index %q is not a number", args[0])
				}
				indexes = []uint32{idx}
			} else if argCount > 0 {
				indexes = indexes[:0]
				for i := uint32(0); i <= argCount; i++ {
					indexes = append(indexes, i)
				}
			}

			for _, i := range indexes {
				addr, err := c.GetEphAccountAddress(mnemonic, c.GetBip39PassPhrase(), accountType, i, algo)
				if err != nil {
					return err
				}
				if len(indexes) == 1 {
					fmt.Println(addr.String())
				} else {
					fmt.Printf("%d %s\n", i, addr.String())
				}
			}
			return nil
		},
	}

	flags.AddKeyringFlags(cmd.Flags())
	cmd.Flags().BoolVar(&argCredential, "credential", false, "derive the credential-wallet address instead of the transaction one")
	cmd.Flags().Uint32Var(&argCount, "count", 0, "print indexes 0..count, one per line")
	return cmd
}
