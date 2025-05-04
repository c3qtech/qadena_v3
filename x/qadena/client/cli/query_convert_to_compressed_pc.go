package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"encoding/hex"
	"math/big"
	c "qadena/x/qadena/common"
)

func CmdConvertToCompressedPC() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert-to-compressed-pc [amount] [blinding-factor]",
		Args:  cobra.ExactArgs(2),
		Short: "converts a CompressedPC Hex Format",
		RunE: func(cmd *cobra.Command, args []string) error {
			c.Debug = false
			amount, success := big.NewInt(0).SetString(args[0], 10)

			if !success {
				return fmt.Errorf("invalid amount: %s", args[0])
			}

			bf, success := big.NewInt(0).SetString(args[1], 10)

			if !success {
				return fmt.Errorf("invalid blinding factor: %s", args[0])
			}

			pc := c.NewPedersenCommit(amount, bf)

			// protoize
			protoBPedersenCommit := c.ProtoizeBPedersenCommit(pc)

			// hex encode the protoBPedersenCommit.C
			hexCompressed := hex.EncodeToString(protoBPedersenCommit.C.Compressed)
			fmt.Print(hexCompressed)

			return nil
		},
	}

	return cmd
}
