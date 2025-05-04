package main

import (
	"fmt"
	"os"

	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"

	"qadena_v3/app"
	"qadena_v3/cmd/qadenad/cmd"
)

func main() {
	rootCmd := cmd.NewRootCmd()

	rootCmd.AddCommand(NewEnclaveCmd())
	if err := svrcmd.Execute(rootCmd, "", app.DefaultNodeHome); err != nil {
		fmt.Fprintln(rootCmd.OutOrStderr(), err)
		os.Exit(1)
	}
}
