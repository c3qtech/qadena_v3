// msgencode reads a single Cosmos SDK message as JSON on stdin (the same "@type"-tagged shape a
// gov proposal uses) and writes its protobuf encoding to stdout as base64.
//
// WHY THIS EXISTS.  A cw3-flex-multisig proposal carries its payload as a CosmosMsg::Any (called
// Stargate before CosmWasm 2.x), whose `value` field is the RAW PROTOBUF BYTES of the message.
// Nothing in the qadenad CLI emits those: `tx ... --generate-only` produces a whole unsigned tx,
// and `tx encode` base64s a whole TxRaw.  Encoding by hand in shell or Python would mean
// reimplementing protobuf field ordering for every message type, which is exactly the kind of
// thing that silently produces a well-formed-but-wrong blob.
//
// So this reuses the SDK's own codec: whatever the chain would accept, this produces.
//
// Usage:
//   echo '{"@type":"/cosmos.vesting.v1beta1.MsgCreatePeriodicVestingAccount", ...}' | msgencode
package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func main() {
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	authtypes.RegisterInterfaces(registry)
	vestingtypes.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	stakingtypes.RegisterInterfaces(registry)
	distrtypes.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)

	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		os.Exit(1)
	}

	var msg sdk.Msg
	if err := cdc.UnmarshalInterfaceJSON(in, &msg); err != nil {
		fmt.Fprintln(os.Stderr, "decode json:", err)
		os.Exit(1)
	}

	bz, err := cdc.Marshal(msg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal proto:", err)
		os.Exit(1)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(bz))
}
