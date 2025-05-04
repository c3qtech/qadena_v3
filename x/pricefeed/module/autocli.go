package pricefeed

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	modulev1 "qadena/api/qadena/pricefeed"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service: modulev1.Query_ServiceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				/*
					{
						RpcMethod: "PostedPriceAll",
						Use:       "list-posted-price",
						Short:     "List all PostedPrice",
					},
					{
						RpcMethod:      "PostedPrice",
						Use:            "show-posted-price [id]",
						Short:          "Shows a PostedPrice",
						PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "marketId"}, {ProtoField: "oracleAddress"}},
					},
				*/
				{
					RpcMethod:      "Price",
					Use:            "price [market-id]",
					Short:          "Query Price",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "marketId"}},
				},

				{
					RpcMethod:      "Prices",
					Use:            "prices [market-id]",
					Short:          "Query Prices",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "marketId"}},
				},

				{
					RpcMethod:      "RawPrices",
					Use:            "raw-prices [market-id]",
					Short:          "Query RawPrices",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "marketId"}},
				},

				{
					RpcMethod:      "Oracles",
					Use:            "oracles [market-id]",
					Short:          "Query Oracles",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "marketId"}},
				},

				{
					RpcMethod:      "Markets",
					Use:            "markets",
					Short:          "Query Markets",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{},
				},

				// this line is used by ignite scaffolding # autocli/query
			},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Msg_ServiceDesc.ServiceName,
			EnhanceCustomCommand: true, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "UpdateParams",
					Skip:      true, // skipped because authority gated
				},
				{
					RpcMethod:      "PostPrice",
					Use:            "post-price [market-id] [price] [expiry]",
					Short:          "Send a PostPrice tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "marketId"}, {ProtoField: "price"}, {ProtoField: "expiry"}},
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
