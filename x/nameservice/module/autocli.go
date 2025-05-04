package nameservice

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	modulev1 "qadena/api/qadena/nameservice"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Query_ServiceDesc.ServiceName,
			EnhanceCustomCommand: true, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				{
					RpcMethod: "NameBindingAll",
					Use:       "list-name-binding",
					Short:     "List all NameBinding",
				},
				{
					RpcMethod:      "NameBinding",
					Use:            "show-name-binding [id]",
					Short:          "Shows a NameBinding",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "credential"}, {ProtoField: "credentialType"}},
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
					RpcMethod:      "BindCredential",
					Use:            "bind-credential [credential-type] [credential-info] [credential-pedersen-commit]",
					Short:          "Send a BindCredential tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "credentialType"}, {ProtoField: "credentialInfo"}, {ProtoField: "credentialPedersenCommit"}},
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
