package dsvs

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	modulev1 "github.com/c3qtech/qadena_v3/api/qadena/dsvs"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Query_ServiceDesc.ServiceName,
			EnhanceCustomCommand: true,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				{
					RpcMethod: "DocumentHashAll",
					Use:       "list-document-hash",
					Short:     "List all DocumentHash",
				},
				{
					RpcMethod:      "DocumentHash",
					Use:            "show-document-hash [id]",
					Short:          "Shows a DocumentHash",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "hash"}},
				},
				{
					RpcMethod: "DocumentAll",
					Use:       "list-document",
					Short:     "List all Document",
				},
				{
					RpcMethod:      "Document",
					Use:            "show-document [id]",
					Short:          "Shows a Document",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "documentID"}},
				},
				{
					RpcMethod: "AuthorizedSignatoryAll",
					Use:       "list-authorized-signatory",
					Short:     "List all Authorized_Signatory",
				},
				{
					RpcMethod:      "AuthorizedSignatory",
					Use:            "show-authorized-signatory [id]",
					Short:          "Shows a Authorized_Signatory",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "walletID"}},
				},
				// this line is used by ignite scaffolding # autocli/query
			},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Msg_ServiceDesc.ServiceName,
			EnhanceCustomCommand: false,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "UpdateParams",
					Skip:      true, // skipped because authority gated
				},
				{
					RpcMethod:      "CreateDocument",
					Use:            "create-document [document-type] [company-name] [required-signatory] [hash]",
					Short:          "Send a Create_Document tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "documentType"}, {ProtoField: "companyName"}, {ProtoField: "requiredSignatory"}, {ProtoField: "hash"}},
				},
				{
					RpcMethod:      "SignDocument",
					Use:            "sign-document [completed-signatory] [current-hash] [hash]",
					Short:          "Send a Sign_Document tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "completedSignatory"}, {ProtoField: "currentHash"}, {ProtoField: "hash"}},
				},
				{
					RpcMethod:      "RegisterAuthorizedSignatory",
					Use:            "register-authorized-signatory [v-share-authorized-signatory]",
					Short:          "Send a Register_Authorized_Signatory tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "vShareAuthorizedSignatory"}},
				},
				{
					RpcMethod:      "RemoveDocument",
					Use:            "remove-document [document-i-d]",
					Short:          "Send a Remove_Document tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "documentID"}},
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
