package qadena

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	modulev1 "qadena/api/qadena/qadena"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Query_ServiceDesc.ServiceName,
			EnhanceCustomCommand: false, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "CredentialAll",
					Use:       "list-credential",
					Short:     "List all Credential",
				},
				{
					RpcMethod:      "Credential",
					Use:            "show-credential [id]",
					Short:          "Shows a Credential",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "credentialID"}, {ProtoField: "credentialType"}},
				},
				{
					RpcMethod: "WalletAll",
					Use:       "list-wallet",
					Short:     "List all Wallet",
				},
				{
					RpcMethod:      "Wallet",
					Use:            "show-wallet [id]",
					Short:          "Shows a Wallet",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "walletID"}},
				},
				{
					RpcMethod:      "FindCredential",
					Use:            "find-credential [credential-p-c] [credential-type] [ss-interval-pub-k-i-d] [enc-user-credential-pub-k-s-s-interval-pub-k] [enc-proof-p-c-s-s-interval-pub-k] [enc-check-p-c-s-s-interval-pub-k]",
					Short:          "Query FindCredential",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "credentialPC"}, {ProtoField: "credentialType"}, {ProtoField: "sSIntervalPubKID"}, {ProtoField: "encUserCredentialPubKSSIntervalPubK"}, {ProtoField: "encProofPCSSIntervalPubK"}, {ProtoField: "encCheckPCSSIntervalPubK"}},
				},
				{
					RpcMethod:      "IntervalPublicKeyID",
					Use:            "show-interval-public-key-id [id]",
					Short:          "Shows a Interval_Public_Key_ID",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "nodeID"}, {ProtoField: "nodeType"}},
				},
				{
					RpcMethod: "SuspiciousTransactionAll",
					Use:       "list-suspicious-transaction",
					Short:     "List all SuspiciousTransaction",
				},
				{
					RpcMethod:      "SuspiciousTransaction",
					Use:            "show-suspicious-transaction [id]",
					Short:          "Shows a SuspiciousTransaction by id",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "id"}},
				},
				{
					RpcMethod: "RecoverKeyAll",
					Use:       "list-recover-key",
					Short:     "List all RecoverKey",
				},
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				{
					RpcMethod:      "PublicKey",
					Use:            "show-public-key [id]",
					Short:          "Shows a Public_Key",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "pubKID"}, {ProtoField: "pubKType"}},
				},
				{
					RpcMethod: "PublicKeyAll",
					Use:       "list-public-key",
					Short:     "List all Public_Key",
				},
				{
					RpcMethod: "IntervalPublicKeyIDAll",
					Use:       "list-interval-public-key-id",
					Short:     "List all Interval_Public_Key_ID",
				},
				{
					RpcMethod: "PioneerJarAll",
					Use:       "list-pioneer-jar",
					Short:     "List all Pioneer_Jar",
				},
				{
					RpcMethod:      "PioneerJar",
					Use:            "show-pioneer-jar [id]",
					Short:          "Shows a Pioneer_Jar",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "pioneerID"}},
				},
				{
					RpcMethod: "JarRegulatorAll",
					Use:       "list-jar-regulator",
					Short:     "List all Jar_Regulator",
				},
				{
					RpcMethod:      "JarRegulator",
					Use:            "show-jar-regulator [id]",
					Short:          "Shows a Jar_Regulator",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "jarID"}},
				},
				{
					RpcMethod: "ProtectKeyAll",
					Use:       "list-protect-key",
					Short:     "List all ProtectKey",
				},
				{
					RpcMethod:      "ProtectKey",
					Use:            "show-protect-key [id]",
					Short:          "Shows a ProtectKey",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "walletID"}},
				},
				{
					RpcMethod:      "RecoverKey",
					Use:            "show-recover-key [id]",
					Short:          "Shows a RecoverKey",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "walletID"}},
				},
				{
					RpcMethod:      "Treasury",
					Use:            "treasury",
					Short:          "Query Treasury",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{},
				},
				{
					RpcMethod:      "Account",
					Use:            "account [name]",
					Short:          "Query Account",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "name"}},
				},
				{
					RpcMethod:      "Incentives",
					Use:            "incentives",
					Short:          "Query Incentives",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{},
				},
				{
					RpcMethod:      "SyncEnclave",
					Use:            "sync-enclave [remote-report] [enclave-pub-k]",
					Short:          "Query SyncEnclave",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "remoteReport"}, {ProtoField: "enclavePubK"}},
				},

				{
					RpcMethod:      "EnclaveSecretShare",
					Use:            "enclave-secret-share [remote-report] [enclave-pub-k] [pub-k-i-d]",
					Short:          "Query EnclaveSecretShare",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "remoteReport"}, {ProtoField: "enclavePubK"}, {ProtoField: "pubKID"}},
				},
				{
					RpcMethod:      "EnclaveRecoverKeyShare",
					Use:            "enclave-recover-key-share [remote-report] [new-wallet-i-d] [share-wallet-i-d] [enc-share-wallet-pub-k]",
					Short:          "Query EnclaveRecoverKeyShare",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "remoteReport"}, {ProtoField: "newWalletID"}, {ProtoField: "shareWalletID"}, {ProtoField: "encShareWalletPubK"}},
				},
				{
					RpcMethod: "EnclaveIdentityAll",
					Use:       "list-enclave-identity",
					Short:     "List all Enclave_Identity",
				},
				{
					RpcMethod:      "EnclaveIdentity",
					Use:            "show-enclave-identity [id]",
					Short:          "Shows a Enclave_Identity",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "uniqueID"}},
				},
				// this line is used by ignite scaffolding # autocli/query
			},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Msg_ServiceDesc.ServiceName,
			EnhanceCustomCommand: false, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "UpdateParams",
					Skip:      true, // skipped because authority gated
				},
				{
					RpcMethod:      "CreateSuspiciousTransaction",
					Use:            "create-suspicious-transaction [jarID] [regulatorPubKID] [reason] [time] [encSourcePersonalInfoRegulatorPubK] [encDestinationPersonalInfoRegulatorPubK] [encEAmountRegulatorPubK] [encOptInReasonRegulatorPubK]",
					Short:          "Create SuspiciousTransaction",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "jarID"}, {ProtoField: "regulatorPubKID"}, {ProtoField: "reason"}, {ProtoField: "time"}, {ProtoField: "encSourcePersonalInfoRegulatorPubK"}, {ProtoField: "encDestinationPersonalInfoRegulatorPubK"}, {ProtoField: "encEAmountRegulatorPubK"}, {ProtoField: "encOptInReasonRegulatorPubK"}},
				},
				{
					RpcMethod:      "UpdateSuspiciousTransaction",
					Use:            "update-suspicious-transaction [id] [jarID] [regulatorPubKID] [reason] [time] [encSourcePersonalInfoRegulatorPubK] [encDestinationPersonalInfoRegulatorPubK] [encEAmountRegulatorPubK] [encOptInReasonRegulatorPubK]",
					Short:          "Update SuspiciousTransaction",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "id"}, {ProtoField: "jarID"}, {ProtoField: "regulatorPubKID"}, {ProtoField: "reason"}, {ProtoField: "time"}, {ProtoField: "encSourcePersonalInfoRegulatorPubK"}, {ProtoField: "encDestinationPersonalInfoRegulatorPubK"}, {ProtoField: "encEAmountRegulatorPubK"}, {ProtoField: "encOptInReasonRegulatorPubK"}},
				},
				{
					RpcMethod:      "DeleteSuspiciousTransaction",
					Use:            "delete-suspicious-transaction [id]",
					Short:          "Delete SuspiciousTransaction",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "id"}},
				},
				{
					RpcMethod:      "AddPublicKey",
					Use:            "add-public-key [pub-k] [pub-k-type]",
					Short:          "Send a Add_Public_Key tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "pubK"}, {ProtoField: "pubKType"}},
				},
				{
					RpcMethod:      "UpdateIntervalPublicKeyID",
					Use:            "update-interval-public-key-i-d [node-i-d] [node-type]",
					Short:          "Send a Update_Interval_Public_Key_I_D tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "nodeID"}, {ProtoField: "nodeType"}},
				},
				{
					RpcMethod:      "UpdatePioneerJar",
					Use:            "update-pioneer-jar [pioneer-i-d] [jar-i-d]",
					Short:          "Send a UpdatePioneerJar tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "pioneerID"}, {ProtoField: "jarID"}},
				},
				{
					RpcMethod:      "UpdateJarRegulator",
					Use:            "update-jar-regulator [jar-i-d] [regulator-i-d]",
					Short:          "Send a UpdateJarRegulator tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "jarID"}, {ProtoField: "regulatorID"}},
				},
				{
					RpcMethod:      "CreateWallet",
					Use:            "create-wallet [home-pioneer-i-d] [jar-i-d] [jar-interval-pub-k-i-d] [ss-interval-pub-k-i-d] [enc-create-wallet-v-share] [v-share-bind] [accept-password-p-c] [enc-s-s-accept-validated-credentials] [wallet-amount-pedersen-commit] [enc-wallet-amount-user-credential-pub-k] [transparent-wallet-amount-p-c] [accept-credential-type]",
					Short:          "Send a CreateWallet tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "homePioneerID"}, {ProtoField: "jarID"}, {ProtoField: "jarIntervalPubKID"}, {ProtoField: "sSIntervalPubKID"}, {ProtoField: "encCreateWalletVShare"}, {ProtoField: "vShareBind"}, {ProtoField: "acceptPasswordPC"}, {ProtoField: "encSSAcceptValidatedCredentials"}, {ProtoField: "walletAmountPedersenCommit"}, {ProtoField: "encWalletAmountUserCredentialPubK"}, {ProtoField: "transparentWalletAmountPC"}, {ProtoField: "acceptCredentialType"}},
				},
				{
					RpcMethod:      "TransferFunds",
					Use:            "transfer-funds [transaction-i-d] [jar-i-d] [jar-interval-pub-k-i-d] [ss-interval-pub-k-i-d] [source-p-c] [hidden-transfer-p-c] [new-source-p-c] [enc-new-source-wallet-amount] [enc-new-destination-wallet-amount] [enc-anon-transfer-funds] [transparent-amount] [token-denom] [hidden-transfer-p-c-proof] [new-source-p-c-proof] [enc-transfer-funds-v-share] [v-share-bind]",
					Short:          "Send a TransferFunds tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "transactionID"}, {ProtoField: "jarID"}, {ProtoField: "jarIntervalPubKID"}, {ProtoField: "sSIntervalPubKID"}, {ProtoField: "sourcePC"}, {ProtoField: "hiddenTransferPC"}, {ProtoField: "newSourcePC"}, {ProtoField: "encNewSourceWalletAmount"}, {ProtoField: "encNewDestinationWalletAmount"}, {ProtoField: "encAnonTransferFunds"}, {ProtoField: "transparentAmount"}, {ProtoField: "tokenDenom"}, {ProtoField: "hiddenTransferPCProof"}, {ProtoField: "newSourcePCProof"}, {ProtoField: "encTransferFundsVShare"}, {ProtoField: "vShareBind"}},
				},
				{
					RpcMethod:      "ReceiveFunds",
					Use:            "receive-funds [transaction-i-d] [jar-i-d] [jar-interval-pub-k-i-d] [ss-interval-pub-k-i-d] [destination-p-c] [hidden-transfer-p-c] [new-destination-p-c] [enc-new-destination-wallet-amount] [enc-anon-receive-funds] [transparent-amount] [token-denom] [hidden-transfer-p-c-proof] [new-destination-p-c-proof] [enc-receive-funds-v-share] [v-share-bind]",
					Short:          "Send a ReceiveFunds tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "transactionID"}, {ProtoField: "jarID"}, {ProtoField: "jarIntervalPubKID"}, {ProtoField: "sSIntervalPubKID"}, {ProtoField: "destinationPC"}, {ProtoField: "hiddenTransferPC"}, {ProtoField: "newDestinationPC"}, {ProtoField: "encNewDestinationWalletAmount"}, {ProtoField: "encAnonReceiveFunds"}, {ProtoField: "transparentAmount"}, {ProtoField: "tokenDenom"}, {ProtoField: "hiddenTransferPCProof"}, {ProtoField: "newDestinationPCProof"}, {ProtoField: "encReceiveFundsVShare"}, {ProtoField: "vShareBind"}},
				},
				{
					RpcMethod:      "DeploySmartContract",
					Use:            "deploy-smart-contract [src-wallet-i-d] [smart-contract-hex]",
					Short:          "Send a Deploy_Smart_Contract tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "srcWalletID"}, {ProtoField: "smartContractHex"}},
				},
				{
					RpcMethod:      "ExecuteSmartContract",
					Use:            "execute-smart-contract [src-wallet-i-d] [smart-contract-hex]",
					Short:          "Send a Execute_Smart_Contract tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "srcWalletID"}, {ProtoField: "smartContractHex"}},
				},
				{
					RpcMethod:      "CreateCredential",
					Use:            "create-credential [credential-i-d] [credential-type] [credential-pedersen-commit] [ss-interval-pub-k-i-d] [enc-credential-info-v-share] [v-share-bind] [enc-credential-hash-s-s-interval-pub-k] [find-credential-pedersen-commit] [e-k-y-c-app-wallet-i-d] [reference-credential-i-d]",
					Short:          "Send a CreateCredential tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "credentialID"}, {ProtoField: "credentialType"}, {ProtoField: "credentialPedersenCommit"}, {ProtoField: "sSIntervalPubKID"}, {ProtoField: "encCredentialInfoVShare"}, {ProtoField: "vShareBind"}, {ProtoField: "encCredentialHashSSIntervalPubK"}, {ProtoField: "findCredentialPedersenCommit"}, {ProtoField: "eKYCAppWalletID"}, {ProtoField: "referenceCredentialID"}},
				},
				{
					RpcMethod:      "PioneerAddPublicKey",
					Use:            "pioneer-add-public-key [pub-k-i-d] [pub-k] [pub-k-type] [shares]",
					Short:          "Send a Pioneer_Add_Public_Key tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "pubKID"}, {ProtoField: "pubK"}, {ProtoField: "pubKType"}, {ProtoField: "shares"}},
				},
				{
					RpcMethod:      "PioneerUpdateIntervalPublicKeyID",
					Use:            "pioneer-update-interval-public-key-i-d [pub-k-i-d] [node-i-d] [node-type] [external-i-p-address]",
					Short:          "Send a Pioneer_Update_Interval_Public_Key_I_D tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "pubKID"}, {ProtoField: "nodeID"}, {ProtoField: "nodeType"}, {ProtoField: "externalIPAddress"}},
				},
				{
					RpcMethod:      "PioneerEnclaveExchange",
					Use:            "pioneer-enclave-exchange [msg-type] [msg]",
					Short:          "Send a Pioneer_Enclave_Exchange tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "msgType"}, {ProtoField: "msg"}},
				},
				{
					RpcMethod:      "PioneerBroadcastSecretSharePrivateKey",
					Use:            "pioneer-broadcast-secret-share-private-key [private-keys] [remote-report]",
					Short:          "Send a Pioneer_Broadcast_Secret_Share_Private_Key tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "privateKeys"}, {ProtoField: "remoteReport"}},
				},
				{
					RpcMethod:      "ProtectPrivateKey",
					Use:            "protect-private-key [threshold] [recover-share]",
					Short:          "Send a ProtectPrivateKey tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "threshold"}, {ProtoField: "recoverShare"}},
				},
				{
					RpcMethod:      "SignRecoverPrivateKey",
					Use:            "sign-recover-private-key [ss-interval-pub-k-i-d] [enc-destination-e-wallet-i-d-s-s-interval-pub-k-i-d] [recover-share]",
					Short:          "Send a SignRecoverPrivateKey tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "sSIntervalPubKID"}, {ProtoField: "encDestinationEWalletIDSSIntervalPubKID"}, {ProtoField: "recoverShare"}},
				},
				{
					RpcMethod:      "ClaimCredential",
					Use:            "claim-credential [credential-i-d] [credential-type] [recover-key] [ss-interval-pub-k-i-d] [enc-claim-credential-extra-parms-s-s-interval-pub-k]",
					Short:          "Send a ClaimCredential tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "credentialID"}, {ProtoField: "credentialType"}, {ProtoField: "recoverKey"}, {ProtoField: "sSIntervalPubKID"}, {ProtoField: "encClaimCredentialExtraParmsSSIntervalPubK"}},
				},
				{
					RpcMethod:      "CreateBulkCredentials",
					Use:            "create-bulk-credentials [credential-type] [ss-interval-pub-k-i-d] [v-share-bind] [e-k-y-c-app-wallet-i-d] [bulk-credentials]",
					Short:          "Send a CreateBulkCredentials tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "credentialType"}, {ProtoField: "sSIntervalPubKID"}, {ProtoField: "vShareBind"}, {ProtoField: "eKYCAppWalletID"}, {ProtoField: "bulkCredentials"}},
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
