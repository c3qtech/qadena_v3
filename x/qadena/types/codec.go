package types

import (
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	// this line is used by starport scaffolding # 1
)

func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgCreateSuspiciousTransaction{},
		&MsgUpdateSuspiciousTransaction{},
		&MsgDeleteSuspiciousTransaction{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgAddPublicKey{},
	)
	/*
		registry.RegisterImplementations((*sdk.Msg)(nil),
			&MsgUpdateIntervalPublicKeyID{},
		)
	*/
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgPioneerUpdatePioneerJar{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgPioneerUpdateJarRegulator{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgCreateWallet{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgTransferFunds{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgReceiveFunds{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgDeploySmartContract{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgExecuteSmartContract{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgCreateCredential{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgPioneerAddPublicKey{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgPioneerUpdateIntervalPublicKeyID{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgPioneerEnclaveExchange{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgPioneerBroadcastSecretSharePrivateKey{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgProtectPrivateKey{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgSignRecoverPrivateKey{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgClaimCredential{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgCreateBulkCredentials{},
	)
	// this line is used by starport scaffolding # 3

	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgUpdateParams{},
	)
	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}
