package keeper

import (
	"fmt"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"cosmossdk.io/core/header"
	"github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"
)

type (
	Keeper struct {
		cdc          codec.BinaryCodec
		storeService store.KVStoreService
		logger       log.Logger

		// the address capable of executing a MsgUpdateParams message. Typically, this
		// should be the x/gov module account.
		authority string

		headerService header.Service

		bankKeeper   types.BankKeeper
		qadenaKeeper types.QadenaKeeper
	}
)

func NewKeeper(
	cdc codec.BinaryCodec,
	storeService store.KVStoreService,
	logger log.Logger,
	authority string,

	bankKeeper types.BankKeeper,
	qadenaKeeper types.QadenaKeeper,
	headerService header.Service,

) Keeper {
	if _, err := sdk.AccAddressFromBech32(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address: %s", authority))
	}

	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		authority:    authority,
		logger:       logger,

		bankKeeper:    bankKeeper,
		qadenaKeeper:  qadenaKeeper,
		headerService: headerService,
	}
}

// GetAuthority returns the module's authority.
func (k Keeper) GetAuthority() string {
	return k.authority
}

// Logger returns a module-specific logger.
func (k Keeper) Logger() log.Logger {
	return k.logger.With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

// common funcs
// called from various DSVS MsgServer
// This was a line-for-line copy of the qadena keeper's lookup.  It now delegates, so the rotation
// grace period is defined once rather than in two places that could drift apart -- and drifting
// apart here means dsvs and qadena disagreeing about whether a transaction is valid, which is a
// consensus split, not a style problem.
//
// The error is translated rather than passed through: qadena and dsvs each register their own
// ErrPubKIDNotExists, and leaking qadena's would change the codespace on every dsvs failure that
// goes through here.
func DSVSMsgServerGetIntervalPublicKeyWithPrevious(ctx sdk.Context, qadenaKeeper types.QadenaKeeper, intervalNodeID string, intervalNodeType string) (pubKID string, pubK string, previousPubK string, serviceProviderType string, err error) {
	pubKID, pubK, previousPubK, serviceProviderType, err = qadenaKeeper.GetIntervalPublicKeyWithPrevious(ctx, intervalNodeID, intervalNodeType)
	if err != nil {
		err = types.ErrPubKIDNotExists
	}
	return
}

func DSVSMsgServerGetJarForPioneer(ctx sdk.Context, qadenaKeeper types.QadenaKeeper, pioneerID string) (jarID string, err error) {
	// find the interval ss pubk
	pioneerJar, found := qadenaKeeper.GetPioneerJar(ctx, pioneerID)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	jarID = pioneerJar.GetJarID()
	return
}

func DSVSMsgServerAppendRequiredChainCCPubK(ctx sdk.Context, ccPubK []c.VSharePubKInfo, qadenaKeeper types.QadenaKeeper, pioneerID string, excludeSSIntervalPubK bool) ([]c.VSharePubKInfo, error) {
	if excludeSSIntervalPubK && pioneerID == "" {
		c.ContextError(ctx, "Logic error")
		return nil, fmt.Errorf("Logic error")
	}
	if !excludeSSIntervalPubK {
		// AltPubK carries the key this one replaced, so a document bound moments before a rotation
		// is still accepted.  See common.VSharePubKInfo.
		ssIntervalPubKID, ssIntervalPubK, ssPreviousPubK, _, err := DSVSMsgServerGetIntervalPublicKeyWithPrevious(ctx, qadenaKeeper, qadenatypes.SSNodeID, qadenatypes.SSNodeType)

		if err != nil {
			c.ContextError(ctx, "Couldn't get interval public key")
			return nil, err
		}

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     ssIntervalPubK,
			AltPubK:  ssPreviousPubK,
			NodeID:   qadenatypes.SSNodeID,
			NodeType: qadenatypes.SSNodeType,
		})

		c.ContextDebug(ctx, "ssIntervalPubKID", "id", ssIntervalPubKID, "pubk", ssIntervalPubK)
	}

	if pioneerID != "" {
		jarID, err := DSVSMsgServerGetJarForPioneer(ctx, qadenaKeeper, pioneerID)

		if err != nil {
			c.ContextError(ctx, "Couldn't get jar for pioneer", "pioneerID", pioneerID)
			return nil, err
		}

		c.ContextDebug(ctx, "jarID", "jarID", jarID)

		jarIntervalPubKID, jarIntervalPubK, jarPreviousPubK, _, err := DSVSMsgServerGetIntervalPublicKeyWithPrevious(ctx, qadenaKeeper, jarID, qadenatypes.JarNodeType)

		if err != nil {
			c.ContextError(ctx, "Couldn't get jar interval public key", "jarID", jarID, "nodeType", qadenatypes.JarNodeType)
			return nil, err
		}

		c.ContextDebug(ctx, "jarIntervalPubKID", "id", jarIntervalPubKID, "pubk", jarIntervalPubK)

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     jarIntervalPubK,
			AltPubK:  jarPreviousPubK,
			NodeID:   jarID,
			NodeType: qadenatypes.JarNodeType,
		})
	}

	return ccPubK, nil
}

func DSVSMsgServerAppendAuthorizeUser(ctx sdk.Context, ccPubK []c.VSharePubKInfo, qadenaKeeper types.QadenaKeeper, creatorWallet qadenatypes.Wallet, serviceProviderType string) ([]c.VSharePubKInfo, error) {
	// make sure that the creator has the required service provider
	serviceProviderFound := false
	for _, serviceProviderID := range creatorWallet.ServiceProviderID {
		_, pubK, previousPubK, intervalServiceProviderType, err := DSVSMsgServerGetIntervalPublicKeyWithPrevious(ctx, qadenaKeeper, serviceProviderID, qadenatypes.ServiceProviderNodeType)

		if err == nil {
			if serviceProviderType == intervalServiceProviderType {
				ccPubK = append(ccPubK, c.VSharePubKInfo{PubK: pubK, AltPubK: previousPubK, NodeID: serviceProviderID, NodeType: qadenatypes.ServiceProviderNodeType})

				serviceProviderFound = true
				break
			}
		}
	}
	if !serviceProviderFound {
		return nil, types.ErrUnauthorized
	}

	return ccPubK, nil
}
