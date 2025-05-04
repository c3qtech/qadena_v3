package keeper

import (
	"fmt"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"qadena/x/dsvs/types"
	c "qadena/x/qadena/common"
	qadenatypes "qadena/x/qadena/types"
)

type (
	Keeper struct {
		cdc          codec.BinaryCodec
		storeService store.KVStoreService
		logger       log.Logger

		// the address capable of executing a MsgUpdateParams message. Typically, this
		// should be the x/gov module account.
		authority string

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
) Keeper {
	if _, err := sdk.AccAddressFromBech32(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address: %s", authority))
	}

	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		authority:    authority,
		logger:       logger,

		bankKeeper:   bankKeeper,
		qadenaKeeper: qadenaKeeper,
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
func DSVSMsgServerGetIntervalPublicKey(ctx sdk.Context, qadenaKeeper types.QadenaKeeper, intervalNodeID string, intervalNodeType string) (pubKID string, pubK string, serviceProviderType string, err error) {
	// find the interval ss pubk
	intervalPubKID, found := qadenaKeeper.GetIntervalPublicKeyID(ctx, intervalNodeID, intervalNodeType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	intervalPubK, found := qadenaKeeper.GetPublicKey(ctx, intervalPubKID.PubKID, qadenatypes.TransactionPubKType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	pubKID = intervalPubKID.PubKID
	pubK = intervalPubK.PubK
	serviceProviderType = intervalPubKID.ServiceProviderType
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
		fmt.Println("Logic error")
		return nil, fmt.Errorf("Logic error")
	}
	if !excludeSSIntervalPubK {
		ssIntervalPubKID, ssIntervalPubK, _, err := DSVSMsgServerGetIntervalPublicKey(ctx, qadenaKeeper, qadenatypes.SSNodeID, qadenatypes.SSNodeType)

		if err != nil {
			fmt.Println("Couldn't get interval public key")
			return nil, err
		}

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     ssIntervalPubK,
			NodeID:   qadenatypes.SSNodeID,
			NodeType: qadenatypes.SSNodeType,
		})

		fmt.Println("ssIntervalPubKID", ssIntervalPubKID, "ssIntervalPubK", ssIntervalPubK)
	}

	if pioneerID != "" {
		jarID, err := DSVSMsgServerGetJarForPioneer(ctx, qadenaKeeper, pioneerID)

		if err != nil {
			fmt.Println("Couldn't get jar for pioneer", pioneerID)
			return nil, err
		}

		fmt.Println("jarID", jarID)

		jarIntervalPubKID, jarIntervalPubK, _, err := DSVSMsgServerGetIntervalPublicKey(ctx, qadenaKeeper, jarID, qadenatypes.JarNodeType)

		if err != nil {
			fmt.Println("Couldn't get jar interval public key", jarID, qadenatypes.JarNodeType)
			return nil, err
		}

		fmt.Println("jarIntervalPubKID", jarIntervalPubKID, "jarIntervalPubK", jarIntervalPubK)

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     jarIntervalPubK,
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
		_, pubK, intervalServiceProviderType, err := DSVSMsgServerGetIntervalPublicKey(ctx, qadenaKeeper, serviceProviderID, qadenatypes.ServiceProviderNodeType)

		if err == nil {
			if serviceProviderType == intervalServiceProviderType {
				ccPubK = append(ccPubK, c.VSharePubKInfo{PubK: pubK, NodeID: serviceProviderID, NodeType: qadenatypes.ServiceProviderNodeType})

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
