package keeper

import (
	"fmt"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"encoding/json"
	"os"

	"cosmossdk.io/core/comet"
	"cosmossdk.io/core/header"
)

type (
	Keeper struct {
		cdc          codec.BinaryCodec
		storeService store.KVStoreService
		logger       log.Logger

		// the address capable of executing a MsgUpdateParams message. Typically, this
		// should be the x/gov module account.
		authority string

		bankKeeper           types.BankKeeper
		accountKeeper        types.AccountKeeper
		pricefeedKeeper      types.PricefeedKeeper
		contractInfo         *types.ContractInfoHolder
		cachedCreator        *c.StringHolder
		cachedGasPriceInAQDN *c.UInt64Holder
		headerService        header.Service
		cometService         comet.BlockInfoService

		nodeParams types.NodeParams
	}
)

func (k Keeper) LoadNodeParams(homePath string) {

	c.LoggerDebug(k.logger, "Loading "+homePath+"/config/node_params.json")

	file, _ := os.ReadFile(homePath + "/config/node_params.json")

	//c.LoggerDebug(k.logger, "file: " + string(file))

	err := json.Unmarshal([]byte(file), &k.nodeParams)

	if err != nil {
		c.LoggerError(k.logger, "Unmarshal err "+err.Error())
		panic("Unmarshal err " + err.Error())
	}

	c.LoggerDebug(k.logger, "NodeParams: "+c.PrettyPrint(k.nodeParams))
}

func NewKeeper(
	cdc codec.BinaryCodec,
	storeService store.KVStoreService,
	logger log.Logger,
	authority string,

	bank types.BankKeeper,
	ak types.AccountKeeper,
	pfk types.PricefeedKeeper,

	headerService header.Service,
	cometService comet.BlockInfoService,

) Keeper {
	if _, err := sdk.AccAddressFromBech32(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address: %s", authority))
	}

	return Keeper{
		cdc:                  cdc,
		storeService:         storeService,
		authority:            authority,
		logger:               logger,
		bankKeeper:           bank, // need to make sure our Keeper is initialized properly or SendCoinsFromAccountToModule will not work
		accountKeeper:        ak,
		pricefeedKeeper:      pfk,
		contractInfo:         &types.ContractInfoHolder{}, // filled in by app wiring once wasmd exists
		cachedCreator:        &c.StringHolder{},           //
		cachedGasPriceInAQDN: &c.UInt64Holder{},           //
		headerService:        headerService,
		cometService:         cometService,
	}
}

// GetAuthority returns the module's authority.
func (k Keeper) GetAuthority() string {
	return k.authority
}

// SetContractInfoSource wires in wasm state lookup, once app wiring has built wasmd's keeper.
func (k Keeper) SetContractInfoSource(src types.ContractInfoSource) {
	k.contractInfo.Source = src
}

// contractCodeID reports the live code ID for an address, and whether it is a wasm contract at all.
//
// A missing source is treated as "not a contract" rather than panicking: unit tests and simulations
// build the keeper without app wiring, and there the question never has a wasm answer.  Every caller
// that could be fooled by that verifies membership in the scanned-contract whitelist FIRST, so a
// nil source cannot turn an unlisted contract into a permitted one.
func (k Keeper) contractCodeID(ctx sdk.Context, addr sdk.AccAddress) (uint64, bool) {
	if k.contractInfo == nil || k.contractInfo.Source == nil {
		return 0, false
	}
	return k.contractInfo.Source.ContractCodeID(ctx, addr)
}

// Logger returns a module-specific logger.
func (k Keeper) Logger() log.Logger {
	return k.logger.With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

// if you get:  ✘ Panic: Multiple implementations found for interface types.QadenaKeeper, please look in expected_keepers for the new types and add something similar as a placeholder
func (k Keeper) DUMMY_KEEPER_METHOD_NAMESERVICE() {
	panic("RAV DO NOT IMPLEMENT ME")
}

func (k Keeper) DUMMY_KEEPER_METHOD_DSVS() {
	panic("RAV DO NOT IMPLEMENT ME")
}

// common funcs for keepers

// GetIntervalPublicKeyWithPrevious resolves an interval key and, when the record names one, the key
// it replaced at the last rotation.
//
// previousPubK is what makes the rotation grace period possible: a transaction whose VShare was
// built moments before a rotation still names the old key, and rejecting it would fail a perfectly
// well-formed transaction over timing alone.  It is read from consensus state -- the record's
// PreviousPubKID, filled in by SetIntervalPublicKeyID -- rather than from history, because pruning
// settings, uptime and state-sync method all differ between validators, so "what was the key N
// blocks ago" is not a question every node can answer the same way.
//
// A previous id with no matching PublicKey row is NOT an error: previousPubK comes back empty and
// the caller simply gets no grace, which is exactly the behaviour before this existed.
func (k Keeper) GetIntervalPublicKeyWithPrevious(ctx sdk.Context, intervalNodeID string, intervalNodeType string) (pubKID string, pubK string, previousPubK string, serviceProviderType string, err error) {
	// find the interval ss pubk
	intervalPubKID, found := k.GetIntervalPublicKeyID(ctx, intervalNodeID, intervalNodeType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	intervalPubK, found := k.GetPublicKey(ctx, intervalPubKID.PubKID, types.TransactionPubKType)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	if intervalPubKID.PreviousPubKID != "" {
		if prev, prevFound := k.GetPublicKey(ctx, intervalPubKID.PreviousPubKID, types.TransactionPubKType); prevFound {
			previousPubK = prev.PubK
		}
	}

	pubKID = intervalPubKID.PubKID
	pubK = intervalPubK.PubK
	serviceProviderType = intervalPubKID.ServiceProviderType
	return
}

func MsgServerGetJarForPioneer(ctx sdk.Context, qadenaKeeper Keeper, pioneerID string) (jarID string, err error) {
	// find the interval ss pubk
	pioneerJar, found := qadenaKeeper.GetPioneerJar(ctx, pioneerID)

	if !found {
		err = types.ErrPubKIDNotExists
		return
	}

	jarID = pioneerJar.GetJarID()
	return
}

func MsgServerAppendRequiredChainCCPubK(ctx sdk.Context, ccPubK []c.VSharePubKInfo, qadenaKeeper Keeper, pioneerID string, excludeSSIntervalPubK bool) ([]c.VSharePubKInfo, error) {
	if excludeSSIntervalPubK && pioneerID == "" {
		c.ContextError(ctx, "Logic error")
		return nil, fmt.Errorf("Logic error")
	}
	if !excludeSSIntervalPubK {
		// The SS interval key rotates every 555 blocks, so this is the one that actually needs the
		// grace: AltPubK lets a VShare bound just before a rotation still satisfy the expectation.
		ssIntervalPubKID, ssIntervalPubK, ssPreviousPubK, _, err := qadenaKeeper.GetIntervalPublicKeyWithPrevious(ctx, types.SSNodeID, types.SSNodeType)

		if err != nil {
			c.ContextError(ctx, "Couldn't get interval public key")
			return nil, err
		}

		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     ssIntervalPubK,
			AltPubK:  ssPreviousPubK,
			NodeID:   types.SSNodeID,
			NodeType: types.SSNodeType,
		})

		c.ContextDebug(ctx, "ssIntervalPubKID", "id", ssIntervalPubKID, "pubk", ssIntervalPubK)
	}

	if pioneerID != "" {
		jarID, err := MsgServerGetJarForPioneer(ctx, qadenaKeeper, pioneerID)

		if err != nil {
			c.ContextError(ctx, "Couldn't get jar for pioneer", "pioneerID", pioneerID)
			return nil, err
		}

		c.ContextDebug(ctx, "jarID", "jarID", jarID)

		jarIntervalPubKID, jarIntervalPubK, jarPreviousPubK, _, err := qadenaKeeper.GetIntervalPublicKeyWithPrevious(ctx, jarID, types.JarNodeType)

		if err != nil {
			c.ContextError(ctx, "Couldn't get jar interval public key", "jarID", jarID, "nodeType", types.JarNodeType)
			return nil, err
		}

		c.ContextDebug(ctx, "jarIntervalPubKID", "id", jarIntervalPubKID, "pubk", jarIntervalPubK)

		// Nothing rotates a jar key on a timer today, so this is empty in practice.  It is set
		// anyway so the rule is "an interval key expectation carries its predecessor" rather than a
		// special case for SS that whoever adds jar rotation would have to remember to copy.
		ccPubK = append(ccPubK, c.VSharePubKInfo{
			PubK:     jarIntervalPubK,
			AltPubK:  jarPreviousPubK,
			NodeID:   jarID,
			NodeType: types.JarNodeType,
		})
	}

	return ccPubK, nil
}

func MsgServerAppendAuthorizeUser(ctx sdk.Context, ccPubK []c.VSharePubKInfo, qadenaKeeper Keeper, creatorWallet types.Wallet, serviceProviderType string) ([]c.VSharePubKInfo, error) {
	// make sure that the creator has the required service provider
	serviceProviderFound := false
	for _, serviceProviderID := range creatorWallet.ServiceProviderID {
		_, pubK, previousPubK, intervalServiceProviderType, err := qadenaKeeper.GetIntervalPublicKeyWithPrevious(ctx, serviceProviderID, types.ServiceProviderNodeType)

		if err == nil {
			if serviceProviderType == intervalServiceProviderType {
				ccPubK = append(ccPubK, c.VSharePubKInfo{PubK: pubK, AltPubK: previousPubK, NodeID: serviceProviderID, NodeType: types.ServiceProviderNodeType})

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

// find any service providers that are optional
func MsgServerAppendOptionalServiceProvidersCCPubK(ctx sdk.Context, ccPubK []c.VSharePubKInfo, qadenaKeeper Keeper, serviceProviderID []string, optionalServiceProviderType []string) ([]c.VSharePubKInfo, error) {
	for i := range serviceProviderID {
		_, pubK, previousPubK, serviceProviderType, err := qadenaKeeper.GetIntervalPublicKeyWithPrevious(ctx, serviceProviderID[i], types.ServiceProviderNodeType)
		if err != nil {
			c.ContextError(ctx, "Couldn't get service provider interval public key", "serviceProviderID", serviceProviderID[i], "nodeType", types.ServiceProviderNodeType)
			return nil, err
		}

		// check if serviceProviderType is in array requiredServiceProviderType
		for j := range optionalServiceProviderType {
			if serviceProviderType == optionalServiceProviderType[j] {
				ccPubK = append(ccPubK, c.VSharePubKInfo{
					PubK:     pubK,
					AltPubK:  previousPubK,
					NodeID:   serviceProviderID[i],
					NodeType: types.ServiceProviderNodeType,
				})
			}
		}
	}

	return ccPubK, nil
}
