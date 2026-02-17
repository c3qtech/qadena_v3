package keeper

import (
	"context"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (k Keeper) displayStoresSync(sdkctx sdk.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	gsh := &qadenatypes.MsgGetStoreHash{}

	enclaveGRPCClient := k.qadenaKeeper.GetEnclaveRPCClient()

	storeHashes, err := enclaveGRPCClient.GetStoreHash(ctx, gsh)
	if err != nil {
		c.ContextDebug(sdkctx, "DSVS: displayStoresSync error returned by GetStoreHash on enclave "+err.Error())
		return err
	}

	for _, sh := range storeHashes.GetHashes() {
		switch sh.Key {
		case types.AuthorizedSignatoryKeyPrefix:
			h := c.StoreHashByKVStoreService(sdkctx, k.storeService, sh.Key)
			if sh.Hash != h {
				c.ContextError(sdkctx, "DSVS: displayStoresSync OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
			} else {
				c.ContextDebug(sdkctx, "DSVS: displayStoresSync in-sync store:  key="+sh.Key+" hash="+c.DisplayHash(h))
			}
		default:
			c.ContextDebug(sdkctx, "DSVS: displayStoresSync Ignoring key="+sh.Key+" in DSVS module")
		}
	}

	return nil
}

// sync DB between chain and enclave
func (k Keeper) EnclaveSynchronizeStores(sdkctx sdk.Context) error {
	c.ContextDebug(sdkctx, "DSVS: EnclaveSynchronizeStores -- Chain initialized and ready for business, synchronizing enclave...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	gsh := &qadenatypes.MsgGetStoreHash{}

	enclaveGRPCClient := k.qadenaKeeper.GetEnclaveRPCClient()

	storeHashes, err := enclaveGRPCClient.GetStoreHash(ctx, gsh)
	if err != nil {
		c.ContextDebug(sdkctx, "DSVS: EnclaveSynchronizeStores error returned by GetStoreHash on enclave "+err.Error())
		return err
	}

	checkSync := false

	for _, sh := range storeHashes.GetHashes() {
		h := c.StoreHashByKVStoreService(sdkctx, k.storeService, sh.Key)
		switch sh.Key {
		case types.AuthorizedSignatoryKeyPrefix:
			if sh.Hash != h {
				c.ContextError(sdkctx, "DSVS: EnclaveSynchronizeStores OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))

				authorizedSignatories := k.GetAllAuthorizedSignatory(sdkctx)
				for _, authorizedSignatory := range authorizedSignatories {
					// first
					first := c.ProtoizeVShareSignatory(&c.VShareSignatory{
						EncSignatoryVShare: authorizedSignatory.Signatory[0].EncAuthorizedSignatoryVShare,
						VShareBind:         c.DSVSUnprotoizeVShareBindData(authorizedSignatory.Signatory[0].AuthorizedSignatoryVShareBind),
						Time:               authorizedSignatory.Signatory[0].Time,
					})

					var rest []*qadenatypes.VShareSignatory
					if len(authorizedSignatory.Signatory) > 1 {
						rest = make([]*qadenatypes.VShareSignatory, 0, len(authorizedSignatory.Signatory)-1)
						for _, s := range authorizedSignatory.Signatory[1:] {
							rest = append(rest, c.ProtoizeVShareSignatory(&c.VShareSignatory{
								EncSignatoryVShare: s.EncAuthorizedSignatoryVShare,
								VShareBind:         c.DSVSUnprotoizeVShareBindData(s.AuthorizedSignatoryVShareBind),
								Time:               s.Time,
							}))
						}
					}

					// rest
					req := &qadenatypes.ValidateAuthorizedSignatoryRequest{
						Creator:          authorizedSignatory.WalletID,
						Signatory:        first,
						CurrentSignatory: rest,
					}
					_, err := enclaveGRPCClient.ValidateAuthorizedSignatory(sdkctx, req)
					if err != nil {
						c.ContextError(sdkctx, "DSVS: EnclaveSynchronizeStores error returned by ValidateAuthorizedSignatory on enclave "+err.Error())
						return err
					}
					checkSync = true
				}
			} else {
				c.ContextDebug(sdkctx, "DSVS: EnclaveSynchronizeStores in-sync store:  key="+sh.Key+" hash="+c.DisplayHash(h))
			}
		default:
			c.ContextDebug(sdkctx, "DSVS: EnclaveSynchronizeStores Ignoring key="+sh.Key+" in DSVS module")
		}
	}

	if checkSync {
		c.ContextDebug(sdkctx, "DSVS: EnclaveSynchronizeStores Checking Sync after chain->enclave synchronization")
		k.displayStoresSync(sdkctx)
	}

	return nil
}

var synchronizedWithEnclave = false

func (k Keeper) EnclaveBeginBlock(sdkCtx sdk.Context) {

	if !synchronizedWithEnclave {
		err := k.EnclaveSynchronizeStores(sdkCtx)
		if err != nil {
			c.ContextError(sdkCtx, "DSVS: enclaveSynchronizeStores failed: "+err.Error())
		} else {
			synchronizedWithEnclave = true
		}
	} else {
		if c.LogLevelDebugEnabled {
			header := k.headerService.GetHeaderInfo(sdkCtx)
			if header.Height%25 == 0 {
				k.displayStoresSync(sdkCtx)
			}
		}
	}
}
