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
		c.ContextDebug(sdkctx, "error returned by GetStoreHash on enclave "+err.Error())
		return err
	}

	for _, sh := range storeHashes.GetHashes() {
		h := c.StoreHashByKVStoreService(sdkctx, k.storeService, sh.Key)
		if sh.Hash != h {
			c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
		} else {
			c.ContextDebug(sdkctx, "in-sync store:  key="+sh.Key+" hash="+c.DisplayHash(h))
		}
	}

	return nil
}

// sync DB between chain and enclave
func (k Keeper) EnclaveSynchronizeStores(sdkctx sdk.Context) error {
	c.ContextDebug(sdkctx, "DSVS module BeginBlock -- Chain initialized and ready for business, synchronizing enclave...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	gsh := &qadenatypes.MsgGetStoreHash{}

	enclaveGRPCClient := k.qadenaKeeper.GetEnclaveRPCClient()

	storeHashes, err := enclaveGRPCClient.GetStoreHash(ctx, gsh)
	if err != nil {
		c.ContextDebug(sdkctx, "error returned by GetStoreHash on enclave "+err.Error())
		return err
	}

	checkSync := false

	for _, sh := range storeHashes.GetHashes() {
		h := c.StoreHashByKVStoreService(sdkctx, k.storeService, sh.Key)
		if sh.Hash != h {
			switch sh.Key {
			case types.AuthorizedSignatoryKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))

				authorizedSignatories := k.GetAllAuthorizedSignatory(sdkctx)
				//    fmt.Println("wallets", list)
				for _, authorizedSignatory := range authorizedSignatories {
					// first
					first := c.ProtoizeVShareSignatory(&c.VShareSignatory{
						EncSignatoryVShare: authorizedSignatory.Signatory[0].EncAuthorizedSignatoryVShare,
						VShareBind:         c.DSVSUnprotoizeVShareBindData(authorizedSignatory.Signatory[0].AuthorizedSignatoryVShareBind),
					})

					var rest []*qadenatypes.VShareSignatory
					if len(authorizedSignatory.Signatory) > 1 {
						rest = make([]*qadenatypes.VShareSignatory, 0, len(authorizedSignatory.Signatory)-1)
						for _, s := range authorizedSignatory.Signatory[1:] {
							rest = append(rest, c.ProtoizeVShareSignatory(&c.VShareSignatory{
								EncSignatoryVShare: s.EncAuthorizedSignatoryVShare,
								VShareBind:         c.DSVSUnprotoizeVShareBindData(s.AuthorizedSignatoryVShareBind),
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
						c.ContextError(sdkctx, "error returned by ValidateAuthorizedSignatory on enclave "+err.Error())
						return err
					}
					checkSync = true
				}

			default:
				c.ContextDebug(sdkctx, "Ignoring key="+sh.Key+" in DSVS module")
			}

		} else {
			c.ContextDebug(sdkctx, "in-sync store:  key="+sh.Key+" hash="+c.DisplayHash(h))
		}
	}

	if checkSync {
		c.ContextDebug(sdkctx, "Checking Sync after chain->enclave synchronization")
		k.displayStoresSync(sdkctx)
	}

	return nil
}
