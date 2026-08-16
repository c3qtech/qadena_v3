package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (k Keeper) displayStoresSync(sdkctx sdk.Context) error {
	ctx, cancel := enclaveExecContext()
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
			// The chain-side shadow, wired where this module already scans.
			k.CompareStoreAccumulator(sdkctx, sh.Key)
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

	ctx, cancel := enclaveExecContext()
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
		if sh.Key == types.AuthorizedSignatoryKeyPrefix {
			// Same structural place as the enclave's shadow (inside its GetStoreHash): every
			// moment this module scans for hashes, it also checks its maintained accumulator.
			k.CompareStoreAccumulator(sdkctx, sh.Key)
		}
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
					// SET, NOT VALIDATE.  This replays a row the chain has already validated, which is
					// what every other store's seeding does (SetWallet, SetCredential, SetProtectKey).
					// Going through ValidateAuthorizedSignatory applied the LIVE-path freshness rule --
					// the vshare bind must name the current or previous ss interval key -- to rows that
					// are old by construction, so on a state-synced joiner all of them were refused:
					//
					//	bindData does not contain the current or previous ssIntervalPubKID
					//	... code 1141: Unauthorized
					//
					// The node then ran with no authorized signatories at all and forked 252 blocks
					// later, when ValidateAuthorizedSigner rejected a transaction the network accepted.
					// The freshness rule still guards the live path in
					// msg_server_register_authorized_signatory.go; only this replay bypasses it.
					_, err := enclaveGRPCClient.SetAuthorizedSignatory(sdkctx, req)
					if err != nil {
						c.ContextError(sdkctx, "DSVS: EnclaveSynchronizeStores error returned by SetAuthorizedSignatory on enclave "+err.Error())
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
