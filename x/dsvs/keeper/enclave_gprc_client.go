package keeper

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	qadenatypes "github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (k Keeper) EnclaveSynchronizeStores(sdkctx sdk.Context) error {
	c.ContextDebug(sdkctx, "DSVS: EnclaveSynchronizeStores -- Chain initialized and ready for business, synchronizing enclave...")

	ctx, cancel := enclaveExecContext()
	defer cancel()

	enclaveGRPCClient := k.qadenaKeeper.GetEnclaveRPCClient()

	// Decision by accumulator rows, exactly as the qadena keeper's sync (backlog item 46).
	reply, err := enclaveGRPCClient.GetStoreAccumulators(ctx, &qadenatypes.MsgGetStoreAccumulators{
		Keys: []string{types.AuthorizedSignatoryKeyPrefix},
	})
	if err != nil {
		c.ContextError(sdkctx, "DSVS: EnclaveSynchronizeStores error returned by GetStoreAccumulators on enclave "+err.Error())
		return err
	}

	checkSync := false

	for _, e := range reply.GetAccumulators() {
		if e.GetKey() != types.AuthorizedSignatoryKeyPrefix {
			continue
		}
		if !e.GetPresent() {
			return fmt.Errorf("DSVS: enclave returned no accumulator for %s -- establish-then-answer makes this impossible", e.GetKey())
		}
		chainAcc := k.EnsureStoreAccumulator(sdkctx, e.GetKey())
		{
			if string(chainAcc[:]) != string(e.GetAcc()) {
				c.ContextError(sdkctx, "DSVS: EnclaveSynchronizeStores OUT-OF-SYNC store:  key="+e.GetKey()+
					" enclave-acc="+fmt.Sprintf("%x", e.GetAcc())+" chain-acc="+c.AccumulatorHex(chainAcc))

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
				c.ContextDebug(sdkctx, "DSVS: EnclaveSynchronizeStores in-sync store:  key="+e.GetKey()+" acc="+c.AccumulatorHex(chainAcc))
			}
		}
	}
	_ = checkSync

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
	}
}
