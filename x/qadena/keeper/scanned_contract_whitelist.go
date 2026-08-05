package keeper

import (
	"context"
	"strconv"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The scanned-contract whitelist: non-wallet parties that may take part in a bank send, and are
// still AML-scanned when they do.
//
// It replaced a bank-send whitelist that exempted these accounts from scanning altogether.  That
// exemption was never really a policy choice -- it was a workaround for a report format that could
// only name credentialed people.  Now that a report can name a contract, the workaround is gone and
// nothing on this chain moves account-to-account without being scanned.
//
// Unlike most state in this module it is NOT forwarded to the enclave wholesale.  The enclave
// decides whether a scanned transfer is reportable; whether a party is ALLOWED to be a non-wallet is
// a chain-level question, answered in the send restriction, which then passes the resolved entry
// down on the scan message.  The enclave cannot answer it itself -- it holds no wasm state and has
// no way to tell a contract from a plain account.

// SetScannedContractWhitelist adds or replaces one entry.
func (k Keeper) SetScannedContractWhitelist(ctx context.Context, entry types.ScannedContractWhitelist) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ScannedContractWhitelistKeyPrefix))
	b := k.cdc.MustMarshal(&entry)
	store.Set(types.ScannedContractWhitelistKey(entry.Address), b)
}

// GetScannedContractWhitelist returns one entry, including its pinned code ID and reason.
//
// There is no cheaper Has()-style variant here, unlike the list this replaced.  That one only ever
// asked a yes/no question; this one always needs the record, because the pinned code ID has to be
// re-checked on every send and the reason travels into the report.
func (k Keeper) GetScannedContractWhitelist(ctx context.Context, address string) (val types.ScannedContractWhitelist, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ScannedContractWhitelistKeyPrefix))

	b := store.Get(types.ScannedContractWhitelistKey(address))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveScannedContractWhitelist drops one entry.
func (k Keeper) RemoveScannedContractWhitelist(ctx context.Context, address string) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ScannedContractWhitelistKeyPrefix))
	store.Delete(types.ScannedContractWhitelistKey(address))
}

// resolveScannedParty decides how one side of a bank send should be described to the enclave.
//
// It returns nil for an ordinary party -- a wallet, or an address the enclave will refuse as
// unscannable on its own terms.  It returns an entry only for a listed non-wallet, which is what
// tells the enclave to take a contract descriptor instead of decoding a credential.
//
// The pinned code ID is re-verified HERE, on every send, rather than trusted from the stored entry.
// That is the whole point of pinning: a wasmd contract's admin can migrate it to new code, so an
// entry approved for a benign escrow would otherwise carry over to whatever that address runs next.
// Re-checking turns a migration into a refusal that names itself, and governance has to re-approve
// the new code explicitly.
func (k Keeper) resolveScannedParty(ctx sdk.Context, addr sdk.AccAddress) (*types.ScannedContractWhitelist, error) {
	entry, found := k.GetScannedContractWhitelist(ctx, addr.String())
	if !found {
		// Not listed.  Not an error by itself -- the overwhelmingly common case is an ordinary
		// wallet, which the enclave scans normally.  An unlisted address that turns out to hold no
		// credential is refused by the enclave as unscannable.
		return nil, nil
	}

	liveCodeID, isContract := k.contractCodeID(ctx, addr)

	// An entry pinned to code that is no longer running is void.  Checked in both directions: a
	// contract whose code changed, and a listed non-contract that has since BECOME a contract at
	// the same address.
	if isContract != (entry.CodeID != 0) || (isContract && liveCodeID != entry.CodeID) {
		c.ContextError(ctx, "refusing bank send for "+addr.String()+
			": whitelisted at codeID "+strconv.FormatUint(entry.CodeID, 10)+
			", chain now reports "+describeCode(liveCodeID, isContract))
		return nil, errorsmod.Wrapf(types.ErrScannedContractCodeMismatch,
			"%s: whitelisted at codeID %d, now %s", addr.String(), entry.CodeID,
			describeCode(liveCodeID, isContract))
	}

	return &entry, nil
}

// GetAllScannedContractWhitelist returns every entry, for genesis export and for querying.
func (k Keeper) GetAllScannedContractWhitelist(ctx context.Context) (list []types.ScannedContractWhitelist) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.ScannedContractWhitelistKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.ScannedContractWhitelist
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
