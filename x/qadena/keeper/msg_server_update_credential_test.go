package keeper_test

import (
	"testing"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/stretchr/testify/require"
)

// These cover only the authorization branches that run before the enclave is contacted.  The test
// harness has no enclave and no pricefeed keeper, so a case that got as far as the fee or the
// enclave call would panic rather than assert anything -- which is exactly why the ownership checks
// live at the top of the handler.

const (
	testOwnerWalletID    = "qadena1owner"
	testOtherWalletID    = "qadena1other"
	testCredentialID     = "qadena1owner-credential"
	testOtherCredentialD = "qadena1other-credential"
)

func TestUpdateCredentialWalletNotFound(t *testing.T) {
	_, ms, ctx := setupMsgServer(t)

	_, err := ms.UpdateCredential(ctx, &types.MsgUpdateCredential{
		Creator:        testOwnerWalletID,
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
	})

	require.ErrorIs(t, err, types.ErrWalletNotExists)
}

func TestUpdateCredentialCredentialNotFound(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetWalletNoEnclave(ctx, types.Wallet{
		WalletID:     testOwnerWalletID,
		CredentialID: testCredentialID,
	})

	_, err := ms.UpdateCredential(ctx, &types.MsgUpdateCredential{
		Creator:        testOwnerWalletID,
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
	})

	// the exact inversion of ClaimCredential, which rejects a credentialID that already exists
	require.ErrorIs(t, err, types.ErrCredentialNotExists)
}

func TestUpdateCredentialNotOwner(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetWalletNoEnclave(ctx, types.Wallet{
		WalletID:     testOtherWalletID,
		CredentialID: testOtherCredentialD,
	})

	// the credential belongs to somebody else
	k.SetCredentialNoEnclave(ctx, types.Credential{
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
		WalletID:       testOwnerWalletID,
	})

	_, err := ms.UpdateCredential(ctx, &types.MsgUpdateCredential{
		Creator:        testOtherWalletID,
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
	})

	require.ErrorIs(t, err, types.ErrCredentialUpdateNotOwner)
}

// An unclaimed credential has an empty walletID, which must never match a creator.
func TestUpdateCredentialUnclaimed(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetWalletNoEnclave(ctx, types.Wallet{
		WalletID:     testOwnerWalletID,
		CredentialID: testCredentialID,
	})

	k.SetCredentialNoEnclave(ctx, types.Credential{
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
		WalletID:       "",
	})

	_, err := ms.UpdateCredential(ctx, &types.MsgUpdateCredential{
		Creator:        testOwnerWalletID,
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
	})

	require.ErrorIs(t, err, types.ErrCredentialUpdateNotOwner)
}

// The credential says the creator owns it, but the wallet points somewhere else.  The two records
// disagreeing is a bug, not something to paper over by picking one of them.
func TestUpdateCredentialWalletPointsElsewhere(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetWalletNoEnclave(ctx, types.Wallet{
		WalletID:     testOwnerWalletID,
		CredentialID: testOtherCredentialD,
	})

	k.SetCredentialNoEnclave(ctx, types.Credential{
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
		WalletID:       testOwnerWalletID,
	})

	_, err := ms.UpdateCredential(ctx, &types.MsgUpdateCredential{
		Creator:        testOwnerWalletID,
		CredentialID:   testCredentialID,
		CredentialType: types.PersonalInfoCredentialType,
	})

	require.ErrorIs(t, err, types.ErrCredentialUpdateNotOwner)
}

func TestClaimUpdatedCredentialWalletNotFound(t *testing.T) {
	_, ms, ctx := setupMsgServer(t)

	_, err := ms.ClaimUpdatedCredential(ctx, &types.MsgClaimUpdatedCredential{
		Creator: testOwnerWalletID,
	})

	require.ErrorIs(t, err, types.ErrWalletNotExists)
}

func TestClaimUpdatedCredentialEmptyAcceptList(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetWalletNoEnclave(ctx, types.Wallet{WalletID: testOwnerWalletID})

	_, err := ms.ClaimUpdatedCredential(ctx, &types.MsgClaimUpdatedCredential{
		Creator: testOwnerWalletID,
	})

	require.ErrorIs(t, err, types.ErrInvalidVShare)
}

// A user may drop a contact credential of their own, but not the personal-info row or its name
// sub-credentials: those anchor wallet.credentialID and the identity hashes key recovery resolves.
func TestRemoveCredentialOwnerCannotRemoveIdentity(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	for _, credentialType := range []string{
		types.PersonalInfoCredentialType,
		types.FirstNamePersonalInfoCredentialType,
		types.MiddleNamePersonalInfoCredentialType,
		types.LastNamePersonalInfoCredentialType,
	} {
		k.SetCredentialNoEnclave(ctx, types.Credential{
			CredentialID:   testCredentialID,
			CredentialType: credentialType,
			WalletID:       testOwnerWalletID,
		})

		_, err := ms.RemoveCredential(ctx, &types.MsgRemoveCredential{
			Creator:        testOwnerWalletID,
			CredentialID:   testCredentialID,
			CredentialType: credentialType,
		})

		require.ErrorIsf(t, err, types.ErrCredentialUpdateRejected, "credential type %s", credentialType)
	}
}

func TestRemoveCredentialNotFound(t *testing.T) {
	_, ms, ctx := setupMsgServer(t)

	_, err := ms.RemoveCredential(ctx, &types.MsgRemoveCredential{
		Creator:        testOwnerWalletID,
		CredentialID:   testCredentialID,
		CredentialType: types.PhoneContactCredentialType,
	})

	require.ErrorIs(t, err, types.ErrCredentialNotExists)
}
