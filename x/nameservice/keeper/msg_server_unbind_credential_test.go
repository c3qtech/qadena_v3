package keeper_test

import (
	"testing"

	"github.com/c3qtech/qadena_v3/x/nameservice/types"

	"github.com/stretchr/testify/require"
)

const (
	testBoundAddress = "qadena1bound"
	testOtherAddress = "qadena1other"
	testPhoneNumber  = "+639061234567"
	testPhoneType    = "phone-contact-info"
)

func TestUnbindCredentialRemovesBinding(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetNameBinding(ctx, types.NameBinding{
		Credential:     testPhoneNumber,
		CredentialType: testPhoneType,
		Address:        testBoundAddress,
	})

	_, err := ms.UnbindCredential(ctx, &types.MsgUnbindCredential{
		Creator:        testBoundAddress,
		CredentialType: testPhoneType,
		CredentialInfo: testPhoneNumber,
	})
	require.NoError(t, err)

	_, found := k.GetNameBinding(ctx, testPhoneNumber, testPhoneType)
	require.False(t, found, "binding should be gone")
}

// The whole point of the authorization check: a contact you no longer hold must not be removable by
// whoever holds it next.
func TestUnbindCredentialNotOwner(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetNameBinding(ctx, types.NameBinding{
		Credential:     testPhoneNumber,
		CredentialType: testPhoneType,
		Address:        testBoundAddress,
	})

	_, err := ms.UnbindCredential(ctx, &types.MsgUnbindCredential{
		Creator:        testOtherAddress,
		CredentialType: testPhoneType,
		CredentialInfo: testPhoneNumber,
	})
	require.ErrorIs(t, err, types.ErrNameBindingNotOwner)

	_, found := k.GetNameBinding(ctx, testPhoneNumber, testPhoneType)
	require.True(t, found, "binding must survive a rejected unbind")
}

func TestUnbindCredentialNotFound(t *testing.T) {
	_, ms, ctx := setupMsgServer(t)

	_, err := ms.UnbindCredential(ctx, &types.MsgUnbindCredential{
		Creator:        testBoundAddress,
		CredentialType: testPhoneType,
		CredentialInfo: testPhoneNumber,
	})
	require.ErrorIs(t, err, types.ErrNameBindingNotExists)
}

// The binding key is (contact, type), so the same number bound for a different type is a different
// binding and must not be collaterally removed.
func TestUnbindCredentialIsPerCredentialType(t *testing.T) {
	k, ms, ctx := setupMsgServer(t)

	k.SetNameBinding(ctx, types.NameBinding{
		Credential:     testPhoneNumber,
		CredentialType: testPhoneType,
		Address:        testBoundAddress,
	})
	k.SetNameBinding(ctx, types.NameBinding{
		Credential:     testPhoneNumber,
		CredentialType: "email-contact-info",
		Address:        testBoundAddress,
	})

	_, err := ms.UnbindCredential(ctx, &types.MsgUnbindCredential{
		Creator:        testBoundAddress,
		CredentialType: testPhoneType,
		CredentialInfo: testPhoneNumber,
	})
	require.NoError(t, err)

	_, found := k.GetNameBinding(ctx, testPhoneNumber, "email-contact-info")
	require.True(t, found, "the other credential type's binding must be untouched")
}
