package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "github.com/c3qtech/qadena_v3/testutil/keeper"
	"github.com/c3qtech/qadena_v3/testutil/nullify"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNIntervalPublicKeyID(keeper keeper.Keeper, ctx context.Context, n int) []types.IntervalPublicKeyID {
	ctx = testCtx(ctx)
	items := make([]types.IntervalPublicKeyID, n)
	for i := range items {
		items[i].NodeID = strconv.Itoa(i)
		items[i].NodeType = strconv.Itoa(i)
		// A distinct, non-empty PubKID per item.  Left empty, every item shares the by-PubKID key
		// "/" -- so the duplicate-PubKID guard would fire on the second item, and any assertion
		// about the reverse index would be vacuous.
		items[i].PubKID = "pubkid" + strconv.Itoa(i)

		keeper.SetIntervalPublicKeyID(ctx, items[i])
	}
	return items
}

func TestIntervalPublicKeyIDGet(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNIntervalPublicKeyID(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetIntervalPublicKeyID(ctx,
			item.NodeID,
			item.NodeType,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestIntervalPublicKeyIDRemove(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNIntervalPublicKeyID(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveIntervalPublicKeyID(ctx,
			item.NodeID,
			item.NodeType,
		)
		_, found := keeper.GetIntervalPublicKeyID(ctx,
			item.NodeID,
			item.NodeType,
		)
		require.False(t, found)
	}
}

// The grace period for the SS interval key rests entirely on this: SetIntervalPublicKeyID is the
// only writer, so it is the only place that can record what a rotation replaced.  A transaction
// bound to the previous key is accepted; one bound to the key before that is not, and that bound is
// the whole point -- without it the rule would degrade to "accept any key this node ever saw".
func TestIntervalPublicKeyIDRotationRecordsPrevious(t *testing.T) {
	k, ctx := keepertest.QadenaKeeper(t)
	ctx = testCtx(ctx)

	set := func(pubKID string) types.IntervalPublicKeyID {
		k.SetIntervalPublicKeyID(ctx, types.IntervalPublicKeyID{
			NodeID:   types.SSNodeID,
			NodeType: types.SSNodeType,
			PubKID:   pubKID,
		})
		got, found := k.GetIntervalPublicKeyID(ctx, types.SSNodeID, types.SSNodeType)
		require.True(t, found)
		return got
	}

	// A first write has nothing to point back at.
	require.Equal(t, "", set("keyA").PreviousPubKID)

	// One rotation: keyA is still within its grace.
	require.Equal(t, "keyA", set("keyB").PreviousPubKID)

	// A second rotation expires keyA.  One-deep is deliberate -- the window only has to cover a
	// transaction in flight, and a client can never legitimately present a key older than the one
	// it read.
	require.Equal(t, "keyB", set("keyC").PreviousPubKID)

	// Rewriting the SAME key is not a rotation.  DeactivateServiceProvider does exactly this to
	// change only the service provider type; if it were treated as one, the record would name
	// itself as its own predecessor and the grace would cover a key that is still current.
	require.Equal(t, "keyB", set("keyC").PreviousPubKID)
}

func TestIntervalPublicKeyIDGetAll(t *testing.T) {
	keeper, ctx := keepertest.QadenaKeeper(t)
	items := createNIntervalPublicKeyID(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllIntervalPublicKeyID(ctx)),
	)
}
