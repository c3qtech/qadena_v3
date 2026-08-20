package main

// Regression tests for the fork at height 30755, where a receiving enclave cached its Shamir
// SHARE into the PRIVATE KEY cache.  See docs/TESTING-BACKLOG.md items 80, 90 and 91.
//
// The bug survived from the first commit because it is only wrong ABOVE THREE OWNERS: addSSShare
// hands every owner the whole key at threshold 1 and only splits at 4+, so caching "my share" was
// correct for the fleet's entire life until a fourth pioneer became addressable.  These tests
// therefore cover BOTH sides of that boundary -- a test that only exercised the unsplit case would
// have passed against the broken code.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// A real Shamir share is one byte longer than the secret it splits: 65 bytes, 130 hex chars,
// against a private key's 32 bytes and 64 hex chars.  That length difference IS the bug.
const fakeShare130 = "ab" // repeated below

func aShare() string { return strings.Repeat(fakeShare130, 65) }
func aKey() string   { return strings.Repeat("cd", 32) }

// newSSTestServer returns a server that believes it is pioneerID and can decrypt shares addressed
// to it, plus the enclave public key to encrypt those shares with.
func newSSTestServer(t *testing.T, pioneerID string) (*qadenaServer, string) {
	t.Helper()
	s := newTestEnclaveServer(t)

	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	enclavePubK := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	s.setPrivateEnclaveParamsEnclaveInfo("", k.Hex(), enclavePubK)
	s.setPrivateEnclaveParamsPioneerInfo(pioneerID, "wallet-"+pioneerID, "", "", "")
	return s, enclavePubK
}

// broadcastFor builds the SetPublicKey message the key generator sends to every owner.
func broadcastFor(pubKID string, owners []string, me, myValue, enclavePubK string) *types.PublicKey {
	shares := make([]*types.Share, 0, len(owners))
	for _, o := range owners {
		v := "someone-elses-share"
		if o == me {
			v = myValue
		}
		shares = append(shares, &types.Share{
			PioneerID:       o,
			EncEnclaveShare: c.MarshalAndBEncrypt(enclavePubK, v),
		})
	}
	return &types.PublicKey{PubKID: pubKID, PubKType: types.EnclavePubKType, PubK: "unused", Shares: shares}
}

// FOUR owners means getThreshold == 2, which means addSSShare really did shamir.Split and what
// arrives is a SHARE.  Caching it as the private key is what forked the chain.
func TestSetPublicKeyDoesNotCacheAShareAsThePrivateKey(t *testing.T) {
	owners := []string{"pioneer1", "pioneer2", "pioneer3", "pioneer4"}
	require.Equal(t, 2, getThreshold(len(owners)), "premise: four owners must be a SPLIT key")

	s, pub := newSSTestServer(t, "pioneer2")
	share := aShare()

	_, err := s.SetPublicKey(context.Background(), broadcastFor("split-key", owners, "pioneer2", share, pub))
	require.NoError(t, err)

	// The share belongs in the share store...
	stored, found := s.getShare("split-key")
	require.True(t, found, "the share should still be recorded in the share store")
	require.Equal(t, share, stored)

	// ...and must NOT be sitting in the private key cache, where getSSPrivK would hand it to
	// ScalarMult as a 65-byte scalar and panic.
	cached, found := s.getPrivKCache("split-key")
	require.False(t, found && cached == share, "the SHARE was cached as the private key -- this is the height 30755 bug")
	require.Empty(t, cached, "the cache must be left empty so getSSPrivK reconstructs from shares")
}

// ONE owner means getThreshold == 1, and addSSShare hands out the WHOLE key rather than splitting
// (hashicorp's shamir.Split refuses a threshold below 2).  Here "my share" really is the key, and
// caching it is correct -- the behaviour every release before the fix depended on.
func TestSetPublicKeyCachesTheKeyWhenItWasNotSplit(t *testing.T) {
	owners := []string{"pioneer1"}
	require.Equal(t, 1, getThreshold(len(owners)), "premise: one owner must be an UNSPLIT key")

	s, pub := newSSTestServer(t, "pioneer1")
	key := aKey()

	_, err := s.SetPublicKey(context.Background(), broadcastFor("unsplit-key", owners, "pioneer1", key, pub))
	require.NoError(t, err)

	cached, found := s.getPrivKCache("unsplit-key")
	require.True(t, found, "an unsplit key must still be cached on receipt")
	require.Equal(t, key, cached)
}

// getSSPrivK must never hand back a cached value that is not a key, so a node poisoned before the
// fix existed repairs itself rather than panicking forever.
func TestGetSSPrivKDiscardsACacheEntryThatIsNotAKey(t *testing.T) {
	s := newTestEnclaveServer(t)
	poison := aShare()
	s.setPrivKCache("poisoned", poison)

	got := s.getSSPrivK("poisoned")

	require.NotEqual(t, poison, got, "returned the poisoned entry -- it would panic in ScalarMult")
	// No owners are recorded, so reconstruction cannot succeed; returning empty is the correct
	// failure.  The point is that it did not return 65 bytes.
	require.Empty(t, got)
}

func TestIsPrivKHex(t *testing.T) {
	cases := map[string]struct {
		in   string
		want bool
	}{
		"a real 32-byte key":     {aKey(), true},
		"a 65-byte Shamir share": {aShare(), false},
		"empty":                  {"", false},
		"not hex":                {strings.Repeat("zz", 32), false},
		"31 bytes":               {strings.Repeat("ab", 31), false},
		"33 bytes":               {strings.Repeat("ab", 33), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { require.Equal(t, tc.want, isPrivKHex(tc.in)) })
	}
}

// The interceptor used to call status.Errorf(status.Code(err), ...) while err was still nil.
// status.Code(nil) is codes.OK, and status.Errorf with codes.OK returns NIL -- so a panicking
// handler produced a zero-value reply and NO error, which the keeper read as a verdict.
func TestPanicRecoveryInterceptorReturnsAnError(t *testing.T) {
	info := &grpc.UnaryServerInfo{FullMethod: "/qadena.qadena.QadenaEnclave/ValidatePersonalInfo"}

	resp, err := panicRecoveryInterceptor(context.Background(), nil, info,
		func(context.Context, any) (any, error) { panic("can't handle scalars > 256 bits") })

	require.Error(t, err, "a panicking handler MUST NOT come back as a nil error")
	require.Nil(t, resp, "a panicking handler must not return a usable reply")
	require.Equal(t, codes.Internal, status.Code(err))
	require.Contains(t, err.Error(), "ValidatePersonalInfo", "the error should name the method that panicked")
}
