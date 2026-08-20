package keeper

// Regression test for the fork at height 30755.  See docs/TESTING-BACKLOG.md items 80 and 90.
//
// The enclave cannot produce {Status:false, Reason:PersonalInfoOK}: its reject branch is guarded
// by `if reason != PersonalInfoOK`, so every genuine rejection carries a NON-ZERO reason.  That
// reply arrived anyway, because a recovered panic returned the zero value with a nil error -- and
// this function read it as "the credential is bad" and convicted a well-formed credential with
// 1153, while a healthy peer accepted the same credential and computed a different app hash.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The embedded interface is nil, so any RPC this test does not model panics rather than quietly
// succeeding -- the same convention the watchdog fakes use.
type fakeValidatePersonalInfoClient struct {
	types.QadenaEnclaveClient
	reply *types.ValidatePersonalInfoReply
	err   error
}

func (f *fakeValidatePersonalInfoClient) ValidatePersonalInfo(
	_ context.Context, _ *types.MsgCreateCredential, _ ...grpc.CallOption,
) (*types.ValidatePersonalInfoReply, error) {
	return f.reply, f.err
}

func TestEnclaveValidatePersonalInfoReplies(t *testing.T) {
	cases := map[string]struct {
		reply       *types.ValidatePersonalInfoReply
		wantErr     bool
		wantConvict bool // true = blamed the CREDENTIAL (1153)
	}{
		"a genuine rejection convicts the credential": {
			reply:       &types.ValidatePersonalInfoReply{Status: false, Reason: int32(c.PersonalInfoInvalidGender)},
			wantErr:     true,
			wantConvict: true,
		},
		"a valid credential passes": {
			reply:   &types.ValidatePersonalInfoReply{Status: true},
			wantErr: false,
		},
		// The height 30755 reply.  Must NOT be read as a verdict.
		"a zero-value reply is an enclave fault, not a verdict": {
			reply:       &types.ValidatePersonalInfoReply{Status: false, Reason: int32(c.PersonalInfoOK)},
			wantErr:     true,
			wantConvict: false,
		},
		"a nil reply is an enclave fault, not a verdict": {
			reply:       nil,
			wantErr:     true,
			wantConvict: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			withEnclaveClient(t, &fakeValidatePersonalInfoClient{reply: tc.reply})

			err := Keeper{}.EnclaveValidatePersonalInfo(testSDKContext(), &types.MsgCreateCredential{})

			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			if tc.wantConvict {
				require.True(t, errors.Is(err, types.ErrInvalidPersonalInfo),
					"a real rejection should still convict the credential")
			} else {
				require.False(t, errors.Is(err, types.ErrInvalidPersonalInfo),
					"a malformed reply MUST NOT be reported as an invalid credential -- that is the fork")
				require.True(t, errors.Is(err, types.ErrGenericEnclave),
					"it should be reported as an enclave fault")
			}
		})
	}
}
