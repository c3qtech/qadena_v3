package types

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func init() {
	// The binary configures the qadena bech32 prefix; the types test package does not.
	sdk.GetConfig().SetBech32PrefixForAccount("qadena", "qadenapub")
}

func validShare(id string) *Share {
	return &Share{PioneerID: id, EncEnclaveShare: []byte("some-encrypted-share")}
}

func TestMsgPioneerUpdatePublicKeyValidateBasic(t *testing.T) {
	good := "qadena1us04k44mpxw3zpyv08fyq07gnz6e7qurxlv9jg"
	sig := make([]byte, 70)

	base := func() *MsgPioneerUpdatePublicKey {
		return NewMsgPioneerUpdatePublicKey(good, "pubkid", "transaction",
			[]*Share{validShare("p1"), validShare("p2")}, sig, []byte("report"))
	}

	require.NoError(t, base().ValidateBasic())

	t.Run("bad creator", func(t *testing.T) {
		m := base()
		m.Creator = "not-bech32"
		require.Error(t, m.ValidateBasic())
	})
	t.Run("empty pubKID", func(t *testing.T) {
		m := base()
		m.PubKID = ""
		require.Error(t, m.ValidateBasic())
	})
	t.Run("zero shares", func(t *testing.T) {
		m := base()
		m.Shares = nil
		require.Error(t, m.ValidateBasic())
	})
	t.Run("too many shares", func(t *testing.T) {
		m := base()
		m.Shares = make([]*Share, MaxReshareShares+1)
		for i := range m.Shares {
			m.Shares[i] = validShare("p" + string(rune('a'+i)))
		}
		require.Error(t, m.ValidateBasic())
	})
	t.Run("duplicate owner", func(t *testing.T) {
		m := base()
		m.Shares = []*Share{validShare("dup"), validShare("dup")}
		require.Error(t, m.ValidateBasic(), "a duplicate is a repeated Shamir x-coordinate")
	})
	t.Run("empty owner id", func(t *testing.T) {
		m := base()
		m.Shares = []*Share{validShare("p1"), {PioneerID: "", EncEnclaveShare: []byte("x")}}
		require.Error(t, m.ValidateBasic())
	})
	t.Run("oversize share blob", func(t *testing.T) {
		m := base()
		m.Shares = []*Share{{PioneerID: "p1", EncEnclaveShare: make([]byte, MaxReshareShareBytes+1)}}
		require.Error(t, m.ValidateBasic())
	})
	t.Run("empty share blob", func(t *testing.T) {
		m := base()
		m.Shares = []*Share{{PioneerID: "p1", EncEnclaveShare: nil}}
		require.Error(t, m.ValidateBasic())
	})
	t.Run("sig too short", func(t *testing.T) {
		m := base()
		m.PossessionSig = []byte{1, 2}
		require.Error(t, m.ValidateBasic())
	})
	t.Run("sig too long", func(t *testing.T) {
		m := base()
		m.PossessionSig = make([]byte, MaxPossessionSigLen+1)
		require.Error(t, m.ValidateBasic())
	})
}
