package types

import (
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
)

var _ paramtypes.ParamSet = (*Params)(nil)

// ParamKeyTable the param key table for launch module
func ParamKeyTable() paramtypes.KeyTable {
	return paramtypes.NewKeyTable().RegisterParamSet(&Params{})
}

// NewParams creates a new Params instance
func NewParams() Params {
	return Params{
		// ON BY DEFAULT.  Releasing a pioneer's published address when its validator leaves the
		// bonded set is the behavior every chain should have: the address is what makes a pioneer a
		// secret-share owner candidate for each NEW interval key, so leaving it published for an
		// unbonded or jailed validator keeps a node with no stake behind it -- and possibly no
		// machine behind it either -- in every future owner set.  A chain has to opt OUT of that,
		// not into it.
		//
		// THE ONE PLACE THIS DEFAULT DOES NOT REACH, and it is deliberate: a chain whose params
		// were stored BEFORE this field existed.  Those bytes carry no field 28, so they unmarshal
		// as false, and GetParams on an empty store likewise returns the zero value.  Both are
		// required, not regrettable -- a new binary replaying that chain's history has to reproduce
		// the app hashes the old one produced, and hooks that fired at a height where they
		// originally did not would fork the state root (the block-sync-from-genesis trap this repo
		// has already been bitten by once).  Such a chain turns it on by governance, which records
		// the change in state at a height, where replay can follow it.
		ReleaseAddressOnUnbond: true,

		// FOUR ROTATIONS (keyUpdateFrequency is 555 blocks), which is the grace a pioneer gets
		// between its validator leaving the bonded set and the SS audit being allowed to drop it
		// from the owner sets of keys it already holds.
		//
		// Sized against what it has to tolerate, not picked round: a downtime jail plus a restart
		// plus an unjail is minutes, while the audit only looks once per rotation and re-shares at
		// most maxSSResharesPerRotation keys when it does.  Less than a couple of rotations and a
		// node that blips between two audits can still lose ownership it never actually abandoned;
		// much more and the fleet spends days reporting custody it does not have.
		//
		// The same zero-value rule as the field above applies and is why this is not simply read
		// from the proto: a chain whose stored params predate field 30 unmarshals 0, which the
		// keeper reads as DISABLED rather than "no grace at all".  That is the safe direction --
		// an old chain keeps today's behaviour until governance sets this deliberately.
		SsDepartureGrace: 4 * 555,
	}
}

// DefaultParams returns a default set of parameters
func DefaultParams() Params {
	return NewParams()
}

// ParamSetPairs get the params.ParamSet
func (p *Params) ParamSetPairs() paramtypes.ParamSetPairs {
	return paramtypes.ParamSetPairs{}
}

// Validate lives in params_validate.go.  It used to return nil from here, which meant genesis
// validated nothing and MsgUpdateParams did not even call it.
