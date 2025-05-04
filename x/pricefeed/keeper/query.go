package keeper

import (
	"qadena/x/pricefeed/types"
)

var _ types.QueryServer = Keeper{}
