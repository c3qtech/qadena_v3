package keeper

import (
	"qadena_v3/x/pricefeed/types"
)

var _ types.QueryServer = Keeper{}
