package keeper

import (
	"qadena_v3/x/nameservice/types"
)

var _ types.QueryServer = Keeper{}
