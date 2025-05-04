package keeper

import (
	"qadena/x/dsvs/types"
)

var _ types.QueryServer = Keeper{}
