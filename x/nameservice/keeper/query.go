package keeper

import (
	"qadena/x/nameservice/types"
)

var _ types.QueryServer = Keeper{}
