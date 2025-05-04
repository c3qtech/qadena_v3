package keeper

import (
	"github.com/c3qtech/qadena_v3/x/pricefeed/types"
)

var _ types.QueryServer = Keeper{}
