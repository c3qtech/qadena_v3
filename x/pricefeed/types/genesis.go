package types

import (
	"fmt"
)

// DefaultIndex is the default global index
const DefaultIndex uint64 = 1

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		PostedPriceList: []PostedPrice{},
		// this line is used by starport scaffolding # genesis/types/default
		Params: DefaultParams(),
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	// Check for duplicated index in postedPrice
	postedPriceIndexMap := make(map[string]struct{})

	for _, elem := range gs.PostedPriceList {
		index := string(PostedPriceKey(elem.MarketId, elem.OracleAddress))
		if _, ok := postedPriceIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for postedPrice")
		}
		postedPriceIndexMap[index] = struct{}{}
	}
	// this line is used by starport scaffolding # genesis/types/validate

	return gs.Params.Validate()
}
