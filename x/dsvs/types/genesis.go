package types

import (
	"fmt"
)

// DefaultIndex is the default global index
const DefaultIndex uint64 = 1

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		DocumentHashList:        []DocumentHash{},
		DocumentList:            []Document{},
		AuthorizedSignatoryList: []AuthorizedSignatory{},
		// this line is used by starport scaffolding # genesis/types/default
		Params: DefaultParams(),
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	// Check for duplicated index in documentHash
	documentHashIndexMap := make(map[string]struct{})

	for _, elem := range gs.DocumentHashList {
		index := string(elem.Hash)
		if _, ok := documentHashIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for documentHash")
		}
		documentHashIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in document
	documentIndexMap := make(map[string]struct{})

	for _, elem := range gs.DocumentList {
		index := string(DocumentKey(elem.DocumentID))
		if _, ok := documentIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for document")
		}
		documentIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in authorizedSignatory
	authorizedSignatoryIndexMap := make(map[string]struct{})

	for _, elem := range gs.AuthorizedSignatoryList {
		index := string(AuthorizedSignatoryKey(elem.WalletID))
		if _, ok := authorizedSignatoryIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for authorizedSignatory")
		}
		authorizedSignatoryIndexMap[index] = struct{}{}
	}
	// this line is used by starport scaffolding # genesis/types/validate

	return gs.Params.Validate()
}
