package types

import (
	"fmt"
)

// DefaultIndex is the default global index
const DefaultIndex uint64 = 1

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		CredentialList:            []Credential{},
		PublicKeyList:             []PublicKey{},
		WalletList:                []Wallet{},
		IntervalPublicKeyIDList:   []IntervalPublicKeyID{},
		PioneerJarList:            []PioneerJar{},
		JarRegulatorList:          []JarRegulator{},
		SuspiciousTransactionList: []SuspiciousTransaction{},
		ProtectKeyList:            []ProtectKey{},
		RecoverKeyList:            []RecoverKey{},
		EnclaveIdentityList:       []EnclaveIdentity{},
		// this line is used by starport scaffolding # genesis/types/default
		Params: DefaultParams(),
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	// Check for duplicated index in credential
	credentialIndexMap := make(map[string]struct{})

	for _, elem := range gs.CredentialList {
		index := string(CredentialKey(elem.CredentialID, elem.CredentialType))
		if _, ok := credentialIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for credential")
		}
		credentialIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in publicKey
	publicKeyIndexMap := make(map[string]struct{})

	for _, elem := range gs.PublicKeyList {
		index := string(PublicKeyKey(elem.PubKID, elem.PubKType))
		if _, ok := publicKeyIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for publicKey")
		}
		publicKeyIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in wallet
	walletIndexMap := make(map[string]struct{})

	for _, elem := range gs.WalletList {
		index := string(WalletKey(elem.WalletID))
		if _, ok := walletIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for wallet")
		}
		walletIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in intervalPublicKeyID
	intervalPublicKeyIDIndexMap := make(map[string]struct{})

	for _, elem := range gs.IntervalPublicKeyIDList {
		index := string(IntervalPublicKeyIDKey(elem.NodeID, elem.NodeType))
		if _, ok := intervalPublicKeyIDIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for intervalPublicKeyID")
		}
		intervalPublicKeyIDIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in pioneerJar
	pioneerJarIndexMap := make(map[string]struct{})

	for _, elem := range gs.PioneerJarList {
		index := string(PioneerJarKey(elem.PioneerID))
		if _, ok := pioneerJarIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for pioneerJar")
		}
		pioneerJarIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in jarRegulator
	jarRegulatorIndexMap := make(map[string]struct{})

	for _, elem := range gs.JarRegulatorList {
		index := string(JarRegulatorKey(elem.JarID))
		if _, ok := jarRegulatorIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for jarRegulator")
		}
		jarRegulatorIndexMap[index] = struct{}{}
	}
	// Check for duplicated ID in suspiciousTransaction
	suspiciousTransactionIdMap := make(map[uint64]bool)
	suspiciousTransactionCount := gs.GetSuspiciousTransactionCount()
	for _, elem := range gs.SuspiciousTransactionList {
		if _, ok := suspiciousTransactionIdMap[elem.Id]; ok {
			return fmt.Errorf("duplicated id for suspiciousTransaction")
		}
		if elem.Id >= suspiciousTransactionCount {
			return fmt.Errorf("suspiciousTransaction id should be lower or equal than the last id")
		}
		suspiciousTransactionIdMap[elem.Id] = true
	}
	// Check for duplicated index in protectKey
	protectKeyIndexMap := make(map[string]struct{})

	for _, elem := range gs.ProtectKeyList {
		index := string(ProtectKeyKey(elem.WalletID))
		if _, ok := protectKeyIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for protectKey")
		}
		protectKeyIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in recoverKey
	recoverKeyIndexMap := make(map[string]struct{})

	for _, elem := range gs.RecoverKeyList {
		index := string(RecoverKeyKey(elem.WalletID))
		if _, ok := recoverKeyIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for recoverKey")
		}
		recoverKeyIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in enclaveIdentity
	enclaveIdentityIndexMap := make(map[string]struct{})

	for _, elem := range gs.EnclaveIdentityList {
		index := string(EnclaveIdentityKey(elem.UniqueID))
		if _, ok := enclaveIdentityIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for enclaveIdentity")
		}
		enclaveIdentityIndexMap[index] = struct{}{}
	}
	// this line is used by starport scaffolding # genesis/types/validate

	return gs.Params.Validate()
}
