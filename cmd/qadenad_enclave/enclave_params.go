package main

import (
	"qadena_v3/x/qadena/types"
)

// these are never shared with other enclaves
type PrivateEnclaveParams struct {
	PioneerID         string
	PioneerWalletID   string
	PioneerArmorPrivK string
	PioneerPrivK      string
	PioneerPubK       string

	EnclaveArmorPrivK string
	EnclavePrivK      string
	EnclavePubK       string

	PioneerIsValidator       bool
	PioneerExternalIPAddress string

	SealedTableSharedSecret []byte
}

// make getters for PrivateEnclaveParams that are thread ssafe

func (s *qadenaServer) getPrivateEnclaveParamsPioneerID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.PioneerID
}

func (s *qadenaServer) getPrivateEnclaveParamsPioneerWalletID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.PioneerWalletID
}

func (s *qadenaServer) getPrivateEnclaveParamsPioneerArmorPrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.PioneerArmorPrivK
}

func (s *qadenaServer) getPrivateEnclaveParamsPioneerPrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.PioneerPrivK
}

func (s *qadenaServer) getPrivateEnclaveParamsPioneerPubK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.PioneerPubK
}

func (s *qadenaServer) getPrivateEnclaveParamsEnclaveArmorPrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.EnclaveArmorPrivK
}

func (s *qadenaServer) getPrivateEnclaveParamsEnclavePrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.EnclavePrivK
}

func (s *qadenaServer) getPrivateEnclaveParamsEnclavePubK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.EnclavePubK
}

func (s *qadenaServer) getPrivateEnclaveParamsSealedTableSharedSecret() []byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.SealedTableSharedSecret
}

func (s *qadenaServer) getPrivateEnclaveParamsPioneerIsValidator() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.PioneerIsValidator
}

func (s *qadenaServer) getPrivateEnclaveParamsPioneerExternalIPAddress() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.privateEnclaveParams.PioneerExternalIPAddress
}

// make setters for PrivateEnclaveParams that are thread safe

func (s *qadenaServer) setPrivateEnclaveParamsPioneerInfo(pioneerID string, pioneerWalletID string, pioneerArmorPrivK string, pioneerPrivK string, pioneerPubK string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.privateEnclaveParams.PioneerID = pioneerID
	s.privateEnclaveParams.PioneerWalletID = pioneerWalletID
	s.privateEnclaveParams.PioneerArmorPrivK = pioneerArmorPrivK
	s.privateEnclaveParams.PioneerPrivK = pioneerPrivK
	s.privateEnclaveParams.PioneerPubK = pioneerPubK
}

func (s *qadenaServer) setPrivateEnclaveParamsEnclaveInfo(enclaveArmorPrivK string, enclavePrivK string, enclavePubK string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.privateEnclaveParams.EnclaveArmorPrivK = enclaveArmorPrivK
	s.privateEnclaveParams.EnclavePrivK = enclavePrivK
	s.privateEnclaveParams.EnclavePubK = enclavePubK
}

func (s *qadenaServer) setPrivateEnclaveParamsSealedTableSharedSecret(sealedTableSharedSecret []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.privateEnclaveParams.SealedTableSharedSecret = sealedTableSharedSecret
}

func (s *qadenaServer) setPrivateEnclaveParamsPioneerIsValidator(pioneerIsValidator bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.privateEnclaveParams.PioneerIsValidator = pioneerIsValidator
}

func (s *qadenaServer) setPrivateEnclaveParamsPioneerExternalIPAddress(pioneerExternalIPAddress string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.privateEnclaveParams.PioneerExternalIPAddress = pioneerExternalIPAddress
}

// make getters for SharedEnclaveParams that are thread ssafe

func (s *qadenaServer) getSharedEnclaveParamsJarID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.JarID
}

func (s *qadenaServer) getSharedEnclaveParamsJarPubK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.JarPubK
}

func (s *qadenaServer) getSharedEnclaveParamsJarPrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.JarPrivK
}

func (s *qadenaServer) getSharedEnclaveParamsJarArmorPrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.JarArmorPrivK
}

func (s *qadenaServer) getSharedEnclaveParamsRegulatorID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.RegulatorID
}

func (s *qadenaServer) getSharedEnclaveParamsRegulatorPubK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.RegulatorPubK
}

func (s *qadenaServer) getSharedEnclaveParamsRegulatorPrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.RegulatorPrivK
}

func (s *qadenaServer) getSharedEnclaveParamsRegulatorArmorPrivK() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.RegulatorArmorPrivK
}

func (s *qadenaServer) getSharedEnclaveParamsSSIntervalOwners() *types.EncryptableEnclaveSSOwnerMap {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.SSIntervalOwners
}

func (s *qadenaServer) getSharedEnclaveParamsSSIntervalPubKCache() *types.EncryptableEnclavePubKCacheMap {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sharedEnclaveParams.SSIntervalPubKCache
}

func (s *qadenaServer) setSharedEnclaveParamsRegulatorInfo(regulatorID string, regulatorPubK string, regulatorPrivK string, regulatorArmorPrivK string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.sharedEnclaveParams.RegulatorID = regulatorID
	s.sharedEnclaveParams.RegulatorPubK = regulatorPubK
	s.sharedEnclaveParams.RegulatorPrivK = regulatorPrivK
	s.sharedEnclaveParams.RegulatorArmorPrivK = regulatorArmorPrivK
}

func (s *qadenaServer) setSharedEnclaveParamsJarInfo(jarID string, jarPubK string, jarPrivK string, jarArmorPrivK string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.sharedEnclaveParams.JarID = jarID
	s.sharedEnclaveParams.JarPubK = jarPubK
	s.sharedEnclaveParams.JarPrivK = jarPrivK
	s.sharedEnclaveParams.JarArmorPrivK = jarArmorPrivK
}

func (s *qadenaServer) setSharedEnclaveParamsSSIntervalOwners(ssIntervalOwners *types.EncryptableEnclaveSSOwnerMap) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.sharedEnclaveParams.SSIntervalOwners = ssIntervalOwners
}

func (s *qadenaServer) setSharedEnclaveParamsSSIntervalPubKCache(ssIntervalPubKCache *types.EncryptableEnclavePubKCacheMap) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.sharedEnclaveParams.SSIntervalPubKCache = ssIntervalPubKCache
}
