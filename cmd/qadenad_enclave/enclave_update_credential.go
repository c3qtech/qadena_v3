package main

// The enclave half of MsgUpdateCredential.  Structurally this is ClaimCredential with the
// existence check inverted -- claim rejects a credentialID that already exists, update requires
// one -- plus the change policy, the alias index, and one critical omission: it never writes
// wallet.credentialID.  That single difference is what keeps the user's wallet, balances, name
// bindings and recovery shares attached across a correction.

import (
	"context"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"

	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cosmos/gogoproto/proto"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// nameSubCredentialTypeByField maps the identity fields that have their own sub-credential to
// that sub-credential's type.  Birthdate and Gender have none: they live only in the
// personal-info row.
var nameSubCredentialTypeByField = map[string]string{
	c.UpdateFieldFirstName:  types.FirstNamePersonalInfoCredentialType,
	c.UpdateFieldMiddleName: types.MiddleNamePersonalInfoCredentialType,
	c.UpdateFieldLastName:   types.LastNamePersonalInfoCredentialType,
}

func nameForSubCredentialType(details *types.EncryptablePersonalInfoDetails, credentialType string) (string, bool) {
	switch credentialType {
	case types.FirstNamePersonalInfoCredentialType:
		return details.FirstName, true
	case types.MiddleNamePersonalInfoCredentialType:
		return details.MiddleName, true
	case types.LastNamePersonalInfoCredentialType:
		return details.LastName, true
	}
	return "", false
}

func (s *qadenaServer) UpdateCredential(ctx context.Context, in *types.EnclaveUpdateCredentialRequest) (*types.MsgUpdateCredentialResponse, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "UpdateCredential")
	} else {
		c.LoggerDebug(logger, "UpdateCredential "+c.PrettyPrint(in))
	}

	if in.Msg == nil {
		return nil, types.ErrCredentialUpdateRejected
	}
	msg := in.Msg

	// Two shapes are updatable: the personal-info row, whose three name sub-credentials ride along
	// inside the parms and whose changes are policed by the change policy; and a contact
	// credential, which is a single value with no identity hash behind it.  The name
	// sub-credentials are deliberately not updatable on their own -- they only ever move together
	// with the personal-info row they have to agree with.
	switch msg.CredentialType {
	case types.PersonalInfoCredentialType, types.PhoneContactCredentialType, types.EmailContactCredentialType:
	default:
		c.LoggerError(logger, "UpdateCredential does not support "+msg.CredentialType)
		return nil, types.ErrCredentialUpdateRejected
	}

	unprotoExtraParmsVShareBind := c.UnprotoizeVShareBindData(msg.UpdateCredentialExtraParmsVShareBind)

	var parms types.EncryptableUpdateCredentialExtraParms
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoExtraParmsVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoExtraParmsVShareBind.GetSSIntervalPubKID()), unprotoExtraParmsVShareBind, msg.EncUpdateCredentialExtraParmsVShare, &parms)
	if err != nil {
		c.LoggerError(logger, "Can't decrypt updateCredentialExtraParms")
		return nil, err
	}

	if !s.RealEnclave {
		c.LoggerDebug(logger, "updateCredentialExtraParms "+c.PrettyPrint(parms))
	}

	wallet, found := s.getWallet(parms.WalletID)
	if !found {
		return nil, types.ErrWalletNotExists
	}

	if wallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] != types.QadenaRealWallet {
		c.LoggerError(logger, "can't update a credential on a subwallet")
		return nil, types.ErrInvalidWallet
	}

	requiredChainCCPubK := make([]c.VSharePubKInfo, 0)
	requiredChainCCPubK, err = s.enclaveAppendRequiredChainCCPubK(requiredChainCCPubK, "", false)
	if err != nil {
		c.LoggerError(logger, "RequiredChainCCPubK err "+err.Error())
		return nil, err
	}
	optionalServiceProvidersCCPubK := make([]c.VSharePubKInfo, 0)
	optionalServiceProvidersCCPubK, err = s.enclaveAppendOptionalServiceProvidersCCPubK(optionalServiceProvidersCCPubK, wallet.ServiceProviderID, []string{types.FinanceServiceProvider})
	if err != nil {
		c.LoggerError(logger, "OptionalServiceProvidersCCPubK err "+err.Error())
		return nil, err
	}

	credentialCCPubK := make([]c.VSharePubKInfo, 0)
	credentialCCPubK = append(credentialCCPubK, requiredChainCCPubK...)
	credentialCCPubK = append(credentialCCPubK, optionalServiceProvidersCCPubK...)

	var sdkctx sdk.Context = sdk.Context{}.WithLogger(logger)

	if !c.ValidateVShare(sdkctx, parms.GetCredentialInfoVShareBind(), parms.EncCredentialInfoVShare, credentialCCPubK) {
		c.LoggerError(logger, "invalid credential info vshare")
		return nil, types.ErrInvalidVShare
	}

	// Only personal-info carries an identity hash; a contact credential has nothing to hash, and
	// claim leaves the field empty for those too.
	if msg.CredentialType == types.PersonalInfoCredentialType {
		if !c.ValidateVShare(sdkctx, parms.CredentialHashVShareBind, parms.EncCredentialHashVShare, credentialCCPubK) {
			c.LoggerError(logger, "invalid credential hash vshare")
			return nil, types.ErrInvalidVShare
		}
	}

	// the row being corrected.  Claim requires this to be absent; update requires it to exist.
	oldCredential, found := s.getCredential(msg.CredentialID, msg.CredentialType)
	if !found {
		c.LoggerError(logger, "credential to update does not exist "+msg.CredentialID)
		return nil, types.ErrCredentialNotExists
	}

	// Ownership, checked against both rows.  The keeper already checked this in the clear, but
	// the keeper's view is the chain's copy; this is the enclave's own.
	if oldCredential.WalletID != parms.WalletID {
		c.LoggerError(logger, "credential "+msg.CredentialID+" is owned by "+oldCredential.WalletID+", not "+parms.WalletID)
		return nil, types.ErrCredentialUpdateNotOwner
	}
	if wallet.CredentialID != msg.CredentialID {
		c.LoggerError(logger, "wallet "+parms.WalletID+" points at credential "+wallet.CredentialID+", not "+msg.CredentialID)
		return nil, types.ErrCredentialUpdateNotOwner
	}

	// the identity provider's freshly issued, still ownerless credential carrying the corrected
	// data.  Exactly the same lookup a claim does.
	ipCredential, err := s.findOwnerlessIPCredential(parms.FindCredentialPC, msg.CredentialType)
	if err != nil {
		return nil, err
	}

	// Pedersen checks, identical to claim: the new commitment must be derived from the identity
	// provider's, and the user must control the wallet it is being attached to.
	if err := s.validateUpdatePedersenCommits(ipCredential, wallet, parms.NewCredentialPC, parms.ZeroPC, parms.ClaimPC); err != nil {
		return nil, err
	}

	if msg.CredentialType != types.PersonalInfoCredentialType {
		return s.updateContactInfoCredential(msg, &parms, oldCredential, ipCredential)
	}

	// decrypt the corrected personal info and check it against the commitment the client sent
	unprotoCredentialInfoVShareBind := c.UnprotoizeVShareBindData(parms.CredentialInfoVShareBind)
	var newPI types.EncryptablePersonalInfo
	err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoCredentialInfoVShareBind.GetSSIntervalPubKID()), unprotoCredentialInfoVShareBind, parms.EncCredentialInfoVShare, &newPI)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt the corrected credential")
		return nil, err
	}

	if err := s.compareCredentialPC(newPI.Details, newPI.PIN, parms.NewCredentialPC); err != nil {
		return nil, err
	}

	// decrypt the row being replaced.  The old plaintext is the only trustworthy input to the
	// change policy and to the old identity hash -- never take either from the client.
	unprotoOldInfoVShareBind := c.UnprotoizeVShareBindData(oldCredential.CredentialInfoVShareBind)
	var oldPI types.EncryptablePersonalInfo
	err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoOldInfoVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoOldInfoVShareBind.GetSSIntervalPubKID()), unprotoOldInfoVShareBind, oldCredential.EncCredentialInfoVShare, &oldPI)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt the credential being updated "+msg.CredentialID)
		return nil, err
	}

	policy := c.UpdatePolicyFromParams(in.Params)
	verdict, err := c.ClassifyPersonalInfoUpdate(oldPI.Details, newPI.Details, policy)
	if err != nil {
		c.LoggerError(logger, "update rejected by policy: "+err.Error())
		return nil, types.ErrCredentialUpdateRejected
	}

	c.LoggerDebug(logger, "update verdict kind="+verdict.Kind.String()+" fields="+strings.Join(verdict.ChangedFields, ","))

	oldCredentialHash := c.CreateCredentialHash(oldPI.Details)

	// Lazily seed the history from the hash just recomputed above.  Hashes cannot be enumerated
	// backwards out of the forward index, so this is how credentials that predate the alias
	// index acquire one -- exactly, for free, and without an upgrade handler.
	history, found := s.getCredentialIdentityHistory(msg.CredentialID)
	if !found {
		history = types.EncryptableCredentialIdentityHistory{Hashes: []string{oldCredentialHash}}
		// A SEEDED HISTORY CARRIES NO LastUpdateHeight, SO THE COOL-DOWN BELOW CANNOT APPLY TO
		// THIS UPDATE.  That is intended for a credential that predates the alias index -- it has
		// no history through no fault of its own, and refusing it would be worse.  It is NOT
		// intended for a credential that has already been updated: UpdateGeneration counts those,
		// so a generation above zero with no history means the record was LOST, and this path then
		// silently disables the rate limit for the very credential it is meant to protect.
		//
		// Say so loudly.  Backlog 76: a second hash-changing update landed three blocks after the
		// first (h=11713, h=11716) against a 10000-block cool-down, and nothing in the log named a
		// cause, because the only marker was this line at Debug.
		if oldCredential.UpdateGeneration > 0 {
			c.LoggerError(logger, "identity history MISSING for "+msg.CredentialID+
				" at update generation "+strconv.FormatUint(uint64(oldCredential.UpdateGeneration), 10)+
				" -- seeding a fresh record, which SKIPS the update cool-down for this update")
		} else {
			c.LoggerDebug(logger, "seeded identity history for "+msg.CredentialID)
		}
	} else if history.LastUpdateHeight == 0 {
		// Found, but with no height recorded: same effect, different cause.  Worth naming
		// separately, because it points at the WRITE side rather than the lookup.
		c.LoggerError(logger, "identity history for "+msg.CredentialID+
			" has no LastUpdateHeight at update generation "+strconv.FormatUint(uint64(oldCredential.UpdateGeneration), 10)+
			" -- the update cool-down cannot apply")
	} else {
		c.LoggerInfo(logger, "update cool-down check: "+msg.CredentialID+
			" last updated at height "+strconv.FormatInt(history.LastUpdateHeight, 10)+
			", now "+strconv.FormatInt(in.BlockHeight, 10))
	}

	if err := checkUpdateLimits(history, verdict, c.UpdateLimitsFromParams(in.Params), in.BlockHeight); err != nil {
		c.LoggerError(logger, "update rate limited: "+err.Error())
		return nil, types.ErrCredentialUpdateRateLimited
	}

	// the client tells us the new hash; recompute it and refuse to take its word
	newCredentialHash, err := s.decryptCredentialHash(unprotoExtraParmsVShareBind, parms.CredentialHashVShareBind, parms.EncCredentialHashVShare)
	if err != nil {
		return nil, err
	}
	checkCredentialHash := c.CreateCredentialHash(newPI.Details)
	if newCredentialHash != checkCredentialHash {
		c.LoggerError(logger, "credentialHash != checkCredentialHash")
		return nil, types.ErrGenericPedersen
	}

	if verdict.HashChanged != (newCredentialHash != oldCredentialHash) {
		// the policy engine and CreateCredentialHash disagree about whether the identity moved,
		// which would mean one of them is reading a field the other is not
		c.LoggerError(logger, "policy verdict disagrees with the recomputed hashes")
		return nil, types.ErrCredentialUpdateRejected
	}

	// This is what stops a user correcting *into* somebody else's identity: the new hash must be
	// unclaimed, or already point back at this very credential (an idempotent replay).
	if existing, exists := s.getCredentialByHash(newCredentialHash); exists && existing.CredentialID != msg.CredentialID {
		c.LoggerError(logger, "credential hash already belongs to "+existing.CredentialID)
		return nil, types.ErrCredentialExists
	}

	// Validate the sub-updates before writing anything.  Every name the policy says changed must
	// have one, so "personal-info and its three name sub-credentials agree" is an enclave
	// invariant rather than a convention the client is trusted to follow.
	subCredentials, err := s.validateSubUpdates(parms.SubUpdates, msg.CredentialID, newPI.Details, verdict, wallet)
	if err != nil {
		return nil, err
	}

	// ---- everything below this line mutates state ----

	newCredential := oldCredential
	newCredential.CredentialPedersenCommit = parms.NewCredentialPC
	newCredential.EncCredentialInfoVShare = parms.EncCredentialInfoVShare
	newCredential.CredentialInfoVShareBind = parms.CredentialInfoVShareBind
	newCredential.EncCredentialHashVShare = parms.EncCredentialHashVShare
	newCredential.CredentialHashVShareBind = parms.CredentialHashVShareBind
	// the row is owned, so it must not be findable by claim code any more
	newCredential.FindCredentialPedersenCommit = nil
	newCredential.UpdateGeneration = oldCredential.UpdateGeneration + 1
	// CredentialID, CredentialType and WalletID are deliberately carried over unchanged, as are
	// providerWalletID/referenceCredentialID/identityOwnerWalletID: those record who originally
	// issued and paid for this identity, which a correction does not change.

	s.setCredential(newCredential.CredentialID, newCredential.CredentialType, newCredential)

	for _, sub := range subCredentials {
		s.setCredential(sub.CredentialID, sub.CredentialType, sub)
	}

	if verdict.HashChanged {
		history = s.addCredentialHashAlias(newCredentialHash, msg.CredentialID, history)
		if verdict.Kind == c.UpdateKindLifeEvent {
			history.LifeEventCount++
		}
	}
	history.LastUpdateHeight = in.BlockHeight
	s.setCredentialIdentityHistory(msg.CredentialID, history)

	// NOTE: no setWallet.  wallet.CredentialID must survive an update untouched -- this is the
	// single most important difference from ClaimCredential.

	// consume the identity provider's row.  "UPDATED" rather than "CLAIMED" so the two flows stay
	// distinguishable in logs and audits.
	// The PCXY index entry is left in place, exactly as ClaimCredential leaves it: the sentinel
	// walletID is what makes the row unusable, and findOwnerlessIPCredential rejects on it.
	ipCredential.WalletID = types.UpdatedCredentialWalletID
	s.setCredential(ipCredential.CredentialID, ipCredential.CredentialType, ipCredential)

	for _, sub := range parms.SubUpdates {
		ipSub, err := s.findOwnerlessIPCredential(sub.FindCredentialPC, sub.CredentialType)
		if err != nil {
			// already validated above, so this cannot fail; if it somehow does, the whole
			// transaction is rolled back by TransactionComplete(false)
			return nil, err
		}
		ipSub.WalletID = types.UpdatedCredentialWalletID
		s.setCredential(ipSub.CredentialID, ipSub.CredentialType, ipSub)
	}

	c.LoggerDebug(logger, "UpdateCredential ok, generation "+c.PrettyPrint(newCredential.UpdateGeneration))

	return &types.MsgUpdateCredentialResponse{}, nil
}

// updateContactInfoCredential replaces a phone or email credential in place.
//
// There is no change policy here and there is nothing to classify.  A contact credential is a
// single opaque value with no identity hash behind it, so "is this a correction or a substitution?"
// has no meaning: a new phone number is simply a new phone number, and the only thing that makes it
// trustworthy is that an authenticated identity provider issued it.  Nothing is rate limited for
// the same reason -- the identity is untouched -- and the fee plus the identity provider's own
// createCredentialFee are what stop this being cheap to spam.
//
// The user's name bindings are NOT touched.  A binding is keyed by the cleartext contact
// (x/nameservice), so the old value keeps resolving to this wallet until the owner unbinds it with
// MsgUnbindCredential from the ephemeral wallet that bound it.  The enclave cannot do that for
// them: it does not know which ephemeral wallets exist, and they are the signers.
func (s *qadenaServer) updateContactInfoCredential(msg *types.MsgUpdateCredential, parms *types.EncryptableUpdateCredentialExtraParms, oldCredential types.Credential, ipCredential types.Credential) (*types.MsgUpdateCredentialResponse, error) {
	if len(parms.SubUpdates) > 0 {
		c.LoggerError(logger, "a contact credential has no sub-credentials")
		return nil, types.ErrCredentialUpdateRejected
	}

	unprotoNewBind := c.UnprotoizeVShareBindData(parms.CredentialInfoVShareBind)
	var newContact types.EncryptableSingleContactInfo
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoNewBind.GetSSIntervalPubKID()), s.getPubK(unprotoNewBind.GetSSIntervalPubKID()), unprotoNewBind, parms.EncCredentialInfoVShare, &newContact)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt the corrected contact credential")
		return nil, err
	}

	if newContact.Details == nil || newContact.Details.Contact == "" {
		c.LoggerError(logger, "a contact credential may not be emptied; remove it instead")
		return nil, types.ErrCredentialUpdateRejected
	}

	if err := s.compareCredentialPC(newContact.Details, newContact.PIN, parms.NewCredentialPC); err != nil {
		return nil, err
	}

	newCredential := oldCredential
	newCredential.CredentialPedersenCommit = parms.NewCredentialPC
	newCredential.EncCredentialInfoVShare = parms.EncCredentialInfoVShare
	newCredential.CredentialInfoVShareBind = parms.CredentialInfoVShareBind
	newCredential.FindCredentialPedersenCommit = nil
	newCredential.UpdateGeneration = oldCredential.UpdateGeneration + 1

	s.setCredential(newCredential.CredentialID, newCredential.CredentialType, newCredential)

	// no setWallet: wallet.CredentialID is unchanged, as in every update

	ipCredential.WalletID = types.UpdatedCredentialWalletID
	s.setCredential(ipCredential.CredentialID, ipCredential.CredentialType, ipCredential)

	c.LoggerDebug(logger, "updated "+msg.CredentialType+" to generation "+strconv.FormatUint(uint64(newCredential.UpdateGeneration), 10))

	return &types.MsgUpdateCredentialResponse{}, nil
}

// ClaimUpdatedCredential re-points one ephemeral wallet's accept-list at the credentials as they
// stand now.  An ephemeral wallet's accept-list pins each credential's Pedersen commitment at the
// time it was published, so an UpdateCredential that moves a name leaves every ephemeral wallet
// accepting the corresponding sub-credential failing closed until its owner runs this.
func (s *qadenaServer) ClaimUpdatedCredential(ctx context.Context, msg *types.MsgClaimUpdatedCredential) (*types.MsgClaimUpdatedCredentialResponse, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "ClaimUpdatedCredential")
	} else {
		c.LoggerDebug(logger, "ClaimUpdatedCredential "+c.PrettyPrint(msg))
	}

	ephWalletID := msg.Creator

	ephWallet, found := s.getWallet(ephWalletID)
	if !found {
		return nil, types.ErrWalletNotExists
	}

	if ephWallet.EphemeralWalletAmountCount[types.QadenaTokenDenom] == types.QadenaRealWallet {
		c.LoggerError(logger, "a real wallet has no accept-list to refresh")
		return nil, types.ErrInvalidWallet
	}

	// Prove control of the real wallet the same way ValidateCredential does: unwrap the ephemeral
	// wallet's own createWallet vshare, which only somebody holding a key to the real wallet could
	// have produced, and take the real walletID from inside it.  The signer being the ephemeral
	// wallet is not by itself evidence of anything.
	unprotoEphCreateWalletVShareBind := c.UnprotoizeVShareBindData(ephWallet.CreateWalletVShareBind)
	var vShareWallet types.EncryptableCreateWallet
	err := c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoEphCreateWalletVShareBind.GetSSIntervalPubKID()), s.getPubK(unprotoEphCreateWalletVShareBind.GetSSIntervalPubKID()), unprotoEphCreateWalletVShareBind, ephWallet.EncCreateWalletVShare, &vShareWallet)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt the ephemeral wallet's createWallet vshare")
		return nil, err
	}

	if vShareWallet.DstEWalletID == nil {
		c.LoggerError(logger, "ephemeral wallet has no destination wallet")
		return nil, types.ErrInvalidCreateWallet
	}

	realWallet, found := s.getWallet(vShareWallet.DstEWalletID.WalletID)
	if !found {
		return nil, types.ErrWalletNotExists
	}

	if realWallet.CredentialID == "" {
		c.LoggerError(logger, "real wallet "+realWallet.WalletID+" has no credential")
		return nil, types.ErrCredentialNotExists
	}

	// Every commitment offered must be the one the credential actually carries right now.  This is
	// what keeps the message from being a way to publish an arbitrary accept-list: the caller can
	// only ever re-state the truth.
	var vcs types.EncryptableValidatedCredentials
	unprotoAcceptBind := c.UnprotoizeVShareBindData(msg.AcceptValidatedCredentialsVShareBind)
	err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoAcceptBind.GetSSIntervalPubKID()), s.getPubK(unprotoAcceptBind.GetSSIntervalPubKID()), unprotoAcceptBind, msg.EncAcceptValidatedCredentialsVShare, &vcs)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt the accept-validated-credentials vshare")
		return nil, err
	}

	for i := range vcs.Credentials {
		vc := vcs.Credentials[i]
		credential, found := s.getCredential(realWallet.CredentialID, vc.CredentialType)
		if !found {
			c.LoggerError(logger, "could not find credential "+realWallet.CredentialID+" "+vc.CredentialType)
			return nil, types.ErrCredentialNotExists
		}
		if !c.ComparePedersenCommit(c.UnprotoizeBPedersenCommit(vc.CredentialPC), c.UnprotoizeBPedersenCommit(credential.CredentialPedersenCommit)) {
			c.LoggerError(logger, "accept-list commitment for "+vc.CredentialType+" is not the credential's current one")
			return nil, types.ErrInvalidCredential
		}
		c.LoggerDebug(logger, "refreshed accept-list entry "+vc.CredentialType)
	}

	ephWallet.EncAcceptValidatedCredentialsVShare = msg.EncAcceptValidatedCredentialsVShare
	ephWallet.AcceptValidatedCredentialsVShareBind = msg.AcceptValidatedCredentialsVShareBind
	s.setWallet(ephWallet)

	return &types.MsgClaimUpdatedCredentialResponse{}, nil
}

// findOwnerlessIPCredential resolves the identity provider's freshly issued credential from the
// claim code's find-PC and insists it has not already been consumed.
func (s *qadenaServer) findOwnerlessIPCredential(findCredentialPC *types.BPedersenCommit, credentialType string) (types.Credential, error) {
	if findCredentialPC == nil {
		c.LoggerError(logger, "missing findCredentialPC for "+credentialType)
		return types.Credential{}, types.ErrCredentialNotExists
	}

	findCredentialXYCBytes := c.UnprotoizeBPedersenCommit(findCredentialPC).C.Bytes()

	ipCredential, found := s.getCredentialByPCXY(findCredentialXYCBytes, credentialType)
	if !found {
		c.LoggerError(logger, "can't find identity provider credential by "+hex.EncodeToString(findCredentialXYCBytes)+" "+credentialType)
		return types.Credential{}, types.ErrCredentialNotExists
	}

	if ipCredential.WalletID != "" {
		c.LoggerError(logger, "identity provider credential already consumed: "+ipCredential.WalletID)
		return types.Credential{}, types.ErrCredentialClaimed
	}

	return ipCredential, nil
}

// validateUpdatePedersenCommits runs the same two proofs a claim does: newCredentialPC is a
// re-blinding of the identity provider's commitment (via a zero-amount ZeroPC), and claimPC ties
// it to the wallet's own amount commitment.
func (s *qadenaServer) validateUpdatePedersenCommits(ipCredential types.Credential, wallet types.Wallet, newCredentialPC *types.BPedersenCommit, zeroPCProto *types.EncryptablePedersenCommit, claimPC *types.BPedersenCommit) error {
	zeroPC := c.UnprotoizeEncryptablePedersenCommit(zeroPCProto)
	if zeroPC.A.Cmp(c.BigIntZero) != 0 {
		c.LoggerError(logger, "ZeroPC does not have zero amount")
		return types.ErrGenericPedersen
	}

	if !c.ValidatePedersenCommit(zeroPC) {
		c.LoggerError(logger, "failed to validate ZeroPC")
		return types.ErrGenericPedersen
	}

	unprotoIPCredentialPC := c.UnprotoizeBPedersenCommit(ipCredential.CredentialPedersenCommit)
	unprotoNewCredentialPC := c.UnprotoizeBPedersenCommit(newCredentialPC)

	if !c.ValidateSubPedersenCommit(unprotoIPCredentialPC, unprotoNewCredentialPC, zeroPC) {
		c.LoggerError(logger, ipCredential.CredentialType, "failed to validate credentialPC (", unprotoIPCredentialPC.C.B64Address(), ") - newCredentialPC (", unprotoNewCredentialPC.C.B64Address(), ") = 0")
		return types.ErrGenericPedersen
	}

	unprotoWalletAmountPC := c.UnprotoizeBPedersenCommit(wallet.WalletAmount[types.QadenaTokenDenom].WalletAmountPedersenCommit)

	if !c.ValidateAddPedersenCommit(unprotoWalletAmountPC, unprotoNewCredentialPC, c.UnprotoizeBPedersenCommit(claimPC)) {
		c.LoggerError(logger, "failed to validate ClaimPC")
		return types.ErrGenericPedersen
	}

	return nil
}

// compareCredentialPC re-derives the commitment from the decrypted plaintext and the PIN, and
// checks it matches what the client published.  Without this the client could publish a
// commitment over data other than what it encrypted.
func (s *qadenaServer) compareCredentialPC(details proto.Message, pin string, credentialPC *types.BPedersenCommit) error {
	all, err := proto.Marshal(details)
	if err != nil {
		c.LoggerError(logger, "couldn't marshal details "+err.Error())
		return types.ErrGenericPedersen
	}

	pinInt, ok := big.NewInt(0).SetString(pin, 10)
	if !ok {
		c.LoggerError(logger, "bad PIN")
		return types.ErrGenericPedersen
	}

	checkPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(all)), pinInt)

	if !c.ComparePedersenCommit(checkPC, c.UnprotoizeBPedersenCommit(credentialPC)) {
		c.LoggerError(logger, "checkPC != newCredentialPC")
		return types.ErrGenericPedersen
	}

	return nil
}

func (s *qadenaServer) decryptCredentialHash(outerBind *c.VShareBindData, hashBind *types.VShareBindData, encHashVShare []byte) (string, error) {
	privK := s.getSSPrivK(outerBind.GetSSIntervalPubKID())
	if privK == "" {
		c.LoggerError(logger, "Couldn't find privk for "+outerBind.GetSSIntervalPubKID())
		return "", types.ErrGenericEncryption
	}

	var credentialHash types.EncryptableString
	err := c.VShareBDecryptAndProtoUnmarshal(privK, s.getPubK(outerBind.GetSSIntervalPubKID()), c.UnprotoizeVShareBindData(hashBind), encHashVShare, &credentialHash)
	if err != nil {
		c.LoggerError(logger, "couldn't decrypt credential hash "+err.Error())
		return "", err
	}

	return credentialHash.Value, nil
}

// checkUpdateLimits is the rate limit.  The alias list doubles as the counter for hash-changing
// updates, so no separate tally is needed.
func checkUpdateLimits(history types.EncryptableCredentialIdentityHistory, verdict c.UpdateVerdict, limits c.UpdateLimits, blockHeight int64) error {
	// The cool-down applies to every update, including one that only moves citizenship: it is
	// there to stop a credential being rewritten repeatedly, not specifically to protect the
	// identity hash.
	if history.LastUpdateHeight != 0 && blockHeight-history.LastUpdateHeight < limits.MinBlocksBetweenUpdates {
		return c.RateLimitf("last update was at height %d, %d blocks must pass", history.LastUpdateHeight, limits.MinBlocksBetweenUpdates)
	}

	if !verdict.HashChanged {
		return nil
	}

	if uint32(len(history.Hashes)) >= limits.MaxIdentityAliases {
		return c.RateLimitf("credential already has %d identity aliases, limit is %d", len(history.Hashes), limits.MaxIdentityAliases)
	}

	if verdict.Kind == c.UpdateKindLifeEvent && history.LifeEventCount >= limits.MaxLifeEvents {
		return c.RateLimitf("credential already had %d life events, limit is %d", history.LifeEventCount, limits.MaxLifeEvents)
	}

	return nil
}

// validateSubUpdates checks each name sub-credential against the corrected personal info and
// returns the rows to write.  Nothing is written here: a rejection must leave state untouched.
func (s *qadenaServer) validateSubUpdates(subUpdates []*types.EncryptableUpdateSubCredential, credentialID string, newDetails *types.EncryptablePersonalInfoDetails, verdict c.UpdateVerdict, wallet types.Wallet) ([]types.Credential, error) {
	seen := make(map[string]bool, len(subUpdates))
	credentials := make([]types.Credential, 0, len(subUpdates))

	for _, sub := range subUpdates {
		if sub == nil {
			return nil, types.ErrCredentialUpdateRejected
		}

		expectedName, ok := nameForSubCredentialType(newDetails, sub.CredentialType)
		if !ok {
			c.LoggerError(logger, "sub-update for unsupported credential type "+sub.CredentialType)
			return nil, types.ErrCredentialUpdateRejected
		}
		if seen[sub.CredentialType] {
			c.LoggerError(logger, "duplicate sub-update for "+sub.CredentialType)
			return nil, types.ErrCredentialUpdateRejected
		}
		seen[sub.CredentialType] = true

		oldSub, found := s.getCredential(credentialID, sub.CredentialType)
		if !found {
			c.LoggerError(logger, "sub-credential to update does not exist "+credentialID+" "+sub.CredentialType)
			return nil, types.ErrCredentialNotExists
		}
		if oldSub.WalletID != wallet.WalletID {
			c.LoggerError(logger, "sub-credential "+sub.CredentialType+" is owned by "+oldSub.WalletID)
			return nil, types.ErrCredentialUpdateNotOwner
		}

		ipSub, err := s.findOwnerlessIPCredential(sub.FindCredentialPC, sub.CredentialType)
		if err != nil {
			return nil, err
		}

		if err := s.validateUpdatePedersenCommits(ipSub, wallet, sub.NewCredentialPC, sub.ZeroPC, sub.ClaimPC); err != nil {
			return nil, err
		}

		unprotoBind := c.UnprotoizeVShareBindData(sub.CredentialInfoVShareBind)
		var subInfo types.EncryptableSingleContactInfo
		err = c.VShareBDecryptAndProtoUnmarshal(s.getSSPrivK(unprotoBind.GetSSIntervalPubKID()), s.getPubK(unprotoBind.GetSSIntervalPubKID()), unprotoBind, sub.EncCredentialInfoVShare, &subInfo)
		if err != nil {
			c.LoggerError(logger, "couldn't decrypt sub-credential "+sub.CredentialType)
			return nil, err
		}

		if err := s.compareCredentialPC(subInfo.Details, subInfo.PIN, sub.NewCredentialPC); err != nil {
			return nil, err
		}

		// the whole point of carrying the sub-updates inside this message: the name proved by
		// the sub-credential must be the name in the identity hash
		if subInfo.Details == nil || subInfo.Details.Contact != expectedName {
			c.LoggerError(logger, "sub-credential "+sub.CredentialType+" does not match the corrected personal info")
			return nil, types.ErrCredentialUpdateRejected
		}

		newSub := oldSub
		newSub.CredentialPedersenCommit = sub.NewCredentialPC
		newSub.EncCredentialInfoVShare = sub.EncCredentialInfoVShare
		newSub.CredentialInfoVShareBind = sub.CredentialInfoVShareBind
		newSub.FindCredentialPedersenCommit = nil
		newSub.UpdateGeneration = oldSub.UpdateGeneration + 1

		credentials = append(credentials, newSub)
	}

	// A name that moved without its sub-credential moving would leave the transfer-time name
	// proof (which reads the sub-credential's commitment) attesting to a name that is not in the
	// identity hash.  EVERY changed name must be covered, not just the first: with
	// MaxChangedIdentityFields above 1 a client could otherwise move two names and supply one
	// sub-update, leaving the other sub-credential stale.
	for _, field := range verdict.ChangedFields {
		subType, ok := nameSubCredentialTypeByField[field]
		if !ok {
			// birthdate and gender have no sub-credential
			continue
		}
		if !seen[subType] {
			c.LoggerError(logger, "missing sub-update for changed field "+field)
			return nil, types.ErrCredentialUpdateRejected
		}
	}

	return credentials, nil
}
