package main

// Verifying that an institutional guardian signed for the person it actually verified.
//
// THE HOLE THIS CLOSES.  A guardian's social-recovery signature is meant to attest "I
// independently verified this person, and they own this wallet."  It verifiably attested only "a
// named guardian's key signed for wallet X".
//
// An institutional guardian's app server resolves identity -> wallet entirely on its own side: it
// authenticates an email, looks up a NameBinding, and puts only the ENCRYPTED DESTINATION WALLET
// ID into MsgSignRecoverPrivateKey.  Nothing in that message says who was authenticated, so
// SignRecoverKey could not check that the human who logged in had anything to do with the wallet
// being signed.
//
// If user A authenticates but the server resolves user B's wallet, every existing check passes --
// B's RecoverKey record exists, and the guardian genuinely is a guardian of B -- so the signature
// lands on B's recovery.  B's key is not disclosed to A (shares are re-encrypted to B's new wallet,
// and QueryGetRecoverKey demands a timestamp signature from it), but B's recovery advances with no
// authentication from B at all, and A is stuck FOREVER: the per-record dedup in SignRecoverKey has
// consumed the guardian's one signature.  At the deployed threshold of 2 of 2 institutions, that
// costs an attacker one of the two signatures they need.
//
// WHY ONLY INSTITUTIONS.  The bug is structural to SERVER-SIDE identity->wallet resolution, which
// an individual guardian does not do -- their app shows them one recovery and they sign it.  They
// also could not comply: CreateCredentialHash needs all five identity fields byte-exact after
// canonicalization, so a human typing a relative's middle name and birthdate would mostly produce
// a silent non-match.  Individuals are therefore exempt in every mode.  This is a control aimed at
// the failure mode, not a blanket requirement.
//
// WHY IT SHIPS OFF.  The whole scheme rests on one invariant nobody has measured: that the hash a
// guardian computes at signing time equals the one issuance produced and the enclave stores.  If
// that is wrong, enforcing it fails every institutional signature CLOSED -- recovery stops working
// for everyone.  Mode 1 (audit) resolves and compares and logs, while still accepting, so the
// invariant can be proven against real traffic before anything is rejected.

import (
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

const guardianAssertionTag = "guardian-assertion: "

// checkGuardianIdentityAssertion resolves the identity the guardian says it verified and compares
// it to the wallet being signed for.
//
// dstWalletID is the DECRYPTED destination from the message -- which is the protect SUB-wallet id,
// because recoverKeyByCredential files the RecoverKey under the sub-wallet and SignRecoverKey looks
// it up by this value.  That is why the comparison below resolves credential.WalletID (an ORIGINAL
// wallet id) through getProtectSubWalletIDByOriginalWalletID rather than comparing it directly.
//
// Returns nil when the signature should proceed.  In audit mode it always returns nil, having
// logged; only enforce mode returns an error.
func (s *qadenaServer) checkGuardianIdentityAssertion(
	in *types.MsgSignRecoverPrivateKey,
	mode c.SignRecoverKeyAssertionMode,
	signerName string,
	signerIsServiceProvider bool,
	dstWalletID string,
) error {
	if !mode.Enabled() {
		return nil
	}

	// Individual (family/friend) guardians are never asked, in any mode.  See the file header.
	if !signerIsServiceProvider {
		c.LoggerDebug(logger, guardianAssertionTag+"signer "+signerName+
			" is an individual guardian, exempt")
		return nil
	}

	assertedWalletID, reason := s.resolveGuardianAssertion(in)

	if reason == "" && assertedWalletID == dstWalletID {
		c.LoggerDebug(logger, guardianAssertionTag+"OK signer="+signerName)
		return nil
	}

	if reason == "" {
		reason = "asserted identity resolves to a different wallet"
	}

	// THE AUDIT LOG IS THE ENTIRE DELIVERABLE OF MODE 1, so make it greppable and say what was
	// compared.  Wallet ids are redacted on a real enclave along with everything else, following
	// the convention used throughout SignRecoverKey -- and the hash and PII are NEVER logged, in
	// any build, because a credential hash is a stable identifier for a person.
	if s.RealEnclave {
		c.LoggerError(logger, guardianAssertionTag+"MISMATCH mode="+mode.String()+
			" signer="+signerName+" reason="+reason+" (wallet ids redacted)")
	} else {
		c.LoggerError(logger, guardianAssertionTag+"MISMATCH mode="+mode.String()+
			" signer="+signerName+" reason="+reason+
			" assertedWalletID="+orUnresolved(assertedWalletID)+" signingFor="+dstWalletID)
	}

	if mode.Rejects() {
		return types.ErrInvalidSignRecoverKey
	}
	// Audit: the mismatch is recorded and the signature stands.  Accepting here is the POINT of
	// the mode, not an oversight -- it is what makes it safe to measure the invariant on a live
	// chain before enforcing it.
	return nil
}

// resolveGuardianAssertion decrypts the asserted identity hash and resolves it to a protect
// sub-wallet id, entirely through the enclave's own indexes.
//
// Returns ("", reason) on any failure, where reason is a short phrase for the audit log.  Every
// failure is a mismatch: an institution that cannot produce a readable, resolvable assertion has
// not made the statement this gate requires.
func (s *qadenaServer) resolveGuardianAssertion(in *types.MsgSignRecoverPrivateKey) (string, string) {
	if in.GuardianCredentialHashVShareBind == nil || len(in.EncGuardianCredentialHashVShare) == 0 {
		return "", "no identity assertion supplied"
	}

	// Same decrypt idiom recoverKeyByCredential uses for its credential hash.
	bind := c.UnprotoizeVShareBindData(in.GuardianCredentialHashVShareBind)
	privK := s.getSSPrivK(bind.GetSSIntervalPubKID())
	if privK == "" {
		// This enclave cannot read the SS interval key the assertion was bound to.  Distinct from
		// a forged assertion and worth its own phrase: it usually means the sender left the SS node
		// out of the recipient list, so nothing could ever decrypt it.
		return "", "assertion not bound to a readable SS interval key"
	}

	var guardianHash types.EncryptableString
	if err := c.VShareBDecryptAndProtoUnmarshal(privK, s.getPubK(bind.GetSSIntervalPubKID()),
		bind, in.EncGuardianCredentialHashVShare, &guardianHash); err != nil {
		return "", "assertion could not be decrypted"
	}
	if guardianHash.Value == "" {
		return "", "assertion is empty"
	}

	// Hash aliasing already works in our favour: addCredentialHashAlias deliberately keeps old
	// hashes so recovery survives a name change, so a guardian holding pre-update PII still
	// resolves.
	credential, exists := s.getCredentialByHash(guardianHash.Value)
	if !exists {
		return "", "asserted identity matches no credential"
	}

	// credential.WalletID is the ORIGINAL wallet.  The RecoverKey -- and therefore the destination
	// in the message -- is keyed by the PROTECT SUB-WALLET, so this indirection is required and
	// comparing credential.WalletID directly would never match.
	subWalletID, found := s.getProtectSubWalletIDByOriginalWalletID(credential.WalletID)
	if !found {
		return "", "asserted identity has no protect key"
	}
	return subWalletID, ""
}

// orUnresolved keeps an empty wallet id visible in the audit log rather than letting it vanish
// into the surrounding text.
func orUnresolved(s string) string {
	if s == "" {
		return "(unresolved)"
	}
	return s
}
