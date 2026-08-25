package main

import (
	"context"
	"encoding/base64"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/require"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// The guardian identity assertion, across every (guardian class x assertion state x mode) cell.
//
// WHAT IS BEING PINNED.  The gate must be inert at 0, must never reject in audit, must reject only
// an institutional mismatch in enforce, and must never touch an individual guardian in any mode.
// The audit row is the one worth stating outright: it asserts the signature is ACCEPTED even
// though the assertion is wrong, because that is the entire purpose of the state -- it exists so
// the invariant this scheme rests on (a guardian's hash equalling the one issuance produced) can
// be measured on a live chain before anything is failed closed.

// assertionFixture wires the one thing the check cannot be tested without: an assertion the
// enclave can actually decrypt.  Returns the encrypted payload and its bind, having taught the
// server the SS interval keypair the payload is bound to.
func assertionFixture(t *testing.T, s *qadenaServer, hash string) ([]byte, *types.VShareBindData) {
	t.Helper()

	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	// keyHex, not k.Hex(): the latter drops leading zero bytes ~0.39% of the time and getSSPrivK
	// discards anything that is not a 32-byte key, which would make this fixture flaky.
	privKHex := keyHex(k)
	pubKB64 := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	ccPubK := []c.VSharePubKInfo{{
		PubK:     pubKB64,
		NodeID:   types.SSNodeID,
		NodeType: types.SSNodeType,
	}}
	enc, bind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &types.EncryptableString{Value: hash})

	// The enclave resolves the key by the bind's own SS pubKID, so seed the caches under exactly
	// that id rather than a name of our choosing.
	pubKID := bind.GetSSIntervalPubKID()
	require.NotEmpty(t, pubKID, "fixture must bind an SS recipient or nothing can decrypt it")
	s.setPrivKCache(pubKID, privKHex)
	s.setPubKCache(pubKID, pubKB64)

	return enc, c.ProtoizeVShareBindData(bind)
}

// knownIdentity registers a credential under hash, owned by originalWalletID, whose protect
// sub-wallet is subWalletID -- the chain of indexes the check walks.
func knownIdentity(t *testing.T, s *qadenaServer, hash, credentialID, originalWalletID, subWalletID string) {
	t.Helper()
	s.setCredential(credentialID, types.PersonalInfoCredentialType, types.Credential{
		CredentialID:   credentialID,
		CredentialType: types.PersonalInfoCredentialType,
		WalletID:       originalWalletID,
	})
	s.setCredentialByHash(hash, credentialID)
	s.setProtectSubWalletIDByOriginalWalletID(originalWalletID, subWalletID)
}

const (
	victimHash   = "aaaa1111victim"
	attackerHash = "bbbb2222attacker"
	victimSub    = "qadena1victimsubwallet"
	attackerSub  = "qadena1attackersubwallet"
)

// newAssertionServer returns a server that knows two identities: the one being signed for
// (victim) and an unrelated one (attacker) whose hash is what a mis-resolving server would send.
func newAssertionServer(t *testing.T) *qadenaServer {
	t.Helper()
	s := newTestEnclaveServer(t)
	knownIdentity(t, s, victimHash, "cred-victim", "qadena1victimoriginal", victimSub)
	knownIdentity(t, s, attackerHash, "cred-attacker", "qadena1attackeroriginal", attackerSub)
	return s
}

func allModes() []c.SignRecoverKeyAssertionMode {
	return []c.SignRecoverKeyAssertionMode{
		c.SignRecoverKeyAssertionOff,
		c.SignRecoverKeyAssertionAudit,
		c.SignRecoverKeyAssertionEnforce,
	}
}

// A matching assertion is accepted in every mode -- including enforce, which is the case that has
// to keep working or recovery stops for everyone.
func TestGuardianAssertionMatchingAccepted(t *testing.T) {
	for _, mode := range allModes() {
		t.Run(mode.String(), func(t *testing.T) {
			s := newAssertionServer(t)
			enc, bind := assertionFixture(t, s, victimHash)
			msg := &types.MsgSignRecoverPrivateKey{
				EncGuardianCredentialHashVShare:  enc,
				GuardianCredentialHashVShareBind: bind,
			}
			require.NoError(t, s.checkGuardianIdentityAssertion(msg, mode, "ekycph", true, victimSub))
		})
	}
}

// THE REGRESSION.  An institutional guardian signs for the victim's wallet while asserting a
// DIFFERENT person's identity -- exactly what a server that resolved the wrong user produces.
// Rejected only in enforce; accepted (and logged) in audit, which is the point of audit.
func TestGuardianAssertionMismatchRejectedOnlyInEnforce(t *testing.T) {
	cases := []struct {
		mode      c.SignRecoverKeyAssertionMode
		wantError bool
	}{
		{c.SignRecoverKeyAssertionOff, false},
		{c.SignRecoverKeyAssertionAudit, false},
		{c.SignRecoverKeyAssertionEnforce, true},
	}
	for _, tc := range cases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			s := newAssertionServer(t)
			// The guardian asserts the ATTACKER's identity but signs for the VICTIM's wallet.
			enc, bind := assertionFixture(t, s, attackerHash)
			msg := &types.MsgSignRecoverPrivateKey{
				EncGuardianCredentialHashVShare:  enc,
				GuardianCredentialHashVShareBind: bind,
			}
			err := s.checkGuardianIdentityAssertion(msg, tc.mode, "ekycph", true, victimSub)
			if tc.wantError {
				require.ErrorIs(t, err, types.ErrInvalidSignRecoverKey)
			} else {
				require.NoError(t, err, "only enforce may reject; audit must accept so the "+
					"mismatch can be measured on a live chain")
			}
		})
	}
}

// An institution that sends NO assertion is a mismatch, not a free pass -- otherwise enforcing the
// gate would be trivially bypassed by omitting the field.  Still only fatal in enforce.
func TestGuardianAssertionAbsentIsAMismatch(t *testing.T) {
	cases := []struct {
		mode      c.SignRecoverKeyAssertionMode
		wantError bool
	}{
		{c.SignRecoverKeyAssertionOff, false},
		{c.SignRecoverKeyAssertionAudit, false},
		{c.SignRecoverKeyAssertionEnforce, true},
	}
	for _, tc := range cases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			s := newAssertionServer(t)
			msg := &types.MsgSignRecoverPrivateKey{} // no assertion at all
			err := s.checkGuardianIdentityAssertion(msg, tc.mode, "ekycph", true, victimSub)
			if tc.wantError {
				require.ErrorIs(t, err, types.ErrInvalidSignRecoverKey)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// INDIVIDUAL GUARDIANS ARE EXEMPT IN EVERY MODE, assertion or not.  A family member signing from
// their own app never resolves identity server-side, and could not produce a byte-exact
// CreateCredentialHash by hand -- holding them to this would break recovery for the class it was
// never designed to protect.
func TestGuardianAssertionIndividualExemptInEveryMode(t *testing.T) {
	for _, mode := range allModes() {
		t.Run(mode.String(), func(t *testing.T) {
			s := newAssertionServer(t)
			msg := &types.MsgSignRecoverPrivateKey{}
			require.NoError(t, s.checkGuardianIdentityAssertion(
				msg, mode, "qadena1someindividualguardian", false, victimSub))
		})
	}
}

// An individual is exempt even when the assertion they do send is WRONG -- the exemption is by
// class, not by whether the field happens to be absent.
func TestGuardianAssertionIndividualExemptEvenWhenWrong(t *testing.T) {
	s := newAssertionServer(t)
	enc, bind := assertionFixture(t, s, attackerHash)
	msg := &types.MsgSignRecoverPrivateKey{
		EncGuardianCredentialHashVShare:  enc,
		GuardianCredentialHashVShareBind: bind,
	}
	require.NoError(t, s.checkGuardianIdentityAssertion(
		msg, c.SignRecoverKeyAssertionEnforce, "qadena1someindividualguardian", false, victimSub))
}

// An assertion naming an identity the chain has never seen resolves to nothing.  Distinct from a
// mismatch in the log, identical in effect.
func TestGuardianAssertionUnknownIdentityIsAMismatch(t *testing.T) {
	s := newAssertionServer(t)
	enc, bind := assertionFixture(t, s, "cccc3333nobody")
	msg := &types.MsgSignRecoverPrivateKey{
		EncGuardianCredentialHashVShare:  enc,
		GuardianCredentialHashVShareBind: bind,
	}
	require.ErrorIs(t,
		s.checkGuardianIdentityAssertion(msg, c.SignRecoverKeyAssertionEnforce, "ekycph", true, victimSub),
		types.ErrInvalidSignRecoverKey)
}

// A credential with no protect key cannot be the target of a recovery at all, so it cannot satisfy
// the assertion either.  This is the getProtectSubWalletIDByOriginalWalletID branch.
func TestGuardianAssertionIdentityWithoutProtectKeyIsAMismatch(t *testing.T) {
	s := newAssertionServer(t)
	s.setCredential("cred-orphan", types.PersonalInfoCredentialType, types.Credential{
		CredentialID:   "cred-orphan",
		CredentialType: types.PersonalInfoCredentialType,
		WalletID:       "qadena1orphanoriginal",
	})
	s.setCredentialByHash("dddd4444orphan", "cred-orphan")
	// deliberately no setProtectSubWalletIDByOriginalWalletID

	enc, bind := assertionFixture(t, s, "dddd4444orphan")
	msg := &types.MsgSignRecoverPrivateKey{
		EncGuardianCredentialHashVShare:  enc,
		GuardianCredentialHashVShareBind: bind,
	}
	require.ErrorIs(t,
		s.checkGuardianIdentityAssertion(msg, c.SignRecoverKeyAssertionEnforce, "ekycph", true, victimSub),
		types.ErrInvalidSignRecoverKey)
}

// THE COMPARISON TARGET IS THE PROTECT SUB-WALLET, NOT THE CREDENTIAL'S OWN WALLET.
//
// recoverKeyByCredential files the RecoverKey under the sub-wallet and SignRecoverKey looks it up
// by the decrypted destination, so the sub-wallet is what the destination holds.  Comparing
// credential.WalletID directly would match nothing and fail every signature closed the moment
// enforce was switched on -- which is precisely the failure this gate must not cause.  Pinned
// here because the getter that stores it is named ...ByOriginalWalletID, which reads the other way.
func TestGuardianAssertionComparesSubWalletNotOriginal(t *testing.T) {
	s := newAssertionServer(t)
	enc, bind := assertionFixture(t, s, victimHash)
	msg := &types.MsgSignRecoverPrivateKey{
		EncGuardianCredentialHashVShare:  enc,
		GuardianCredentialHashVShareBind: bind,
	}

	// The sub-wallet is accepted...
	require.NoError(t, s.checkGuardianIdentityAssertion(
		msg, c.SignRecoverKeyAssertionEnforce, "ekycph", true, victimSub))

	// ...and the ORIGINAL wallet id is not, which is what proves the indirection is real rather
	// than the two ids happening to be equal in this fixture.
	require.ErrorIs(t, s.checkGuardianIdentityAssertion(
		msg, c.SignRecoverKeyAssertionEnforce, "ekycph", true, "qadena1victimoriginal"),
		types.ErrInvalidSignRecoverKey)
}

// ---------------------------------------------------------------------------------------------
// THE FULL PATH, and the one ordering decision the unit cells above cannot protect.
//
// A rejected signature must NOT consume the guardian's slot.  SignRecoverKey allows each guardian
// to sign a given record exactly once -- the dedup walks recoverKey.Signatory -- so if the
// assertion check ran AFTER that append, a guardian whose server resolved the wrong user would be
// refused AND have burned its one signature on the victim's record.  The victim would then be
// permanently unrecoverable at a 2-of-2 threshold: the attack is blocked and the user is stranded
// anyway, which is barely better than the bug.
//
// The check is therefore placed above the dedup.  Every cell above still passes if someone moves
// it below, because they call checkGuardianIdentityAssertion directly and never see the ordering.
// This drives the real handler so the ordering is pinned by something.
// ---------------------------------------------------------------------------------------------

// signRecoverKeyFixture stands up the minimum state SignRecoverKey needs: a recovery record and a
// protect key for the victim, guarded by one institutional guardian.
func signRecoverKeyFixture(t *testing.T, s *qadenaServer, guardianName, guardianAddr string) {
	t.Helper()

	// The guardian is named canonically in the protect key, and resolves to its bech32 creator
	// through the service-provider index -- which is what puts it in the institutional class.
	s.setIntervalPublicKeyIdNoNotify(types.IntervalPublicKeyID{
		NodeID:   guardianName,
		NodeType: types.ServiceProviderNodeType,
		PubKID:   guardianAddr,
	})

	s.setProtectKeyNoNotify(&types.ProtectKey{
		WalletID:  victimSub,
		Threshold: 1,
		RecoverShare: []*types.RecoverShare{
			{WalletID: guardianName},
		},
	})

	s.setRecoverKeyByOriginalWalletID(victimSub, &types.RecoverKey{
		WalletID:     victimSub,
		Signatory:    []string{},
		RecoverShare: []*types.RecoverShare{},
	})
}

// destinationFor builds the encrypted destination-wallet payload SignRecoverKey decrypts first,
// bound to an SS key this server can read.
func destinationFor(t *testing.T, s *qadenaServer, walletID string) ([]byte, *types.VShareBindData) {
	t.Helper()

	k, err := ecies.GenerateKey()
	require.NoError(t, err)
	pubKB64 := base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(true))

	ccPubK := []c.VSharePubKInfo{{PubK: pubKB64, NodeID: types.SSNodeID, NodeType: types.SSNodeType}}
	enc, bind := c.ProtoMarshalAndVShareBEncrypt(ccPubK,
		&types.EncryptableSignRecoverKeyEWalletID{Nonce: "nonce-test", WalletID: walletID})

	pubKID := bind.GetSSIntervalPubKID()
	require.NotEmpty(t, pubKID)
	s.setPrivKCache(pubKID, keyHex(k))
	s.setPubKCache(pubKID, pubKB64)

	return enc, c.ProtoizeVShareBindData(bind)
}

// A guardian signing for the victim while asserting SOMEONE ELSE's identity is refused in enforce,
// and -- the point of this test -- the victim's record is left exactly as it was, so the real user
// can still be recovered once the guardian sends the right assertion.
func TestSignRecoverKeyRejectedAssertionDoesNotConsumeTheSignature(t *testing.T) {
	const guardianName = "ekycph"
	const guardianAddr = "qadena1guardianserviceprovider"

	s := newAssertionServer(t)
	signRecoverKeyFixture(t, s, guardianName, guardianAddr)

	encDst, dstBind := destinationFor(t, s, victimSub)
	encHash, hashBind := assertionFixture(t, s, attackerHash) // the WRONG identity

	req := &types.EnclaveSignRecoverKeyRequest{
		Msg: &types.MsgSignRecoverPrivateKey{
			Creator:                          guardianAddr,
			EncDestinationEWalletIDVShare:    encDst,
			DestinationEWalletIDVShareBind:   dstBind,
			EncGuardianCredentialHashVShare:  encHash,
			GuardianCredentialHashVShareBind: hashBind,
		},
		Params: types.Params{
			SignRecoverKeyGuardianAssertionMode: types.SignRecoverKeyAssertionEnforce,
		},
	}

	_, err := s.SignRecoverKey(context.Background(), req)
	require.ErrorIs(t, err, types.ErrInvalidSignRecoverKey,
		"a guardian asserting the wrong identity must be refused in enforce mode")

	// THE ASSERTION THAT MATTERS.  The guardian's slot is still free.
	rk, found := s.getRecoverKeyByOriginalWalletID(victimSub)
	require.True(t, found, "the victim's recovery record must still exist")
	require.Empty(t, rk.Signatory,
		"a REFUSED signature must not consume the guardian's one slot -- otherwise the attack is "+
			"blocked and the victim is stranded anyway, since a guardian may sign each record once")
}

// The same path with the RIGHT identity must complete and record the signature -- otherwise the
// test above would pass just as well against a handler that refused everything.
func TestSignRecoverKeyMatchingAssertionRecordsTheSignature(t *testing.T) {
	const guardianName = "ekycph"
	const guardianAddr = "qadena1guardianserviceprovider"

	s := newAssertionServer(t)
	signRecoverKeyFixture(t, s, guardianName, guardianAddr)

	encDst, dstBind := destinationFor(t, s, victimSub)
	encHash, hashBind := assertionFixture(t, s, victimHash) // the CORRECT identity

	req := &types.EnclaveSignRecoverKeyRequest{
		Msg: &types.MsgSignRecoverPrivateKey{
			Creator:                          guardianAddr,
			EncDestinationEWalletIDVShare:    encDst,
			DestinationEWalletIDVShareBind:   dstBind,
			EncGuardianCredentialHashVShare:  encHash,
			GuardianCredentialHashVShareBind: hashBind,
		},
		Params: types.Params{
			SignRecoverKeyGuardianAssertionMode: types.SignRecoverKeyAssertionEnforce,
		},
	}

	_, err := s.SignRecoverKey(context.Background(), req)
	require.NoError(t, err, "a correct assertion must still be accepted in enforce mode")

	rk, found := s.getRecoverKeyByOriginalWalletID(victimSub)
	require.True(t, found)
	require.Equal(t, []string{guardianName}, rk.Signatory,
		"the guardian's signature must be recorded under its canonical name")
}

// EVERY STATE THE PARAM CAN BE IN, driven through the real handler.
//
// The cells earlier in this file pass a decoded mode straight into the check, so none of them
// would notice if EnclaveSignRecoverKeyRequest.Params were dropped on the floor and the gate read
// as off forever.  This drives SignRecoverKey with the mode as the KEEPER stamps it -- a raw
// uint32 on the request -- and asserts the observable that matters: whether the guardian's
// signature ended up on the record.
//
// THE OUT-OF-RANGE ROWS ARE NOT PADDING.  types.Params.Validate rejects 3 and above, so a stored
// param should never hold one -- but the decode deliberately maps anything unrecognised to OFF, so
// that a param written by a NEWER binary can never make an older one start rejecting signatures.
// That failure direction is the whole point (enforcing wrongly fails every institutional recovery
// closed), and it is only asserted here.
func TestSignRecoverKeyEveryParamState(t *testing.T) {
	const guardianName = "ekycph"
	const guardianAddr = "qadena1guardianserviceprovider"

	// A GENUINE bech32 address, derived rather than written out.  An individual guardian is
	// recognised by IsBech32Address succeeding on its protect-key entry, so a hand-typed
	// "qadena1individualguardian" does not work -- it is not in the bech32 charset, so it decodes
	// as invalid, falls through to the service-provider lookups, and resolves to no signer at all.
	// Deriving it also picks up whatever prefix this build is configured for.
	individualAddr := sdk.AccAddress([]byte("individualguardian--")).String()

	// What the guardian asserts about who it verified.
	type assertion int
	const (
		matching assertion = iota
		mismatched
		absent
	)
	assertionName := map[assertion]string{matching: "matching", mismatched: "mismatched", absent: "absent"}

	modes := []struct {
		raw  uint32
		name string
		// rejectsAWrongAssertion is true only for enforce.  Every other state -- including the
		// invalid ones, which decode to off -- accepts regardless.
		rejectsAWrongAssertion bool
	}{
		{types.SignRecoverKeyAssertionOff, "0-off", false},
		{types.SignRecoverKeyAssertionAudit, "1-audit", false},
		{types.SignRecoverKeyAssertionEnforce, "2-enforce", true},
		{3, "3-invalid-reads-as-off", false},
		{255, "255-invalid-reads-as-off", false},
	}

	for _, mode := range modes {
		for _, a := range []assertion{matching, mismatched, absent} {
			for _, institutional := range []bool{true, false} {
				class := "institutional"
				if !institutional {
					class = "individual"
				}
				t.Run(mode.name+"/"+assertionName[a]+"/"+class, func(t *testing.T) {
					s := newAssertionServer(t)

					creator := guardianAddr
					if institutional {
						signRecoverKeyFixture(t, s, guardianName, guardianAddr)
					} else {
						// An individual guardian is named in the protect key by its raw bech32
						// address, which is exactly what puts it in the exempt class.
						creator = individualAddr
						s.setProtectKeyNoNotify(&types.ProtectKey{
							WalletID:     victimSub,
							Threshold:    1,
							RecoverShare: []*types.RecoverShare{{WalletID: individualAddr}},
						})
						s.setRecoverKeyByOriginalWalletID(victimSub, &types.RecoverKey{
							WalletID:     victimSub,
							Signatory:    []string{},
							RecoverShare: []*types.RecoverShare{},
						})
					}

					encDst, dstBind := destinationFor(t, s, victimSub)

					msg := &types.MsgSignRecoverPrivateKey{
						Creator:                        creator,
						EncDestinationEWalletIDVShare:  encDst,
						DestinationEWalletIDVShareBind: dstBind,
					}
					switch a {
					case matching:
						msg.EncGuardianCredentialHashVShare, msg.GuardianCredentialHashVShareBind =
							assertionFixture(t, s, victimHash)
					case mismatched:
						msg.EncGuardianCredentialHashVShare, msg.GuardianCredentialHashVShareBind =
							assertionFixture(t, s, attackerHash)
					case absent:
						// deliberately left nil
					}

					// Only an INSTITUTIONAL guardian in ENFORCE with a wrong-or-missing assertion
					// is refused.  Individuals are exempt in every state; every non-enforce state
					// accepts everything.
					wrongAssertion := a != matching
					wantReject := mode.rejectsAWrongAssertion && institutional && wrongAssertion

					_, err := s.SignRecoverKey(context.Background(), &types.EnclaveSignRecoverKeyRequest{
						Msg:    msg,
						Params: types.Params{SignRecoverKeyGuardianAssertionMode: mode.raw},
					})

					rk, found := s.getRecoverKeyByOriginalWalletID(victimSub)
					require.True(t, found, "the recovery record must survive either way")

					if wantReject {
						require.ErrorIs(t, err, types.ErrInvalidSignRecoverKey)
						// And the slot is still free -- a refusal must not strand the real user.
						require.Empty(t, rk.Signatory,
							"a refused signature must not consume the guardian's one slot")
						return
					}

					require.NoError(t, err, "state %s must accept this signature", mode.name)
					require.Len(t, rk.Signatory, 1, "an accepted signature must be recorded")
				})
			}
		}
	}
}
