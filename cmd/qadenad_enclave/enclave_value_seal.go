package main

// VALUE SEALING: how every sealed row's VALUE is protected, and why it is not SGX sealing.
//
// THE PROBLEM THIS SOLVES.  Values used to be sealed with the SGX PRODUCT key
// (`ecrypto.SealWithProductKey`), which SGX derives from MRSIGNER + productID -- not from the
// measurement.  The signing key ships in this repo, so ANY binary signed with it could open a
// node's sealed rows.  That is not a theory: cmd/sealprobe, a different MRENCLAVE signed with
// cmd/qadenad_enclave/private.pem, opened a live node's SS shares and cached SS private keys on
// real SGX hardware (2026-10-19).
//
// THE FIX IS A KEY HIERARCHY, not a stronger SGX policy.  Exactly one thing is SGX-sealed now --
// enclave_params_<uid>.json, with the UNIQUE key, so only this measurement can open it (see
// writeEnclaveParams).  Everything else hangs off a secret that lives inside those params:
//
//	params file        SGX unique key (MRENCLAVE)        <- the only SGX seal
//	  └─ SealedTableSharedSecret
//	       ├─ row KEYS    MustSealStable, fixed nonce   (unchanged; must be deterministic)
//	       └─ row VALUES  this file                     (random nonce, per call)
//
// A foreign build cannot derive the unique key, so it cannot open the params, so it never learns
// SealedTableSharedSecret, so the stores stay shut.  MRSIGNER stops mattering for sealing -- which
// is the only honest conclusion while the signing key is in the repo.
//
// WHY VALUES MUST NOT BE SGX-SEALED AT ALL.  The upgrade ceremony opens both stores READ-ONLY and
// ferries only the params; enclave_data/enclave_secrets are inherited in place by the next
// measurement.  Unique-sealed values would be unreadable after any rebuild and MustUnseal panics.
// Chaining values to a FERRIED secret is what lets them survive a measurement change -- and, as a
// side effect, a move to another CPU, since this secret comes back through the escrow.
//
// WHY A DERIVED SUBKEY RATHER THAN THE SECRET ITSELF.  MustSealStable encrypts with that same
// secret under a FIXED nonce taken from the secret (common/encrypt.go, `nonce := sharedSecret[0:16]`)
// -- deliberate, because a lookup key must be deterministic or the row cannot be found.  Encrypting
// values with random nonces under the SAME AES key would make both uses share GCM's authentication
// subkey.  One HMAC buys domain separation, so the two can never interfere.
//
// NONCES: FRESH AND RANDOM, EVERY CALL.  That is not new -- ecrypto.Seal did the same, and two
// existing properties depend on it: saveEnclaveParamsIfChanged compares PLAINTEXT rather than
// ciphertext, and the enclave store cannot be consensus state because its bytes differ per node.
//
// THE ONE LIMIT WORTH KNOWING.  AES-256-GCM with a random 96-bit nonce has a soft ceiling: NIST
// advises staying under ~2^32 encryptions per key.  That is per NODE, over the life of its
// SealedTableSharedSecret -- a decade at modest write rates, under two years at ~100 sealed writes
// a second.  Chosen anyway to keep one cipher family across keys, values and the escrow, and it is
// no worse than the ecrypto.Seal it replaces.  If that bound ever bites, the cheap fixes are
// XChaCha20-Poly1305 (already vendored, 192-bit nonce) or a per-row salt fed into the HKDF.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// valueSealMagic tags the format.  Untagged bytes are refused rather than guessed at: the only
	// thing they could be is the retired product-key format, and a store holding those is refused
	// far earlier by initSchema (the schema version was bumped for exactly this).
	valueSealMagic = "QVS1"

	// The HKDF label.  Changing it re-keys every value, so it is versioned.
	valueSealInfo = "qadena value-seal v1"
)

// valueSealKey derives the value-sealing key from the params' SealedTableSharedSecret.
//
// Derived on demand, never stored: there is no new key to generate, escrow, ferry or lose.  The
// escrow and the upgrade handover already carry the secret this comes from, so both paths keep
// working untouched.
func (s *qadenaServer) valueSealKey() ([]byte, error) {
	secret := s.getPrivateEnclaveParamsSealedTableSharedSecret()
	if len(secret) == 0 {
		// Reachable only if something seals before the params exist.  Every sealed table seals its
		// KEY with the same secret, so MustSealStable would already have failed -- but say so
		// plainly rather than deriving a key from nothing.
		return nil, errors.New("no SealedTableSharedSecret: enclave params are not loaded, so no value can be sealed or opened yet")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(valueSealInfo)), key); err != nil {
		return nil, fmt.Errorf("deriving the value-seal key: %w", err)
	}
	return key, nil
}

// sealValue encrypts a row value.  Layout: magic || nonce || AES-256-GCM ciphertext.
func (s *qadenaServer) sealValue(plain []byte) ([]byte, error) {
	key, err := s.valueSealKey()
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("value-seal nonce: %w", err)
	}
	out := make([]byte, 0, len(valueSealMagic)+len(nonce)+len(plain)+aead.Overhead())
	out = append(out, valueSealMagic...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, nil), nil
}

// openValue decrypts a row value written by sealValue.
func (s *qadenaServer) openValue(sealed []byte) ([]byte, error) {
	magic := []byte(valueSealMagic)
	if !bytes.HasPrefix(sealed, magic) {
		return nil, fmt.Errorf("value is not in the %s seal format (%d bytes); a store written by an "+
			"older build is not readable here and initSchema should have refused it", valueSealMagic, len(sealed))
	}
	key, err := s.valueSealKey()
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	body := sealed[len(magic):]
	if len(body) < aead.NonceSize() {
		return nil, errors.New("value-sealed row is too short to hold a nonce")
	}
	return aead.Open(nil, body[:aead.NonceSize()], body[aead.NonceSize():], nil)
}
