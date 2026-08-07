package common

import (
	"bytes"
	"encoding/base64"
	"testing"

	ecies "github.com/ecies/go/v2"
)

// The property this whole file exists to protect: two nodes encrypting the same report must produce
// the same bytes.  They did not, and a two-validator chain forked on the first report ever filed --
// each enclave wrote different ciphertext into consensus state, so the app hashes diverged.
func recipient(t *testing.T) (string, *ecies.PrivateKey) {
	t.Helper()
	k, err := ecies.GenerateKey()
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey.Bytes(false)), k
}

func TestBEncryptDeterministicIsStable(t *testing.T) {
	pub, _ := recipient(t)
	seed := []byte("shared enclave seed")
	ctx := []byte("chain|100|tx0|report0|amount")
	msg := []byte("suspicious transaction amount")

	a, err := BEncryptDeterministic(pub, msg, seed, ctx)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	b, err := BEncryptDeterministic(pub, msg, seed, ctx)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("same inputs produced different ciphertext:\n  %x\n  %x", a, b)
	}
}

// Byte-compatible with the existing reader.  The regulator decrypts with their private key alone --
// no seed, no context -- so reports written before this change stay readable and the regulator's
// tooling does not change.
func TestBEncryptDeterministicDecryptsWithRecipientKeyOnly(t *testing.T) {
	pub, priv := recipient(t)
	msg := []byte("report body")

	ct, err := BEncryptDeterministic(pub, msg, []byte("seed"), []byte("ctx|1"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := ecies.Decrypt(priv, ct)
	if err != nil {
		t.Fatalf("ecies.Decrypt could not read it: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round trip mismatch: got %q want %q", got, msg)
	}
}

// A DIFFERENT context must give a different ephemeral key and nonce.  If it did not, two reports in
// one block would share an AES key AND a GCM nonce -- which leaks the XOR of the plaintexts and
// allows tag forgery.  This is the assertion that makes "context must be unique" enforceable.
func TestBEncryptDeterministicContextSeparates(t *testing.T) {
	pub, _ := recipient(t)
	seed := []byte("seed")
	msg := []byte("same plaintext")

	a, err := BEncryptDeterministic(pub, msg, seed, []byte("chain|100|tx0|report0|amount"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := BEncryptDeterministic(pub, msg, seed, []byte("chain|100|tx0|report0|optin"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different contexts produced identical ciphertext; the nonce/key would be reused")
	}
	// The ephemeral public key is the first 65 bytes; it must differ too, not just the nonce.
	if bytes.Equal(a[:65], b[:65]) {
		t.Fatal("different contexts reused the same ephemeral key")
	}
}

// A different seed must separate too: two enclave sets must never derive each other's keys.
func TestBEncryptDeterministicSeedSeparates(t *testing.T) {
	pub, _ := recipient(t)
	ctx := []byte("ctx|1")
	a, err := BEncryptDeterministic(pub, []byte("m"), []byte("seed A"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BEncryptDeterministic(pub, []byte("m"), []byte("seed B"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different seeds produced identical ciphertext")
	}
}

// Refusing an empty context is part of the contract: a caller that forgets it would otherwise get
// nonce reuse across every report on the chain.
func TestBEncryptDeterministicRejectsEmptyContextAndSeed(t *testing.T) {
	pub, _ := recipient(t)
	if _, err := BEncryptDeterministic(pub, []byte("m"), []byte("seed"), nil); err == nil {
		t.Fatal("empty context was accepted")
	}
	if _, err := BEncryptDeterministic(pub, []byte("m"), nil, []byte("ctx")); err == nil {
		t.Fatal("empty seed was accepted")
	}
}
