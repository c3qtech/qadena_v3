package common

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	//	"bytes"
	"encoding/hex"
	"encoding/json"

	"encoding/base64"
	"strings"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	ecies "github.com/ecies/go/v2"

	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"

	proto "github.com/cosmos/gogoproto/proto"
)

// This is used by the enclave to create stable encryptions used for keys
func SharedSecretNoNonceEncrypt(sharedSecret []byte, plainText []byte) (cipherText []byte, err error) {
	// AES encryption
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		fmt.Println("cannot create new aes block")
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		fmt.Println("cannot create aes gcm")
	}
	nonce := sharedSecret[0:16]
	cipherText = aesgcm.Seal(nil, nonce, plainText, nil)
	return
}

// This is used by the enclave to decrypt stable encryptions used for keys
func SharedSecretNoNonceDecrypt(sharedSecret []byte, cipherText []byte) (plainText []byte, err error) {
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		fmt.Println("cannot create new aes block")
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		fmt.Println("cannot create gcm cipher")
	}

	nonce := sharedSecret[0:16]
	plainText, err = gcm.Open(nil, nonce, cipherText, nil)
	return
}

func Encrypt(pub, plainText string) string {
	pub = strings.TrimSuffix(pub, "_pubk")
	if Debug && DebugFull {
		fmt.Println("pub", pub)
		fmt.Println("plainText", plainText, len(plainText))
	}
	pubkbytes, err := base64.StdEncoding.DecodeString(pub)

	if err != nil {
		return ""
	}

	pubkbyteshex := hex.EncodeToString(pubkbytes)

	pubk, err := ecies.NewPublicKeyFromHex(pubkbyteshex)
	if err != nil {
		return ""
	}

	cipherText, err := ecies.Encrypt(pubk, []byte(plainText))
	if err != nil {
		return ""
	}
	cipherTextHex := hex.EncodeToString(cipherText)
	if Debug && DebugFull {
		fmt.Println("plaintext encrypted hex", cipherTextHex)
	}

	return cipherTextHex
}

func MarshalAndEncrypt(pubk string, v interface{}) string {
	v_b, _ := json.Marshal(v)
	return Encrypt(pubk, string(v_b))
}

func BEncrypt(pub string, plainText []byte) []byte {
	pub = strings.TrimSuffix(pub, "_pubk")
	if Debug && DebugFull {
		fmt.Println("pub", pub)
		fmt.Println("plainText", plainText, len(plainText))
	}
	pubkbytes, err := base64.StdEncoding.DecodeString(pub)

	if err != nil {
		return nil
	}

	pubkbyteshex := hex.EncodeToString(pubkbytes)

	pubk, err := ecies.NewPublicKeyFromHex(pubkbyteshex)
	if err != nil {
		return nil
	}

	cipherText, err := ecies.Encrypt(pubk, plainText)
	if err != nil {
		return nil
	}
	//		cipherTextHex := hex.EncodeToString(cipherText)
	//		fmt.Println("plaintext encrypted hex", cipherTextHex)

	return cipherText
}

// BEncryptDeterministic is BEncrypt with its two RANDOM inputs derived instead of sampled.
//
// WHY THIS EXISTS.  ecies.Encrypt draws a fresh ephemeral key and a fresh 16-byte GCM nonce from
// crypto/rand, so encrypting identical plaintext twice yields different bytes.  That is correct for
// a message in flight and WRONG for anything written into consensus state: every validator runs the
// same block through its own enclave, so each produces different ciphertext, the app hashes diverge
// and the chain forks.  That is not hypothetical -- a two-validator chain forked on the first
// suspicious transaction report ever filed, at the exact block that filed it.
//
// WHAT DOES NOT CHANGE.  This is still public-key encryption to the recipient, byte-compatible with
// ecies.Decrypt: the ephemeral public key and nonce travel inside the ciphertext exactly as before,
// so the regulator decrypts with their private key alone, knowing nothing about seed or context.
// Existing reports stay readable.
//
// SEED is secret material every enclave holds identically, and is used ONLY to generate the
// ephemeral key -- never to decrypt, never shared outside the enclave set.  It is a deterministic
// replacement for crypto/rand, not a second scheme.
//
// CONTEXT MUST BE UNIQUE FOR EVERY CALL, and this is the part that bites.  The ephemeral key fixes
// the AES key, so reusing a (context, seed, recipient) triple for two different plaintexts reuses
// both the AES key and the GCM nonce -- which leaks the XOR of the plaintexts and lets an attacker
// recover the GHASH subkey and forge tags.  A block height alone is NOT unique: one block holds
// many transactions, one transaction can file two reports, and one report encrypts several fields.
// Include every one of those in the context.
func BEncryptDeterministic(pub string, plainText []byte, seed []byte, context []byte) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("BEncryptDeterministic: empty seed")
	}
	if len(context) == 0 {
		return nil, errors.New("BEncryptDeterministic: empty context -- a unique context per encryption is required")
	}

	pub = strings.TrimSuffix(pub, "_pubk")
	pubkbytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return nil, fmt.Errorf("BEncryptDeterministic: bad recipient key: %w", err)
	}
	pubk, err := ecies.NewPublicKeyFromHex(hex.EncodeToString(pubkbytes))
	if err != nil {
		return nil, fmt.Errorf("BEncryptDeterministic: bad recipient key: %w", err)
	}

	ek, err := deterministicEphemeralKey(seed, pubkbytes, context, pubk.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	// From here the layout mirrors ecies.Encrypt exactly:
	//   ephemeral public key (65) || nonce (16) || tag (16) || ciphertext
	var ct bytes.Buffer
	ct.Write(ek.PublicKey.Bytes(false))

	ss, err := ek.Encapsulate(pubk)
	if err != nil {
		return nil, fmt.Errorf("BEncryptDeterministic: encapsulate: %w", err)
	}

	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("BEncryptDeterministic: aes: %w", err)
	}

	nonce, err := deriveBytes(seed, pubkbytes, append(append([]byte{}, context...), []byte("|nonce")...), 16)
	if err != nil {
		return nil, err
	}
	ct.Write(nonce)

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("BEncryptDeterministic: gcm: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plainText, nil)
	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	ct.Write(tag)
	ct.Write(ciphertext[:len(ciphertext)-len(tag)])

	return ct.Bytes(), nil
}

// deterministicEphemeralKey derives a scalar in [1, n-1] by rejection sampling, so the result is
// uniform over the valid range rather than biased the way a plain "reduce mod n" would be.
func deterministicEphemeralKey(seed, recipient, context []byte, n *big.Int) (*ecies.PrivateKey, error) {
	for i := 0; i < 256; i++ {
		info := append(append([]byte{}, context...), []byte(fmt.Sprintf("|ek|%d", i))...)
		b, err := deriveBytes(seed, recipient, info, 32)
		if err != nil {
			return nil, err
		}
		d := new(big.Int).SetBytes(b)
		if d.Sign() > 0 && d.Cmp(n) < 0 {
			return ecies.NewPrivateKeyFromBytes(b), nil
		}
	}
	// 256 consecutive rejections is not reachable in practice for secp256k1; failing loudly beats
	// returning a key derived some other way.
	return nil, errors.New("BEncryptDeterministic: could not derive an ephemeral scalar")
}

func deriveBytes(secret, salt, info []byte, n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), out); err != nil {
		return nil, fmt.Errorf("BEncryptDeterministic: hkdf: %w", err)
	}
	return out, nil
}

// ProtoMarshalAndBEncryptDeterministic is ProtoMarshalAndBEncrypt for values that land in consensus
// state.  See BEncryptDeterministic for why, and for the contract on context uniqueness.
func ProtoMarshalAndBEncryptDeterministic(pubk string, v proto.Message, seed, context []byte) ([]byte, error) {
	v_b, err := proto.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("ProtoMarshalAndBEncryptDeterministic: marshal: %w", err)
	}
	return BEncryptDeterministic(pubk, v_b, seed, context)
}

func ProtoMarshalAndBEncrypt(pubk string, v proto.Message) []byte {
	v_b, _ := proto.Marshal(v)
	return BEncrypt(pubk, v_b)
}

func MarshalAndBEncrypt(pubk string, v string) []byte {
	//	v_b, _ := json.Marshal(v)
	return BEncrypt(pubk, []byte(v))
}

func Decrypt(priv, encrypted string) string {
	privkhex := priv
	if strings.HasSuffix(priv, "_privk") {
		// strip the pubkid from the beginning
		split := strings.Split(priv, "_privkhex:")

		if len(split) != 2 {
			fmt.Println("invalid priv key", priv)
			return ""
		}

		privkhex = split[0]
		if Debug && DebugFull {
			fmt.Println("privkhex", privkhex)
		}
	}

	if Debug && DebugFull {
		fmt.Println("encryptedhex", encrypted)
	}

	privk, err := ecies.NewPrivateKeyFromHex(privkhex)
	if err != nil {
		fmt.Println("Couldn't create private key from hex")
		return ""
	}

	ciphertextBytes, err := hex.DecodeString(encrypted)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	plaintext, err := ecies.Decrypt(privk, ciphertextBytes)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	if Debug && DebugFull {
		fmt.Println("ciphertext decrypted", string(plaintext))
	}

	return string(plaintext)
}

func BDecrypt(priv string, encrypted []byte) []byte {
	privkhex := priv

	if strings.HasSuffix(priv, "_privk") {
		// strip the pubkid from the beginning
		split := strings.Split(priv, "_privkhex:")

		if len(split) != 2 {
			fmt.Println("invalid priv key", priv)
			return nil
		}

		privkhex = split[0]
		if Debug && DebugFull {
			fmt.Println("privkhex", privkhex)
		}
	}

	if Debug && DebugFull {
		fmt.Println("encryptedhex", hex.EncodeToString(encrypted))
	}

	privk, err := ecies.NewPrivateKeyFromHex(privkhex)
	if err != nil {
		fmt.Println("Couldn't create private key from hex")
		return nil
	}

	ciphertextBytes := encrypted

	plaintext, err := ecies.Decrypt(privk, ciphertextBytes)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	if Debug && DebugFull {
		fmt.Println("ciphertext decrypted hex", hex.EncodeToString(plaintext))
	}

	return plaintext
}

func DecryptAndUnmarshal(priv, encrypted string, v interface{}) (string, error) {
	if priv == "" {
		return "", types.ErrGenericEncryption
	}

	j := Decrypt(priv, encrypted)

	if j == "" {
		return "", types.ErrGenericEncryption
	}
	if Debug && DebugFull {
		fmt.Println("decrypted", j)
	}

	res := json.Unmarshal([]byte(j), &v)
	if res != nil {
		if Debug && DebugFull {
			fmt.Println("couldn't unmarshal", res)
		}
		return "", types.ErrGenericEncryption
	}

	if Debug && DebugFull {
		fmt.Println("unmarshalled", j)
	}

	return j, nil
}

func BDecryptAndProtoUnmarshal(priv string, encrypted []byte, v proto.Message) ([]byte, error) {
	if priv == "" {
		return nil, types.ErrGenericEncryption
	}

	j := BDecrypt(priv, encrypted)

	if j == nil {
		return nil, types.ErrGenericEncryption
	}
	if Debug && DebugFull {
		fmt.Println("decrypted", j)
	}

	res := proto.Unmarshal([]byte(j), v)
	if res != nil {
		if Debug && DebugFull {
			fmt.Println("couldn't unmarshal", res)
		}
		return nil, types.ErrGenericEncryption
	}

	if Debug && DebugFull {
		fmt.Println("unmarshalled", j)
	}

	return j, nil
}

func BDecryptAndUnmarshal(priv string, encrypted []byte, v *string) ([]byte, error) {
	if priv == "" {
		return nil, types.ErrGenericEncryption
	}

	j := BDecrypt(priv, encrypted)

	if j == nil {
		return nil, types.ErrGenericEncryption
	}
	if Debug && DebugFull {
		fmt.Println("decrypted", j)
	}

	*v = string(j)

	return j, nil
}
