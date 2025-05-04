package common

import (
	"fmt"

	//	"bytes"
	"encoding/hex"
	"encoding/json"

	"encoding/base64"
	"strings"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	ecies "github.com/ecies/go/v2"

	"crypto/aes"
	"crypto/cipher"

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
	fmt.Println("pub", pub)
	fmt.Println("plainText", plainText, len(plainText))
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
	fmt.Println("plaintext encrypted hex", cipherTextHex)

	return cipherTextHex
}

func MarshalAndEncrypt(pubk string, v interface{}) string {
	v_b, _ := json.Marshal(v)
	return Encrypt(pubk, string(v_b))
}

func BEncrypt(pub string, plainText []byte) []byte {
	pub = strings.TrimSuffix(pub, "_pubk")
	fmt.Println("pub", pub)
	fmt.Println("plainText", plainText, len(plainText))
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
