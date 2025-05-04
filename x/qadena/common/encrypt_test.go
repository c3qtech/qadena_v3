package common

import (
	"encoding/hex"
	"fmt"
	"testing"

	"math/big"
	types "qadena/x/qadena/types"
)

func TestEncryptDecryptEWA(t *testing.T) {
	TextBasedEncrypt = false

	setupConfig()

	pubKeys, privKeys := GenerateKeys(t, 1)

	var ewa types.EncryptableWalletAmount

	walletAmountPC := NewPedersenCommit(big.NewInt(123), big.NewInt(456))

	ewa.Nonce = "nonce"
	ewa.TransactionID = "txID"
	ewa.PedersenCommit = ProtoizeEncryptablePedersenCommit(walletAmountPC)

	fmt.Println("ewa", ewa)

	b := ProtoMarshalAndBEncrypt(pubKeys[0], &ewa)

	var ewa2 types.EncryptableWalletAmount
	_, err := BDecryptAndProtoUnmarshal(privKeys[0], b, &ewa2)

	if err != nil {
		fmt.Println("ERROR! BDecryptAndProtoUnmarshal() failed!")
		t.Errorf("BDecryptAndProtoUnmarshal() failed!")
	}

	fmt.Println("ewa2", ewa2)

	if ComparePedersenCommit(UnprotoizeEncryptablePedersenCommit(ewa.PedersenCommit), UnprotoizeEncryptablePedersenCommit(ewa2.PedersenCommit)) {
		fmt.Println("PedersenCommit and PedersenCommit2 are equal")
	} else {
		t.Errorf("PedersenCommit and PedersenCommit2 are not equal")
	}
}

func TestEncrypt(t *testing.T) {
	setupConfig()
	pubKeys, privKeys := GenerateKeys(t, 1)

	var plaintext = "hello world"

	encrypted := BEncrypt(pubKeys[0], []byte(plaintext))
	encryptedHex := hex.EncodeToString(encrypted)
	fmt.Println("encrypted", encryptedHex)

	decrypted := Decrypt(privKeys[0], encryptedHex)
	fmt.Println("decrypted", decrypted)

	if decrypted != plaintext {
		t.Errorf("decrypted = %s; want %s", decrypted, plaintext)
	}

}
