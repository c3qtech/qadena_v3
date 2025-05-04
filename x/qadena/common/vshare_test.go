package common

import (
	"encoding/hex"
	"fmt"
	"testing"

	types "qadena_v3/x/qadena/types"
)

func TestGenerateVSharedKey(t *testing.T) {
	setupConfig()
	testVShareEncryption = false
	sharedSecret := generateVSharedSecret()
	testVShareEncryption = false

	// print sharedSecret
	fmt.Println("S1:", PrettyPrint(sharedSecret.S1))
	fmt.Println("S2:", PrettyPrint(sharedSecret.S2))

	fmt.Println("S1 encoded:", hex.EncodeToString(sharedSecret.S1.Bytes()))

	fmt.Println("# bytes S1:\t", len(sharedSecret.S1.Bytes()))
}

func TestGenerateSharedSecret(t *testing.T) {
	setupConfig()
	testVShareEncryption = false
	sharedSecret := GenerateSharedSecret()
	testVShareEncryption = false

	// print sharedSecret
	fmt.Println("sharedSecret:", hex.EncodeToString(sharedSecret))
}

func TestNewVShareBindData(t *testing.T) {
	setupConfig()
	// Generate keys
	testVShareEncryption = true
	Debug = true
	DebugFull = true
	pubKeys, _ := GenerateKeys(t, 4)

	// Nodes who will be cc'd for the dstEWalletID
	ccPubK := []VSharePubKInfo{
		{pubKeys[0], "", ""},
		{pubKeys[1], "", ""},
		{pubKeys[2], "jar1", types.JarNodeType},
		{pubKeys[3], types.SSNodeID, types.SSNodeType},
	}

	/*
	   proto v_b 0a1a68656c6c6f20776f726c64207468697320697320612074657374
	   S1: 0 {
	       "X": 97368617487603714092414532914124097846147079533749946779008061592908669241131,
	       "Y": 38012604707558131976206218819154704038994600591102383397891123254401931774169
	   }
	   S2: 0 {
	       "X": 10933688225293634337800930413737356245078722676670001755825505019306063008595,
	       "Y": 29026341325685103236884838969810081548457453006295014773090950353179945034432
	   }

	   sharedSecretBytes: d744af3cb08368d7282db5309c584d04d9be315dd2c5a39370424f7337e9c72bd744af3cb08368d7282db5309c584d04d9be315dd2c5a39370424f7337e9c72b
	   ciphertext encrypted hex 8bb59c1d6e8a3f47e3eec29d901f897afafc7c4c7dd7f86176f93c605b4466a12b7bae0d7816be5fb1ca7dd2d4490ff6b840ab8923186d595fd80c90
	*/

	cipherText, err := hex.DecodeString("8bb59c1d6e8a3f47e3eec29d901f897afafc7c4c7dd7f86176f93c605b4466a12b7bae0d7816be5fb1ca7dd2d4490ff6b840ab8923186d595fd80c90")
	if err != nil {
		t.Fatalf("Failed to decode cipherText: %v", err)
	}

	vSharedSecret := generateVSharedSecret()
	bindDataInternal, _ := newVShareBindData(cipherText, vSharedSecret, ccPubK)

	fmt.Println("bindDataInternal:", PrettyPrint(bindDataInternal))

	// verify
	verified := bindDataInternal.vShareBVerify(cipherText)

	fmt.Println("verified:", verified)
}

func TestVShareEncryptDecrypt(t *testing.T) {
	setupConfig()

	pubKeys, privKeys := GenerateKeys(t, 4)

	// nodes who will be cc'd for the dstEWalletID
	ccPubK := []VSharePubKInfo{
		{pubKeys[0], "", ""},
		{pubKeys[1], "", ""},
		{pubKeys[2], "jar1", types.JarNodeType},
		{pubKeys[3], types.SSNodeID, types.SSNodeType},
	}

	plainText := "hello world this is a test"
	//
	sci := types.EncryptableSingleContactInfoDetails{Contact: plainText}

	// marshal and encrypt the vshare
	testVShareEncryption = false
	encVShare, bind := ProtoMarshalAndVShareBEncrypt(ccPubK, &sci)
	testVShareEncryption = false

	if bind == nil {
		t.Errorf("ERROR! ProtoMarshalAndVShareBEncrypt() failed!")
	} else {
		// verify that the bind is correct
		if bind.VShareBVerify(encVShare) {
			fmt.Println("bind verified")
		} else {
			t.Errorf("ERROR! VerifyBindData() failed!")
		}

		// test decrypt
		var decryptedSCI types.EncryptableSingleContactInfoDetails

		for i := 0; i < 4; i++ {
			err := VShareBDecryptAndProtoUnmarshal(privKeys[i], pubKeys[i], bind, encVShare, &decryptedSCI)
			if err != nil {
				t.Errorf("ERROR! VShareDecryptAndProtoUnmarshal() failed!")
				return
			}
			fmt.Println("decyprtedSCI", decryptedSCI)
			if decryptedSCI.Contact != plainText {
				t.Errorf("decryptedSCI.Contact = %s; want %s", decryptedSCI.Contact, plainText)
			}
		}

		if bind.GetJarID() != "jar1" {
			t.Errorf("bind.GetJarID() = %s; want jar1", bind.GetJarID())
		}

		expectedPubKID := "qadena100n3u3zz8e83jex0wp6j5len75de9hz4gtsa6x"
		if bind.GetSSIntervalPubKID() != expectedPubKID {
			t.Errorf("bind.GetSSIntervalPubKID() = %s; want %s", bind.GetSSIntervalPubKID(), expectedPubKID)
		}
	}
}
