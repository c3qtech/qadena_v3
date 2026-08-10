package common

import (
	"encoding/hex"
	"fmt"
	"testing"

	types "github.com/c3qtech/qadena_v3/x/qadena/types"
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
		{PubK: pubKeys[0], NodeID: "", NodeType: ""},
		{PubK: pubKeys[1], NodeID: "", NodeType: ""},
		{PubK: pubKeys[2], NodeID: "jar1", NodeType: types.JarNodeType},
		{PubK: pubKeys[3], NodeID: types.SSNodeID, NodeType: types.SSNodeType},
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
		{PubK: pubKeys[0], NodeID: "", NodeType: ""},
		{PubK: pubKeys[1], NodeID: "", NodeType: ""},
		{PubK: pubKeys[2], NodeID: "jar1", NodeType: types.JarNodeType},
		{PubK: pubKeys[3], NodeID: types.SSNodeID, NodeType: types.SSNodeType},
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

		// Derived from the fourth mnemonic in GenerateKeys.  The previous literal here
		// (qadena100n3u3zz8e83jex0wp6j5len75de9hz4gtsa6x) predates the move to eth_secp256k1 and
		// had gone stale unnoticed, because GenerateKeys itself was broken and this test could not
		// run at all.  Confirmed against the real keyring rather than by copying what the code now
		// emits:
		//     qadenad keys add x --recover --keyring-backend test   (same mnemonic)
		//     -> qadena1swplxwyw4vduynhg9l8en392tcg2pdx08z56z9
		expectedPubKID := "qadena1swplxwyw4vduynhg9l8en392tcg2pdx08z56z9"
		if bind.GetSSIntervalPubKID() != expectedPubKID {
			t.Errorf("bind.GetSSIntervalPubKID() = %s; want %s", bind.GetSSIntervalPubKID(), expectedPubKID)
		}
	}
}

// The SS interval key rotates every 555 blocks, and a transaction bound to the key that was current
// when the client built it can land one block after the rotation.  The chain then expects the NEW
// key and the bind carries the OLD one, which used to be a flat rejection (qadena code 1142) even
// though the transaction was perfectly well formed.  AltPubK is the grace: the expectation is
// satisfied by either key.
//
// What must NOT widen is whose key it is.  The last two cases below are the ones that matter -- an
// alternate that is not in the bind must still fail, and an alternate that IS in the bind must still
// fail when it is claimed for the wrong node.
func TestFindVSharePubKInfoAcceptsPreviousIntervalKey(t *testing.T) {
	setupConfig()

	pubKeys, _ := GenerateKeys(t, 5)

	// oldSSKey is the key the client read and bound to.  newSSKey and unrelatedKey are deliberately
	// NOT recipients of anything -- newSSKey stands in for the key the rotation installed, and
	// unrelatedKey for one a further rotation installed after that.  strangerKey IS a recipient,
	// but as jar1, which is what makes the identity check below meaningful.
	oldSSKey, strangerKey := pubKeys[2], pubKeys[1]
	newSSKey, unrelatedKey := pubKeys[3], pubKeys[4]

	ccPubK := []VSharePubKInfo{
		{PubK: pubKeys[0], NodeID: "", NodeType: ""},
		{PubK: strangerKey, NodeID: "jar1", NodeType: types.JarNodeType},
		{PubK: oldSSKey, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
	}

	sci := types.EncryptableSingleContactInfoDetails{Contact: "hello world this is a test"}

	testVShareEncryption = false
	encVShare, bind := ProtoMarshalAndVShareBEncrypt(ccPubK, &sci)
	testVShareEncryption = false

	if bind == nil {
		t.Fatalf("ProtoMarshalAndVShareBEncrypt() failed")
	}

	cases := []struct {
		name   string
		expect VSharePubKInfo
		want   bool
	}{
		{
			// No rotation happened: the ordinary path, and proof the grace did not disturb it.
			name:   "current key, no alternate",
			expect: VSharePubKInfo{PubK: oldSSKey, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
			want:   true,
		},
		{
			// The race itself: the chain expects the new key, the bind carries the old one.
			name:   "rotated away, previous key offered as alternate",
			expect: VSharePubKInfo{PubK: newSSKey, AltPubK: oldSSKey, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
			want:   true,
		},
		{
			// Two rotations deep: the bind names neither the current key nor the one before it.
			// The grace is one deep on purpose -- without this bound the rule would decay into
			// "accept any key this node has ever seen".
			name:   "neither key is in the bind",
			expect: VSharePubKInfo{PubK: newSSKey, AltPubK: unrelatedKey, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
			want:   false,
		},
		{
			// strangerKey IS a recipient of this bind -- but as jar1, not as the SS node.  If the
			// alternate skipped the identity check, this would pass and any cc'd party could stand
			// in for the SS node.
			name:   "alternate is in the bind but under another identity",
			expect: VSharePubKInfo{PubK: newSSKey, AltPubK: strangerKey, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
			want:   false,
		},
		{
			// The old behaviour, unchanged: no alternate means no grace.
			name:   "rotated away, no alternate offered",
			expect: VSharePubKInfo{PubK: newSSKey, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bind.FindVSharePubKInfo(tc.expect); got != tc.want {
				t.Errorf("FindVSharePubKInfo() = %v; want %v", got, tc.want)
			}
		})
	}

	// Widening the expectation must not weaken the proof.  VShareBVerify is a property of the bind
	// alone -- it shows every recipient the bind names shares one secret over this ciphertext -- so
	// it has to still hold regardless of what we compared against above.
	if !bind.VShareBVerify(encVShare) {
		t.Errorf("VShareBVerify() failed after the alternate-key checks")
	}
}
