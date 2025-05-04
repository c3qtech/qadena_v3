package common

import (
	//	"encoding/hex"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// defaults for most of the tests
var params = NewECPrimeGroupKeyV2(vecLength)
var vectorBase = params.getVectorBase()

func setup() {
	Debug = false
	DebugFull = false
}

func generateAndVerifyRangeProof(vectorBase *VectorBase, number *big.Int, protoize bool) bool {
	setup()
	randomness, _ := RandomNumber256()

	v := NewPedersenCommit(number, randomness)
	if Debug && DebugFull {
		fmt.Println("V", v)
	}

	randomness, _ = RandomNumber256()

	proof := NewRangeProofV2(vectorBase, v)
	Debug = true
	DebugFull = true
	if Debug && DebugFull {
		fmt.Println("Generated proof")
		fmt.Println("Proof.A", proof.A)
		fmt.Println("Proof.S", proof.S)
		for i := 0; i < len(proof.TCommits); i++ {
			fmt.Println("Proof.TCommits", i, proof.TCommits[i])
		}
		fmt.Println("Proof.TauX", proof.TauX)
		fmt.Println("Proof.Mu", proof.Mu)
		fmt.Println("Proof.T", proof.T)
		fmt.Println("Proof.ProductProof.A", proof.ProductProof.A)
		fmt.Println("Proof.ProductProof.B", proof.ProductProof.B)
		for i := 0; i < len(proof.ProductProof.L); i++ {
			fmt.Println("Proof.ProductProof.L", i, proof.ProductProof.L[i])
		}
		for i := 0; i < len(proof.ProductProof.R); i++ {
			fmt.Println("Proof.ProductProof.R", i, proof.ProductProof.R[i])
		}
	}
	Debug = false
	DebugFull = false

	if protoize {
		protoProof := ProtoizeBRangeProof(proof)
		protoV := ProtoizeBPedersenCommit(v)

		v = UnprotoizeBPedersenCommit(protoV)
		proof = UnprotoizeBRangeProof(protoProof)
	}

	result := VerifyRangeProofV2(vectorBase, v, proof)
	if Debug && DebugFull {
		fmt.Println("Verification Result", result)
	}
	return result
}

func TestRangeProofWithProtoizeUnProtoize(t *testing.T) {
	setup()
	number := new(big.Int).SetInt64(5)
	expectedResult := true
	result := generateAndVerifyRangeProof(vectorBase, number, true)
	if result != expectedResult {
		t.Errorf("result = %t; want %t", result, expectedResult)
	}
}

func TestPaddedHash(t *testing.T) {
	setup()
	h := PaddedHash("G", 0)

	fmt.Println("h", h)

	// test if h is 115377814942352259530286949104270929993039261943703817083262565652424755313180
	if h.Cmp(newInt("115377814942352259530286949104270929993039261943703817083262565652424755313180")) != 0 {
		t.Errorf("h = %s; want 115377814942352259530286949104270929993039261943703817083262565652424755313180", h)
	}
}

func TestMapInto(t *testing.T) {
	setup()
	h := PaddedHash("G", 0)

	p := MapInto(h)

	fmt.Println("p", p)

	// test if p is (115377814942352259530286949104270929993039261943703817083262565652424755313180,84196338600477622106060066094085754468039456168128225340647481061089751590089)
	testP := NewECPoint(newInt("115377814942352259530286949104270929993039261943703817083262565652424755313180"), newInt("84196338600477622106060066094085754468039456168128225340647481061089751590089"))
	if !p.Equal(testP) {
		t.Errorf("p = %s; want (115377814942352259530286949104270929993039261943703817083262565652424755313180,84196338600477622106060066094085754468039456168128225340647481061089751590089)", p)
	}
}

func TestHashString(t *testing.T) {
	setup()
	h := HashString("G")

	fmt.Println("h", h)

	// test if h is 3388216464548280147592959668976866603264284679474019247268538060944586934226
	if h.Cmp(newInt("3388216464548280147592959668976866603264284679474019247268538060944586934226")) != 0 {
		t.Errorf("h = %s; want 3388216464548280147592959668976866603264284679474019247268538060944586934226", h)
	}
}

func TestGenerateParms(t *testing.T) {
	setup()
	p := NewECPrimeGroupKeyV2(vecLength)

	for i := 0; i < vecLength; i++ {
		fmt.Println("gs", i, hex.EncodeToString(p.Gs[i].X.Bytes()), hex.EncodeToString(p.Gs[i].Y.Bytes()))
	}
	for i := 0; i < vecLength; i++ {
		fmt.Println("hs", i, hex.EncodeToString(p.Hs[i].X.Bytes()), hex.EncodeToString(p.Hs[i].Y.Bytes()))
	}

	fmt.Println("G", p.G)
	fmt.Println("H", p.H)
}

func TestNewRangeProofV2(t *testing.T) {
	setup()
	number := new(big.Int).SetInt64(5)
	expectedResult := true
	result := generateAndVerifyRangeProof(vectorBase, number, false)
	if result != expectedResult {
		t.Errorf("result = %t; want %t", result, expectedResult)
	}
}

func TestNewRangeProofV2One(t *testing.T) {
	setup()
	number := new(big.Int).SetInt64(1)
	expectedResult := true
	result := generateAndVerifyRangeProof(vectorBase, number, false)
	if result != expectedResult {
		t.Errorf("result = %t; want %t", result, expectedResult)
	}
}

func TestNewRangeProofV2Zero(t *testing.T) {
	setup()
	number := big.NewInt(0)
	expectedResult := true
	result := generateAndVerifyRangeProof(vectorBase, number, false)
	if result != expectedResult {
		t.Errorf("result = %t; want %t", result, expectedResult)
	}
}

func TestNewRangeProofV2Negative(t *testing.T) {
	setup()
	number := big.NewInt(-1)
	expectedResult := false
	result := generateAndVerifyRangeProof(vectorBase, number, false)
	if result != expectedResult {
		t.Errorf("result = %t; want %t", result, expectedResult)
	}
}

func TestNewRangeProofV2Large(t *testing.T) {
	setup()
	// 2 ^ 128 using Exp
	number := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(vecLength)), nil)
	expectedResult := false
	result := generateAndVerifyRangeProof(vectorBase, number, false)
	if result != expectedResult {
		t.Errorf("result = %t; want %t", result, expectedResult)
	}
}

func TestNewRangeProofV2Large2(t *testing.T) {
	setup()
	// 2 ^ 128 using Exp - 1
	number := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(vecLength)), nil)
	number = new(big.Int).Sub(number, big.NewInt(1))
	expectedResult := true
	result := generateAndVerifyRangeProof(vectorBase, number, false)
	if result != expectedResult {
		t.Errorf("result = %t; want %t", result, expectedResult)
	}
}

func TestNewRangeProofV2SmallRange(t *testing.T) {
	setup()
	params8 := NewECPrimeGroupKeyV2(8)
	vectorBase8 := params8.getVectorBase()

	testCases := []struct {
		number         *big.Int
		expectedResult bool
	}{
		{newInt("255"), true},
		{newInt("0"), true},
		{newInt("1"), true},
		{newInt("254"), true},
		{newInt("-1"), false},
		{newInt("-2"), false},
		{newInt("256"), false},
		{newInt("257"), false},
	}

	for _, tc := range testCases {
		result := generateAndVerifyRangeProof(vectorBase8, tc.number, false)
		if result != tc.expectedResult {
			t.Errorf("result = %t; want %t for number %s", result, tc.expectedResult, tc.number.String())
		}
	}
}
