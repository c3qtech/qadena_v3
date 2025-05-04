package common

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func newInt(s string) *big.Int {
	i, _ := big.NewInt(0).SetString(s, 10)
	return i
}

func TestNewECPoint(t *testing.T) {
	x := newInt("18303386956939991449903206602893465155767250067039941066256298966043004296781")
	y := newInt("17503329493696578784755977957747791143093586631190537577280653861517699092690")
	point := NewECPoint(x, y)

	if !ECPedersen.Curve.IsOnCurve(x, y) {
		t.Errorf("NewECPoint(%s, %s) is not on the curve", x, y)
	}

	if point.X.Cmp(x) != 0 || point.Y.Cmp(y) != 0 {
		t.Errorf("NewECPoint(%s, %s) = (%s, %s); want (%s, %s)", x, y, point.X, point.Y, x, y)
	}
}

func TestECPointEqual(t *testing.T) {
	x := newInt("18303386956939991449903206602893465155767250067039941066256298966043004296781")
	y := newInt("17503329493696578784755977957747791143093586631190537577280653861517699092690")
	point1 := NewECPoint(x, y)
	point2 := NewECPoint(x, y)

	x2 := newInt("10142979298619654978326340800275973129229220698274876423643341992617511790693")
	y2 := newInt("26287639987100765916799552282372971072579608678845774066867687669190264027959")
	point3 := NewECPoint(x2, y2)

	if !point1.Equal(point2) {
		t.Errorf("point1.Equal(point2) = false; want true")
	}

	if point1.Equal(point3) {
		t.Errorf("point1.Equal(point3) = true; want false")
	}
}

func TestECPointString(t *testing.T) {
	x := newInt("18303386956939991449903206602893465155767250067039941066256298966043004296781")
	y := newInt("17503329493696578784755977957747791143093586631190537577280653861517699092690")
	point := NewECPoint(x, y)
	expected := "hex(28775992ca7adfc91a8e858f1084af82d7888aea5dfd313391f9d3f5e76cde4d, 26b2888e27c05d33bd5550f24d1bf38007c5fec52a0ae2a78c48ce528bc090d2)/dec(18303386956939991449903206602893465155767250067039941066256298966043004296781, 17503329493696578784755977957747791143093586631190537577280653861517699092690)"
	if point.String() != expected {
		t.Errorf("point.String() = %s; want %s", point.String(), expected)
	}
}

func TestGMult(t *testing.T) {
	s := []byte{1, 2, 3, 4}
	point := BaseGMult(s)

	expectedPoint := NewECPoint(newInt("20604578889909056137609902642638491786899409410734069432576589448943763479928"), newInt("21005795615442957948505959376619927478431633097596073629574683642269273908187"))

	if !point.Equal(expectedPoint) {
		t.Errorf("GMult(%v) = (%s, %s); want (%s, %s)", s, point.X, point.Y, expectedPoint.X, expectedPoint.Y)
	}
}

func TestECPointMult(t *testing.T) {
	x := newInt("18303386956939991449903206602893465155767250067039941066256298966043004296781")
	y := newInt("17503329493696578784755977957747791143093586631190537577280653861517699092690")
	point := NewECPoint(x, y)
	s := big.NewInt(3)

	result := point.Mult(s)

	expectedX, expectedY := ECPedersen.Curve.ScalarMult(x, y, s.Bytes())
	expectedPoint := NewECPoint(expectedX, expectedY)

	if !result.Equal(expectedPoint) {
		t.Errorf("point.Mult(%s) = (%s, %s); want (%s, %s)", s, result.X, result.Y, expectedPoint.X, expectedPoint.Y)
	}
}

func TestNewECPrimeGroupKey(t *testing.T) {
	gx := newInt("3388216464548280147592959668976866603264284679474019247268538060944586934228")
	gy := newInt("75552690864069724229068221785829518949503260698205079432307762846969920217317")
	g := NewECPoint(gx, gy)
	hx := newInt("22665422587344413573085386901529593189028859532048437645553684283026419226678")
	hy := newInt("6107529163615064436172174578146738342996045377304802890658733470867606006634")

	h := NewECPoint(hx, hy)

	var params = NewECPrimeGroupKeyV2(vecLength)

	if !g.Equal(params.G) {
		t.Errorf("g = %s; want %s", g, params.G)
	}

	if !h.Equal(ECPedersen.H) {
		t.Errorf("h = %s; want %s", h, params.H)
	}

}

func TestGeneratePedersenCommit(t *testing.T) {
	pc := NewPedersenCommit(big.NewInt(1234), nil)
	fmt.Println("pc", pc)
}

func TestGeneratePedersenCommitHexCompressed(t *testing.T) {
	// create a new ECPoint
	//	convert "1234" to big.Int

	Debug = true
	DebugFull = true

	pc := NewPedersenCommit(big.NewInt(1234), big.NewInt(5678))

	// print G and H
	//	fmt.Println("G", ECPedersen.G)
	//	fmt.Println("H", ECPedersen.H)
	x, _ := big.NewInt(0).SetString("18303386956939991449903206602893465155767250067039941066256298966043004296781", 10)
	y, _ := big.NewInt(0).SetString("17503329493696578784755977957747791143093586631190537577280653861517699092690", 10)
	ecPoint := NewECPoint(x, y)

	if !ecPoint.Equal(pc.C) {
		t.Errorf("ecPoint = %s; want %s", ecPoint, pc.C)
	}

	// protoize
	protoBPedersenCommit := ProtoizeBPedersenCommit(pc)
	//	fmt.Println("protoBPedersenCommit", protoBPedersenCommit)
	expected := "0228775992ca7adfc91a8e858f1084af82d7888aea5dfd313391f9d3f5e76cde4d"

	// hex encode the protoBPedersenCommit.C
	hexCompressed := hex.EncodeToString(protoBPedersenCommit.C.Compressed)
	if hexCompressed != expected {
		t.Errorf("hexCompressed = %s; want %s", hexCompressed, expected)
	}
	//	fmt.Println("hexCompressed", hexCompressed)

}

func TestGeneratePedersenCommitZero(t *testing.T) {
	// create a new ECPoint
	//	convert "1234" to big.Int

	Debug = true
	DebugFull = true

	pc := NewPedersenCommit(big.NewInt(0), big.NewInt(5678))

	// print G and H
	//	fmt.Println("G", ECPedersen.G)
	//	fmt.Println("H", ECPedersen.H)
	x, _ := big.NewInt(0).SetString("54247966164429197778230192973490489844360218922464994687240883350209248086784", 10)
	y, _ := big.NewInt(0).SetString("26936616243620728945621104926315910156499050466537718580591357239779285782768", 10)
	ecPoint := NewECPoint(x, y)

	if !ecPoint.Equal(pc.C) {
		t.Errorf("ecPoint = %s; want %s", ecPoint, pc.C)
	}

	// protoize
	protoBPedersenCommit := ProtoizeBPedersenCommit(pc)
	//	fmt.Println("protoBPedersenCommit", protoBPedersenCommit)

	// hex encode the protoBPedersenCommit.C
	hexCompressed := hex.EncodeToString(protoBPedersenCommit.C.Compressed)
	if hexCompressed != "0277ef42c19805d5cb89c777a94f16b82b5dd9c37545f4875741480e81499fcb00" {
		t.Errorf("hexCompressed = %s; want 0277ef42c19805d5cb89c777a94f16b82b5dd9c37545f4875741480e81499fcb00", hexCompressed)
	}
	//	fmt.Println("hexCompressed", hexCompressed)

}

func TestAddPedersenCommit(t *testing.T) {

	x1 := big.NewInt(12345)
	r1 := big.NewInt(67890)
	x2 := big.NewInt(54321)
	r2 := big.NewInt(9876)

	// Compute Pedersen commitments
	input := NewPedersenCommit(x1, r1)
	transfer := NewPedersenCommit(x2, r2)

	add := AddPedersenCommit(input, transfer)

	expectedSum := new(big.Int).Add(x1, x2)

	if add.A.Cmp(expectedSum) != 0 {
		t.Errorf("AddPedersenCommit(%s, %s) = %s; want %s", x1, x2, add.A, x1.Add(x1, x2))

	}

	if !ValidateAddPedersenCommit(input, transfer, add) {
		t.Errorf("AddPedersenCommit(%s, %s) failed validation", x1, x2)
	}

}

func TestSubPedersenCommit(t *testing.T) {
	Debug = true
	DebugFull = true

	x1 := big.NewInt(12345)
	r1 := big.NewInt(67890)
	x2 := big.NewInt(54321)
	r2 := big.NewInt(9876)

	// Compute Pedersen commitments
	input := NewPedersenCommit(x2, r1)
	transfer := NewPedersenCommit(x1, r2)

	sub := SubPedersenCommit(input, transfer)

	expectedDifference := new(big.Int).Sub(x2, x1)

	if sub.A.Cmp(expectedDifference) != 0 {
		t.Errorf("SubPedersenCommit(%s, %s) = %s; want %s", x1, x2, sub.A, x1.Sub(x1, x2))

	}

	if !ValidateSubPedersenCommit(input, transfer, sub) {
		t.Errorf("ValidatePedersenCommit(%s, %s, %s) failed validation", input, transfer, sub)
	}

	if ValidateSubPedersenCommit(input, transfer, transfer) {
		t.Errorf("SubPedersenCommit(%s, %s, %s) should have failed validation", input, transfer, transfer)
	}

}

func TestProtoUnprotoBPedersenCommit(t *testing.T) {
	var bigIntZero *big.Int = big.NewInt(0)
	pc := NewPedersenCommit(big.NewInt(123), big.NewInt(456))
	if ValidatePedersenCommit(pc) {
		fmt.Println("PedersenCommit is valid")
	} else {
		t.Errorf("PedersenCommit is invalid")
	}
	fmt.Println("pc", pc)
	p := ProtoizeBPedersenCommit(pc)
	pc2 := UnprotoizeBPedersenCommit(p)

	if !ValidPedersenCommit(pc2) {
		t.Errorf("PedersenCommit is invalid")
	}

	if ValidatePedersenCommit(pc2) {
		t.Errorf("PedersenCommit is valid, but it should not be (this means that pc2 has A and X)")
	} else {
		fmt.Println("PedersenCommit is invalid")
	}
	fmt.Println("pc2", pc2)
	if ComparePedersenCommit(pc, pc2) {
		fmt.Println("PedersenCommit and PedersenCommit2 are equal")
	} else {
		t.Errorf("PedersenCommit and PedersenCommit2 are not equal")
	}

	if pc2.A.Cmp(bigIntZero) != 0 {
		t.Errorf("pc2.A is not zero, it is %s", pc2.A)
	} else {
		fmt.Println("PC2.A is zero")
	}

}

func TestProtoUnprotoEncryptablePedersenCommit(t *testing.T) {
	pc := NewPedersenCommit(big.NewInt(123), big.NewInt(456))
	if ValidatePedersenCommit(pc) {
		fmt.Println("PedersenCommit is valid")
	} else {
		t.Errorf("PedersenCommit is invalid")
	}
	fmt.Println("pc", pc)
	p := ProtoizeEncryptablePedersenCommit(pc)
	pc2 := UnprotoizeEncryptablePedersenCommit(p)
	if ValidatePedersenCommit(pc2) {
		fmt.Println("PedersenCommit is valid")
	} else {
		t.Errorf("PedersenCommit is invalid")
	}
	fmt.Println("pc2", pc2)
	if ComparePedersenCommit(pc, pc2) {
		fmt.Println("PedersenCommit and PedersenCommit2 are equal")
	} else {
		t.Errorf("PedersenCommit and PedersenCommit2 are not equal")
	}

	pc = NewPedersenCommit(big.NewInt(-123), big.NewInt(-456))
	if ValidatePedersenCommit(pc) {
		fmt.Println("PedersenCommit is valid")
	} else {
		t.Errorf("PedersenCommit is invalid")
	}
	fmt.Println("negative pc", pc)
	p = ProtoizeEncryptablePedersenCommit(pc)
	pc2 = UnprotoizeEncryptablePedersenCommit(p)
	if ValidatePedersenCommit(pc2) {
		fmt.Println("PedersenCommit is valid")
	} else {
		t.Errorf("PedersenCommit is invalid")
	}
	fmt.Println("negative pc2", pc2)
	if ComparePedersenCommit(pc, pc2) {
		fmt.Println("PedersenCommit and PedersenCommit2 are equal")
	} else {
		t.Errorf("PedersenCommit and PedersenCommit2 are not equal")
	}

}
