package common

import (
	"crypto/rand"
	"strings"

	//    "crypto/sha256"
	//    "fmt"
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	//"math"

	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// RangeProof represents a range proof
type RangeProofV2 struct {
	A            *ECPoint
	S            *ECPoint
	TCommits     []*ECPoint
	TauX         *big.Int
	Mu           *big.Int
	T            *big.Int
	ProductProof *InnerProductProofV2
}

// InnerProductProof represents an inner product proof
type InnerProductProofV2 struct {
	L []*ECPoint
	R []*ECPoint
	A *big.Int
	B *big.Int
}

type InnerProductWitness struct {
	A []*big.Int
	B []*big.Int
}

func NewInnerProductWitness(a, b []*big.Int) *InnerProductWitness {
	return &InnerProductWitness{A: a, B: b}
}

func (ipw *InnerProductWitness) GetA() []*big.Int {
	return ipw.A
}

func (ipw *InnerProductWitness) GetB() []*big.Int {
	return ipw.B
}

var (
	keccak256Pool = sync.Pool{
		New: func() interface{} {
			return sha3.NewLegacyKeccak256()
		},
	}

	rng = rand.Reader
)

func toInt(hash []byte, q *big.Int) *big.Int {
	bigIntHash := new(big.Int).SetBytes(hash)
	if bigIntHash.Sign() < 0 {
		return new(big.Int).Add(bigIntHash, new(big.Int).Lsh(big.NewInt(1), 256)).Mod(bigIntHash, q)
	}
	return bigIntHash.Mod(bigIntHash, q)
}

// mapInto maps a BigInteger seed into an elliptic curve point
func MapInto(seed *big.Int) *ECPoint {
	curve := btcec.S256()
	groupOrder := curve.Params().N
	b := curve.Params().B
	p := curve.Params().P
	var point *ECPoint
	success := false

	if Debug && DebugFull {
		fmt.Println("groupOrder", groupOrder)
		fmt.Println("b", b)
		fmt.Println("p", p)
	}

	for !success {
		if Debug && DebugFull {
			fmt.Println("seed", seed)
			fmt.Println("order", groupOrder)
		}
		x := new(big.Int).Mod(seed, groupOrder)
		if Debug && DebugFull {
			fmt.Println("x", x)
		}
		//        fmt.Println("x", hex.EncodeToString(x.Bytes()))
		x2 := new(big.Int).Mul(x, x)
		if Debug && DebugFull {
			fmt.Println("x2", x2)
		}
		x3 := new(big.Int).Mul(x2, x)
		if Debug && DebugFull {
			fmt.Println("x3", x3)
		}
		rhs := new(big.Int).Add(x3, b)
		if Debug && DebugFull {
			fmt.Println("rhs", rhs)
		}
		//        fmt.Println("rhs1", hex.EncodeToString(rhs.Bytes()))
		rhs.Mod(rhs, curve.Params().P)
		if Debug && DebugFull {
			fmt.Println("rhs mod P", rhs)
		}
		//        fmt.Println("rhs2", hex.EncodeToString(rhs.Bytes()))
		y := new(big.Int).ModSqrt(rhs, p)

		if y != nil {
			if Debug && DebugFull {
				fmt.Println("x", hex.EncodeToString(x.Bytes()))
				fmt.Println("y", hex.EncodeToString(y.Bytes()))
			}
			point = newECPointNoCheck(x, y)
			success = true
		} else {
			seed.Add(seed, big.NewInt(1))
		}
	}

	return point
}

func HashString(s string) *big.Int {
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	hasher.Write([]byte(s))
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

func PaddedHash(part1 string, i int) *big.Int {
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	hasher.Write([]byte(part1))

	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[28:], uint32(i))
	hasher.Write(buf)

	hashResult := new(big.Int).SetBytes(hasher.Sum(nil))
	if Debug && DebugFull {
		fmt.Println("hashResult", hashResult)
	}
	return hashResult
}

func HashWithSalt(id string, salt *big.Int) *big.Int {
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	hasher.Write([]byte(id))
	hasher.Write(salt.Bytes())
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

func RandomNumber(bits int) (*big.Int, error) {
	return rand.Int(rng, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	// for testing -- return big.NewInt(123456), nil
}

func RandomNumber256() (*big.Int, error) {
	return RandomNumber(256)
}

func hashUInt(hasher sha3.ShakeHash, integer *big.Int) {
	intArr := integer.Bytes()
	if len(intArr) >= 32 {
		hasher.Write(intArr[len(intArr)-32:])
	} else {
		shaArr := make([]byte, 32)
		copy(shaArr[32-len(intArr):], intArr)
		hasher.Write(shaArr)
	}
}

func randVectorV2(l int, q *big.Int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++ {
		x, err := RandomNumber256()
		if err != nil {
			if Debug && DebugFull {
				fmt.Println(err)
			}
			return nil
		}
		x = new(big.Int).Mod(x, q)
		result[i] = x
	}

	return result
}

func vectorCommitExp(points []*ECPoint, exponents []*big.Int) *ECPoint {
	if len(points) != len(exponents) {
		if Debug && DebugFull {
			fmt.Println("VectorCommitExp: Uh oh! Arrays not of the same length")
			fmt.Printf("len(pcs): %d\n", len(points))
			fmt.Printf("len(exponents): %d\n", len(exponents))
		}
	}

	count := len(points)

	var ret *ECPoint = nil

	for i := 0; i < count; i++ {
		if exponents[i].Cmp(BigIntZero) != 0 {
			if ret == nil {
				ret = points[i].Mult(exponents[i])
			} else {
				ret = ret.Add(points[i].Mult(exponents[i]))
			}
		}
	}

	return ret
}

func vectorBaseCommitGExpHExpBlinding(vb *VectorBase, gExp, hExp []*big.Int, blinding *big.Int) *ECPoint {
	gs := vb.Gs
	hs := vb.Hs

	if len(gs) != len(hs) || len(gs) != len(gExp) || len(gExp) != len(hExp) {
		if Debug && DebugFull {
			fmt.Println("TwoVectorPCommitWithGens: Uh oh! Arrays not of the same length")
			fmt.Printf("len(gs): %d\n", len(gs))
			fmt.Printf("len(hs): %d\n", len(hs))
			fmt.Printf("len(gExp): %d\n", len(gExp))
			fmt.Printf("len(hExp): %d\n", len(hExp))
		}
	}

	count := len(gs)

	var gsgExp *ECPoint = nil
	var hshExp *ECPoint = nil

	for i := 0; i < count; i++ {
		if gExp[i].Cmp(BigIntZero) != 0 {
			if gsgExp == nil {
				gsgExp = gs[i].Mult(gExp[i])
			} else {
				gsgExp = gsgExp.Add(gs[i].Mult(gExp[i]))
			}
		}
		if hExp[i].Cmp(BigIntZero) != 0 {
			if hshExp == nil {
				hshExp = hs[i].Mult(hExp[i])
			} else {
				hshExp = hshExp.Add(hs[i].Mult(hExp[i]))
			}
		}

	}

	if Debug && DebugFull {
		fmt.Println("gsgExp", gsgExp)
		fmt.Println("hshExp", hshExp)
	}

	hb := vb.H.Mult(blinding)
	if Debug && DebugFull {
		fmt.Println("hb", hb)
	}

	var ret *ECPoint = nil
	if gsgExp == nil && hshExp == nil {
		ret = hb
	} else if gsgExp == nil {
		ret = hshExp.Add(hb)
	} else if hshExp == nil {
		ret = gsgExp.Add(hb)
	} else {
		ret = gsgExp.Add(hshExp).Add(hb)
	}

	return ret
}

func computeChallengeFromECPoints(q *big.Int, points []*ECPoint) *big.Int {
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	for _, point := range points {
		pointBytes := point.Bytes()
		hasher.Write(pointBytes)
	}
	hash := hasher.Sum(nil)
	return toInt(hash, q)
}

func computeChallengeFromSaltECPoints(q *big.Int, salt *big.Int, points []*ECPoint) *big.Int {
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	hashUInt(hasher, salt)

	for _, point := range points {
		pointBytes := point.Bytes()
		hasher.Write(pointBytes)
	}
	hash := hasher.Sum(nil)
	return toInt(hash, q)
}

func computeChallengeFromPedersenCommit(q *big.Int, salt *big.Int, pcs []*PedersenCommit) *big.Int {
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	hashUInt(hasher, salt)

	for _, pc := range pcs {
		if pc.X.Cmp(BigIntZero) != 0 {
			pointBytes := pc.C.Bytes()
			hasher.Write(pointBytes)
		}
	}
	hash := hasher.Sum(nil)
	return toInt(hash, q)
}

func computeChallengeFromPedersenCommitECPoint(q *big.Int, salt *big.Int, pcsECPoint []*ECPoint) *big.Int {
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	hashUInt(hasher, salt)

	for _, pc := range pcsECPoint {
		if pc.X.Cmp(BigIntZero) != 0 {
			pointBytes := pc.Bytes()
			hasher.Write(pointBytes)
		}
	}
	hash := hasher.Sum(nil)
	return toInt(hash, q)
}

func computeChallengeFromInts(q *big.Int, ints []*big.Int) *big.Int {
	if Debug && DebugFull {
		fmt.Println("Computing hash")
	}
	hasher := keccak256Pool.Get().(sha3.ShakeHash)
	defer keccak256Pool.Put(hasher)
	hasher.Reset()

	for _, point := range ints {
		hashUInt(hasher, point)
		if Debug && DebugFull {
			fmt.Println(point.Text(16))
		}
	}
	if Debug && DebugFull {
		fmt.Println("Done")
	}
	hash := hasher.Sum(nil)
	return toInt(hash, q)
}

func powerVectorQ(l int, base *big.Int, q *big.Int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++ {
		result[i] = new(big.Int).Exp(base, big.NewInt(int64(i)), q)
	}

	return result
}

func vectorAddScalarQ(v []*big.Int, s *big.Int, q *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], s), q)
	}

	return result
}

func vectorMulScalarQ(v []*big.Int, s *big.Int, q *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], s), q)
	}

	return result
}

func vectorHadamardQ(v, w []*big.Int, q *big.Int) []*big.Int {
	if len(v) != len(w) {
		if Debug && DebugFull {
			fmt.Println("VectorHadamard: Uh oh! Arrays not of the same length")
			fmt.Printf("len(v): %d\n", len(w))
			fmt.Printf("len(w): %d\n", len(v))
		}
	}

	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], w[i]), q)
	}

	return result
}

func vectorHadamardECPointQ(v []*ECPoint, w []*big.Int, q *big.Int) []*ECPoint {
	if len(v) != len(w) {
		if Debug && DebugFull {
			fmt.Println("VectorHadamard: Uh oh! Arrays not of the same length")
			fmt.Printf("len(v): %d\n", len(w))
			fmt.Printf("len(w): %d\n", len(v))
		}
	}

	result := make([]*ECPoint, len(v))

	for i := range v {
		result[i] = v[i].Mult(w[i])
	}

	return result
}

func vectorAddQ(v, w []*big.Int, q *big.Int) []*big.Int {
	if len(v) != len(w) {
		if Debug && DebugFull {
			fmt.Println("VectorAdd: Uh oh! Arrays not of the same length")
			fmt.Printf("len(v): %d\n", len(w))
			fmt.Printf("len(w): %d\n", len(v))
		}
	}

	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], w[i]), q)
	}

	return result
}

func vectorSumECPointWithECPoint(v []*ECPoint, w []*ECPoint) []*ECPoint {
	result := make([]*ECPoint, len(v))

	for i := range v {
		result[i] = v[i].Add(w[i])
	}

	return result
}

func vectorSumECPoint(v []*ECPoint) *ECPoint {
	result := v[0]

	for i := 1; i < len(v); i++ {
		result = result.Add(v[i])
	}

	return result
}

func vectorSumQ(y []*big.Int, q *big.Int) *big.Int {
	result := big.NewInt(0)

	for _, j := range y {
		result = new(big.Int).Mod(new(big.Int).Add(result, j), q)
	}

	return result
}

// padLeft pads the string `str` with the string `pad` on the left until the total length is `l`.
// If `str` is longer than `l`, it returns the right-most `l` characters of `str`.
func padLeft(str, pad string, l int) string {
	// If str is longer than l, return the right-most l characters
	if len(str) > l {
		return str[len(str)-l:]
	}

	// Calculate the number of pad characters needed
	padCount := l - len(str)

	// Create the padding string
	padding := strings.Repeat(pad, padCount)

	// Concatenate the padding and the original string
	return padding + str
}

func strToBigIntArray(str string) []*big.Int {
	result := make([]*big.Int, len(str))

	for i := range str {
		t, success := new(big.Int).SetString(string(str[i]), 10)
		if success {
			result[i] = t
		}
	}

	return result
}

func reverse(l []*big.Int) []*big.Int {
	result := make([]*big.Int, len(l))

	for i := range l {
		result[i] = l[len(l)-i-1]
	}

	return result
}

func modInverse(a, m *big.Int) (*big.Int, error) {
	if m.Sign() != 1 {
		return nil, fmt.Errorf("big.Int: modulus not positive")
	}

	if m.Cmp(big.NewInt(1)) == 0 {
		return big.NewInt(0), nil
	}

	// Calculate (a mod m)
	modVal := new(big.Int).Set(a)
	if a.Sign() < 0 || a.CmpAbs(m) >= 0 {
		modVal.Mod(a, m)
	}

	if modVal.Cmp(big.NewInt(1)) == 0 {
		return big.NewInt(1), nil
	}

	result := new(big.Int)
	result.ModInverse(modVal, m)
	return result, nil
}

func vectorModInverseQ(v []*big.Int, q *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		inv, err := modInverse(v[i], q)
		if err != nil {
			return nil
		}
		result[i] = inv
	}

	return result
}

func innerProductQ(a []*big.Int, b []*big.Int, q *big.Int) *big.Int {
	if len(a) != len(b) {
		if Debug && DebugFull {
			fmt.Println("InnerProduct: Uh oh! Arrays not of the same length")
			fmt.Printf("len(a): %d\n", len(a))
			fmt.Printf("len(b): %d\n", len(b))
		}
	}

	c := big.NewInt(0)

	for i := range a {
		tmp1 := new(big.Int).Mul(a[i], b[i])
		c = new(big.Int).Add(c, new(big.Int).Mod(tmp1, q))
	}

	return new(big.Int).Mod(c, q)
}

func polyCommitment(a0 *big.Int, as []*big.Int) []*PedersenCommit {
	ret := make([]*PedersenCommit, len(as)+1)

	ret[0] = NewPedersenCommit(a0, BigIntZero)

	for i := 0; i < len(as); i++ {
		bf, _ := RandomNumber256()
		ret[i+1] = NewPedersenCommit(as[i], bf)
	}
	return ret
}

func generateSequence1_x_xx_xxx(n int, x *big.Int) []*big.Int {
	xs := make([]*big.Int, n)
	xs[0] = big.NewInt(1)

	for i := 1; i < n; i++ {
		x := new(big.Int).Mul(xs[i-1], x)
		if Debug && DebugFull {
			fmt.Println("x", x)
		}
		xs[i] = x
	}

	return xs
}

func evaluatePolyCommitment(polyCommitment []*PedersenCommit, x *big.Int) *PedersenCommit {
	xs := generateSequence1_x_xx_xxx(len(polyCommitment), x)

	multiplyPolyCommitment := make([]*PedersenCommit, len(polyCommitment))

	if Debug && DebugFull {
		fmt.Println("xs", xs)
	}

	for i := 0; i < len(polyCommitment); i++ {
		// create new PedersenCommit
		multiplyPolyCommitment[i] = NewPedersenCommit(new(big.Int).Mul(polyCommitment[i].A, xs[i]), new(big.Int).Mul(polyCommitment[i].X, xs[i]))
	}

	// sum the PedersenCommit
	sumPolyCommitmentA := big.NewInt(0)
	sumPolyCommitmentX := big.NewInt(0)

	for i := 0; i < len(multiplyPolyCommitment); i++ {
		sumPolyCommitmentA = new(big.Int).Add(sumPolyCommitmentA, multiplyPolyCommitment[i].A)
		sumPolyCommitmentX = new(big.Int).Add(sumPolyCommitmentX, multiplyPolyCommitment[i].X)
	}

	return NewPedersenCommit(sumPolyCommitmentA, sumPolyCommitmentX)
}

func commitPolyCommitmentECPointExp(polyCommitmentECPoint []*ECPoint, xs []*big.Int) *ECPoint {
	multiplyECPoint := make([]*ECPoint, len(polyCommitmentECPoint))

	if Debug && DebugFull {
		fmt.Println("xs", xs)
	}

	for i := 0; i < len(polyCommitmentECPoint); i++ {
		// create new PedersenCommit
		if Debug && DebugFull {
			fmt.Println("polyCommitment", i, polyCommitmentECPoint[i])
		}
		multiplyECPoint[i] = polyCommitmentECPoint[i].Mult(xs[i])
	}

	// sum the PedersenCommit
	sumECPoint := multiplyECPoint[0]

	for i := 1; i < len(multiplyECPoint); i++ {
		sumECPoint = sumECPoint.Add(multiplyECPoint[i])
	}

	return sumECPoint
}

// compareSlices compares two slices of *big.Int for equality
func compareSlices(slice1, slice2 []*big.Int) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i].Cmp(slice2[i]) != 0 {
			return false
		}
	}
	return true
}

func generateInnerProductProofV2(base *VectorBase, c *ECPoint, witness *InnerProductWitness, salt *big.Int) *InnerProductProofV2 {
	n := len(base.Gs)
	if !((n & (n - 1)) == 0) {
		if Debug && DebugFull {
			fmt.Println("generateInnerProductProof: Uh oh! n not a power of 2")
			fmt.Printf("n: %d\n", n)
		}
	}

	bc := bits.OnesCount(uint(n))

	if salt == nil {
		salt = big.NewInt(0)
	}

	return generateInnerProductProofSubV2(base, c, witness.GetA(), witness.GetB(), make([]*ECPoint, 0, bc), make([]*ECPoint, 0, bc), salt)
}

func generateInnerProductProofSubV2(base *VectorBase, P *ECPoint, as []*big.Int, bs []*big.Int, ls []*ECPoint, rs []*ECPoint, previousChallenge *big.Int) *InnerProductProofV2 {
	n := len(as)
	if n == 1 {
		return &InnerProductProofV2{L: ls, R: rs, A: as[0], B: bs[0]}
	}

	nPrime := n / 2

	asLeft := as[:nPrime]
	asRight := as[nPrime : nPrime*2]
	bsLeft := bs[:nPrime]
	bsRight := bs[nPrime : nPrime*2]

	gs := base.Gs
	gLeft := gs[:nPrime]
	gRight := gs[nPrime : nPrime*2]

	hs := base.Hs
	hLeft := hs[:nPrime]
	hRight := hs[nPrime : nPrime*2]

	cL := innerProductQ(asLeft, bsRight, base.Q)
	if Debug && DebugFull {
		fmt.Println("cL", cL)
	}
	cR := innerProductQ(asRight, bsLeft, base.Q)
	if Debug && DebugFull {
		fmt.Println("cR", cR)
	}

	L := vectorCommitExp(gRight, asLeft).Add(vectorCommitExp(hLeft, bsRight))
	if Debug && DebugFull {
		fmt.Println("L", L)
	}
	R := vectorCommitExp(gLeft, asRight).Add(vectorCommitExp(hRight, bsLeft))
	if Debug && DebugFull {
		fmt.Println("R", R)
	}

	u := base.H

	L = L.Add(u.Mult(cL))
	if Debug && DebugFull {
		fmt.Println("L", L)
	}
	ls = append(ls, L)

	R = R.Add(u.Mult(cR))
	if Debug && DebugFull {
		fmt.Println("R", R)
	}
	rs = append(rs, R)

	q := base.Q

	x := computeChallengeFromSaltECPoints(q, previousChallenge, []*ECPoint{L, R})

	if Debug && DebugFull {
		fmt.Println("x", x)
	}

	xInv := new(big.Int).ModInverse(x, q)

	if Debug && DebugFull {
		fmt.Println("xInv", xInv)
	}

	xSquare := new(big.Int).Exp(x, big.NewInt(2), q)

	if Debug && DebugFull {
		fmt.Println("xSquare", xSquare)
	}

	xSquareInv := new(big.Int).ModInverse(xSquare, q)

	if Debug && DebugFull {
		fmt.Println("xSquareInv", xSquareInv)
	}

	xs := make([]*big.Int, nPrime)
	for i := 0; i < nPrime; i++ {
		xs[i] = x
	}

	if Debug && DebugFull {
		fmt.Println("xs", xs)
	}

	xInverse := make([]*big.Int, nPrime)
	for i := 0; i < nPrime; i++ {
		xInverse[i] = xInv
	}

	if Debug && DebugFull {
		fmt.Println("xInverse", xInverse)
	}

	gPrime := vectorSumECPointWithECPoint(vectorHadamardECPointQ(gLeft, xInverse, q), vectorHadamardECPointQ(gRight, xs, q))
	if Debug && DebugFull {
		fmt.Println("gPrime", gPrime)
	}

	hPrime := vectorSumECPointWithECPoint(vectorHadamardECPointQ(hLeft, xs, q), vectorHadamardECPointQ(hRight, xInverse, q))
	if Debug && DebugFull {
		fmt.Println("hPrime", hPrime)
	}

	aPrime := vectorAddQ(vectorMulScalarQ(asLeft, x, q), vectorMulScalarQ(asRight, xInv, q), q)
	if Debug && DebugFull {
		fmt.Println("aPrime", aPrime)
	}

	bPrime := vectorAddQ(vectorMulScalarQ(bsLeft, xInv, q), vectorMulScalarQ(bsRight, x, q), q)

	if Debug && DebugFull {
		fmt.Println("bPrime", bPrime)
	}

	PPrime := P.Add(L.Mult(xSquare)).Add(R.Mult(xSquareInv))

	if Debug && DebugFull {
		fmt.Println("PPrime", PPrime)
	}

	basePrime := NewVectorBase(gPrime, hPrime, nil /* G */, u, q)

	if Debug && DebugFull {
		fmt.Println("basePrime", basePrime)
	}

	return generateInnerProductProofSubV2(basePrime, PPrime, aPrime, bPrime, ls, rs, x)
}

func NewRangeProofV2(vectorBase *VectorBase, commitment *PedersenCommit) *RangeProofV2 {
	if vectorBase == nil || commitment == nil {
		return nil
	}

	if Debug && DebugFull {
		fmt.Println("commitment", commitment)
	}

	number := commitment.A
	q := vectorBase.Q
	if Debug && DebugFull {
		fmt.Println("q", q)
	}

	n := len(vectorBase.Gs)
	aL := reverse(strToBigIntArray(padLeft(fmt.Sprintf("%b", number.Mod(number, q)), "0", n)))

	if Debug && DebugFull {
		fmt.Println("aL", aL)
	}

	aR := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		aR[i] = big.NewInt(-1)
	}
	aR = vectorAddQ(aL, aR, q)

	if Debug && DebugFull {
		fmt.Println("aR", aR)
	}

	alpha, err := RandomNumber256()
	if err != nil {
		// print err
		if Debug && DebugFull {
			fmt.Println("err", err)
		}
		return nil
	}

	_ = alpha

	a := vectorBaseCommitGExpHExpBlinding(vectorBase, aL, aR, alpha)

	if Debug && DebugFull {
		fmt.Println("a", a)
	}

	sL := randVectorV2(n, q)
	sR := randVectorV2(n, q)
	rho, _ := RandomNumber256()

	s := vectorBaseCommitGExpHExpBlinding(vectorBase, sL, sR, rho)

	if Debug && DebugFull {
		fmt.Println("s", s)
	}

	y := computeChallengeFromECPoints(q, []*ECPoint{commitment.C, a, s})

	if Debug && DebugFull {
		fmt.Println("y", y)
	}

	ys := generateSequence1_x_xx_xxx(n, y)

	if Debug && DebugFull {
		fmt.Println("ys", ys)
	}

	z := computeChallengeFromInts(q, []*big.Int{y})

	if Debug && DebugFull {
		fmt.Println("z", z)
	}

	zSquared := new(big.Int).Mod(new(big.Int).Exp(z, big.NewInt(2), nil), q)

	if Debug && DebugFull {
		fmt.Println("zSquared", zSquared)
	}

	zCubed := new(big.Int).Mod(new(big.Int).Exp(z, big.NewInt(3), nil), q)

	if Debug && DebugFull {
		fmt.Println("zCubed", zCubed)
	}

	negz := new(big.Int).Neg(z)
	l0 := vectorAddScalarQ(aL, negz, q)

	if Debug && DebugFull {
		fmt.Println("l0", l0)
	}

	_ = sL
	_ = sR
	_ = rho

	twos := powerVectorQ(n, big.NewInt(2), q)

	if Debug && DebugFull {
		fmt.Println("twos", twos)
	}

	l1 := sL

	if Debug && DebugFull {
		fmt.Println("l1", l1)
	}

	twoTimesZSquared := vectorMulScalarQ(twos, zSquared, q)

	if Debug && DebugFull {
		fmt.Println("twoTimesZSquared", twoTimesZSquared)
	}

	r0 := vectorAddQ(vectorHadamardQ(ys, vectorAddScalarQ(aR, z, q), q), twoTimesZSquared, q)

	if Debug && DebugFull {
		fmt.Println("r0", r0)
	}

	r1 := vectorHadamardQ(sR, ys, q)

	if Debug && DebugFull {
		fmt.Println("r1", r1)
	}

	sumys := vectorSumQ(ys, q)
	zSubZSquared := new(big.Int).Sub(z, zSquared)
	sumysMultiplyZSubZSquared := new(big.Int).Mul(sumys, zSubZSquared)
	zCubedShiftLeft := new(big.Int).Lsh(zCubed, uint(n))
	zCubedShiftLeftSubZCubed := new(big.Int).Sub(zCubedShiftLeft, zCubed)
	k := new(big.Int).Sub(sumysMultiplyZSubZSquared, zCubedShiftLeftSubZCubed)

	if Debug && DebugFull {
		fmt.Println("k", k)
	}

	t0 := new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(zSquared, number)), q)

	if Debug && DebugFull {
		fmt.Println("t0", t0)
	}

	l1r0innerproduct := innerProductQ(l1, r0, q)
	if Debug && DebugFull {
		fmt.Println("l1r0innerproduct", l1r0innerproduct)
	}
	l0r1innerproduct := innerProductQ(l0, r1, q)
	if Debug && DebugFull {
		fmt.Println("l0r1innerproduct", l0r1innerproduct)
	}
	t1 := new(big.Int).Add(l1r0innerproduct, l0r1innerproduct)

	if Debug && DebugFull {
		fmt.Println("t1", t1)
	}

	t2 := innerProductQ(l1, r1, q)

	if Debug && DebugFull {
		fmt.Println("t2", t2)
	}

	polyCommitment := polyCommitment(t0, []*big.Int{t1, t2})

	if Debug && DebugFull {
		for i := 0; i < len(polyCommitment); i++ {
			fmt.Println("polyCommitment", i, polyCommitment[i])
		}
	}

	x := computeChallengeFromPedersenCommit(q, z, polyCommitment)

	if Debug && DebugFull {
		fmt.Println("x", x)
	}

	evalCommit := evaluatePolyCommitment(polyCommitment, x)

	if Debug && DebugFull {
		fmt.Println("evalCommit", evalCommit)
	}

	tauX := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(zSquared, commitment.X), evalCommit.X), q)

	if Debug && DebugFull {
		fmt.Println("tauX", tauX)
	}

	t := evalCommit.A

	if Debug && DebugFull {
		fmt.Println("t", t)
	}

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, x)), q)

	if Debug && DebugFull {
		fmt.Println("mu", mu)
	}

	uChallenge := computeChallengeFromInts(q, []*big.Int{x, tauX, mu, t})

	if Debug && DebugFull {
		fmt.Println("uChallenge", uChallenge)
	}

	u := vectorBase.G.Mult(uChallenge)

	if Debug && DebugFull {
		fmt.Println("u", u)
	}

	hs := vectorBase.Hs

	if Debug && DebugFull {
		fmt.Println("hs", hs)
	}

	gs := vectorBase.Gs

	if Debug && DebugFull {
		fmt.Println("gs", gs)
	}

	hPrimes := vectorHadamardECPointQ(hs, vectorModInverseQ(ys, q), q)

	if Debug && DebugFull {
		fmt.Println("hPrimes", hPrimes)
	}

	l := vectorAddQ(l0, vectorMulScalarQ(l1, x, q), q)

	if Debug && DebugFull {
		fmt.Println("l", l)
	}

	r := vectorAddQ(r0, vectorMulScalarQ(r1, x, q), q)

	if Debug && DebugFull {
		fmt.Println("r", r)
	}

	hExp := vectorAddQ(vectorMulScalarQ(ys, z, q), twoTimesZSquared, q)

	if Debug && DebugFull {
		fmt.Println("hExp", hExp)
	}

	hprimescommithexp := vectorCommitExp(hPrimes, hExp)

	if Debug && DebugFull {
		fmt.Println("hprimescommithexp", hprimescommithexp)
	}

	umultiplyt := u.Mult(t)

	if Debug && DebugFull {
		fmt.Println("umultiplyt", umultiplyt)
	}

	hmultiplymu := vectorBase.H.Mult(mu)

	if Debug && DebugFull {
		fmt.Println("hmultiplymu", hmultiplymu)
	}

	smultiplyx := s.Mult(x)

	gssum := vectorSumECPoint(gs)
	if Debug && DebugFull {
		fmt.Println("gssum", gssum)
	}

	gssummulnegz := gssum.Mult(negz)

	if Debug && DebugFull {
		fmt.Println("gssummulnegz", gssummulnegz)
	}

	P := a.Add(smultiplyx).Add(gssummulnegz).Add(hprimescommithexp).Add(umultiplyt).Sub(hmultiplymu)

	if Debug && DebugFull {
		fmt.Println("P", P)
	}

	primeBase := NewVectorBase(gs, hPrimes, nil /* G */, u, q)

	if Debug && DebugFull {
		fmt.Println("primeBase", primeBase)
	}

	innerProductWitness := NewInnerProductWitness(l, r)

	if Debug && DebugFull {
		fmt.Println("innerProductWitness", innerProductWitness)
	}

	proof := generateInnerProductProofV2(primeBase, P, innerProductWitness, uChallenge)

	if Debug && DebugFull {
		fmt.Println("proof", proof)

		fmt.Println("proof.L", proof.L)
		fmt.Println("proof.R", proof.R)
		fmt.Println("proof.A", proof.A)
		fmt.Println("proof.B", proof.B)

		fmt.Println("y", y)
		fmt.Println("z", z)
		fmt.Println("x", x)
		fmt.Println("u", uChallenge)
	}

	// create polyCommitment where each one has a commitment

	tCommits := make([]*ECPoint, 0, len(polyCommitment))
	for i := 0; i < len(polyCommitment); i++ {
		if polyCommitment[i].X.Cmp(BigIntZero) != 0 {
			tCommits = append(tCommits, polyCommitment[i].C)
		}
	}

	return &RangeProofV2{
		A:            a,
		S:            s,
		TCommits:     tCommits,
		TauX:         tauX,
		Mu:           mu,
		T:            t,
		ProductProof: proof,
	}
}

func VerifyRangeProofV2(vectorBase *VectorBase, input *PedersenCommit, proof *RangeProofV2) bool {
	if vectorBase == nil || input == nil || proof == nil {
		if Debug && DebugFull {
			if Debug && DebugFull {
				fmt.Println("VerifyRangeProof: Uh oh! Nil input or proof")
			}
		}
		return false
	}

	n := len(vectorBase.Gs)

	a := proof.A
	s := proof.S

	q := vectorBase.Q

	y := computeChallengeFromECPoints(q, []*ECPoint{input.C, a, s})

	if Debug && DebugFull {
		fmt.Println("y", y)
	}

	ys := generateSequence1_x_xx_xxx(n, y)

	if Debug && DebugFull {
		fmt.Println("ys", ys)
	}

	z := computeChallengeFromInts(q, []*big.Int{y})

	if Debug && DebugFull {
		fmt.Println("z", z)
	}

	zSquared := new(big.Int).Mod(new(big.Int).Exp(z, big.NewInt(2), nil), q)

	if Debug && DebugFull {
		fmt.Println("zSquared", zSquared)
	}

	zCubed := new(big.Int).Mod(new(big.Int).Exp(z, big.NewInt(3), nil), q)

	if Debug && DebugFull {
		fmt.Println("zCubed", zCubed)
	}

	twos := powerVectorQ(n, big.NewInt(2), q)

	if Debug && DebugFull {
		fmt.Println("twos", twos)
	}

	twoTimesZSquared := vectorMulScalarQ(twos, zSquared, q)

	if Debug && DebugFull {
		fmt.Println("twoTimesZSquared", twoTimesZSquared)
	}

	tCommits := proof.TCommits

	if Debug && DebugFull {
		fmt.Println("tCommits", tCommits)
	}

	x := computeChallengeFromPedersenCommitECPoint(q, z, tCommits)

	if Debug && DebugFull {
		fmt.Println("x", x)
	}

	tauX := proof.TauX
	mu := proof.Mu
	t := proof.T

	sumys := vectorSumQ(ys, q)
	zSubZSquared := new(big.Int).Sub(z, zSquared)
	sumysMultiplyZSubZSquared := new(big.Int).Mul(sumys, zSubZSquared)
	zCubedShiftLeft := new(big.Int).Lsh(zCubed, uint(n))
	zCubedShiftLeftSubZCubed := new(big.Int).Sub(zCubedShiftLeft, zCubed)
	k := new(big.Int).Sub(sumysMultiplyZSubZSquared, zCubedShiftLeftSubZCubed)

	lhsPC := NewPedersenCommit(new(big.Int).Sub(t, k), tauX)
	lhs := lhsPC.C
	if Debug && DebugFull {
		fmt.Println("lhs", lhs)
	}

	xSquared := new(big.Int).Exp(x, big.NewInt(2), nil)

	rhsx := commitPolyCommitmentECPointExp(tCommits, []*big.Int{x, xSquared})
	if Debug && DebugFull {
		fmt.Println("rhsx", rhsx)
	}

	testrhsx := commitPolyCommitmentECPointExp(tCommits[:1], []*big.Int{x})
	if Debug && DebugFull {
		fmt.Println("testrhsx", testrhsx)
	}

	rhs := rhsx.Add(input.C.Mult(zSquared))

	if Debug && DebugFull {
		fmt.Println("rhs", rhs)
	}

	if !lhs.Equal(rhs) {
		if Debug && DebugFull {
			fmt.Println("Range proof verification failed")
		}
		return false
	}

	uChallenge := computeChallengeFromInts(q, []*big.Int{x, tauX, mu, t})

	if Debug && DebugFull {
		fmt.Println("uChallenge", uChallenge)
	}

	u := vectorBase.G.Mult(uChallenge)

	if Debug && DebugFull {
		fmt.Println("u", u)
	}

	hs := vectorBase.Hs
	gs := vectorBase.Gs
	hPrimes := vectorHadamardECPointQ(hs, vectorModInverseQ(ys, q), q)

	if Debug && DebugFull {
		fmt.Println("hPrimes", hPrimes)
	}

	hExp := vectorAddQ(vectorMulScalarQ(ys, z, q), twoTimesZSquared, q)

	if Debug && DebugFull {
		fmt.Println("hExp", hExp)
	}

	P := a.Add(s.Mult(x)).Add(vectorSumECPoint(gs).Mult(new(big.Int).Neg(z))).Add(vectorCommitExp(hPrimes, hExp)).Add(u.Mult(t)).Sub(vectorBase.H.Mult(mu))

	if Debug && DebugFull {
		fmt.Println("P", P)
	}

	primeBase := NewVectorBase(gs, hPrimes, nil /* G */, u, q)

	return verifyInnerProductProofV2(primeBase, P, proof.ProductProof, uChallenge)
}

// Function to multiply each element in the slice by a given multiplier
func multiplySlice(challengeVector []*big.Int, multiplier *big.Int) []*big.Int {
	sleft := make([]*big.Int, len(challengeVector))
	for i, val := range challengeVector {
		sleft[i] = new(big.Int).Mul(val, multiplier)
	}
	return sleft
}

func verifyInnerProductProofV2(params *VectorBase, c *ECPoint, proof *InnerProductProofV2, salt *big.Int) bool {
	ls := proof.L
	rs := proof.R
	challenges := make([]*big.Int, 0, len(ls))
	q := params.Q
	previousChallenge := salt
	for i := 0; i < len(ls); i++ {
		l := ls[i]
		r := rs[i]
		x := computeChallengeFromSaltECPoints(q, previousChallenge, []*ECPoint{l, r})
		challenges = append(challenges, x)
		xInv := new(big.Int).ModInverse(x, q)
		c = c.Add(l.Mult(new(big.Int).Exp(x, big.NewInt(2), q))).Add(r.Mult(new(big.Int).Exp(xInv, big.NewInt(2), q)))
		previousChallenge = x
	}
	if Debug && DebugFull {
		fmt.Println("challenges", challenges)
	}
	n := len(params.Gs)

	otherExponents := make([]*big.Int, n)

	otherExponents[0] = big.NewInt(1)
	for i := 0; i < len(challenges); i++ {
		otherExponents[0] = new(big.Int).Mul(otherExponents[0], challenges[i])
		otherExponents[0] = new(big.Int).Mod(otherExponents[0], q)
	}
	otherExponents[0] = new(big.Int).ModInverse(otherExponents[0], q)

	challenges = reverse(challenges)

	bitSet := make([]bool, n)

	for i := 0; i < n/2; i++ {
		for j := 0; (1<<j)+i < n; j++ {
			i1 := i + (1 << j)
			if bitSet[i1] {
				// Do nothing
			} else {
				otherExponents[i1] = new(big.Int).Mul(otherExponents[i], new(big.Int).Exp(challenges[j], big.NewInt(2), q))
				otherExponents[i1] = new(big.Int).Mod(otherExponents[i1], q)
				bitSet[i1] = true
			}
		}
	}

	// Print the otherExponents for verification
	if Debug && DebugFull {
		for i, val := range otherExponents {
			fmt.Printf("otherExponents[%d]: %s\n", i, val.String())
		}
	}

	challengeVector2 := make([]*big.Int, n)

	for i := 0; i < n; i++ {
		bigIntI := big.NewInt(int64(i))
		ithChallenge := big.NewInt(1)
		for j := 0; j < len(challenges); j++ {
			if bigIntI.Bit(j) == 1 {
				ithChallenge.Mul(ithChallenge, challenges[j])
				ithChallenge.Mod(ithChallenge, q)
			} else {
				inv := new(big.Int).ModInverse(challenges[j], q)
				ithChallenge.Mul(ithChallenge, inv)
				ithChallenge.Mod(ithChallenge, q)
			}
		}
		challengeVector2[i] = ithChallenge
	}

	// Print the challengeVector2 for verification
	if Debug && DebugFull {
		for i, val := range challengeVector2 {
			fmt.Printf("challengeVector2[%d]: %s\n", i, val.String())
		}
	}

	challengeVector := otherExponents

	if compareSlices(challengeVector, challengeVector2) {
		if Debug && DebugFull {
			fmt.Println("Challenge vectors are equal")
		}
	} else {
		return false
	}

	sleft := multiplySlice(challengeVector, proof.A)

	if Debug && DebugFull {
		for i, val := range sleft {
			fmt.Println("sleft", i, val)
		}
	}

	// Reverse the challengeVector
	reversedChallengeVector := reverse(challengeVector)

	// Multiply each element in the reversed challengeVector by proofB
	sright := multiplySlice(reversedChallengeVector, proof.B)

	// Print the result
	if Debug && DebugFull {
		for i, val := range sright {
			fmt.Println("sright", i, val)
		}
	}

	// Compute prod
	prod := new(big.Int).Mul(proof.A, proof.B)
	prod.Mod(prod, q)

	g := vectorCommitExp(params.Gs, sleft)
	h := vectorCommitExp(params.Hs, sright)

	cProof := g.Add(h).Add((params.H).Mult(prod))

	if Debug && DebugFull {
		fmt.Println("c", c)
		fmt.Println("cProof", cProof)
	}

	return cProof.Equal(c)
}
