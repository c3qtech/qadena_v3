package common

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"encoding/base64"

	"github.com/btcsuite/btcd/btcec/v2"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"golang.org/x/crypto/ripemd160"

	"fmt"

	ecies "github.com/ecies/go/v2"

	cmdcfg "github.com/c3qtech/qadena_v3/cmd/config"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

//// Elliptic Curve needed for Pedersen commitments

type ECPoint struct {
	X, Y *big.Int
}

type ECPointInfo struct {
	ECPoint  *ECPoint
	NodeType string
	NodeID   string
}

func (p *ECPoint) String() string {
	return fmt.Sprintf("hex(%s, %s)/dec(%s, %s)", hex.EncodeToString(p.X.Bytes()), hex.EncodeToString(p.Y.Bytes()), p.X, p.Y)
}

type PedersenCommit struct {
	A *big.Int // amount
	X *big.Int // binding factor
	C *ECPoint // commitment
}

// used for pedersen commitments
type cryptoParams struct {
	Curve elliptic.Curve // curve
	Gs    []*ECPoint     // slice of gen 1 for BP
	Hs    []*ECPoint     // slice of gen 2 for BP
	N     *big.Int       // scalar prime (group order, same as Q in VectorBase)
	U     *ECPoint       // a point that is a fixed group element with an unknown discrete-log relative to g,h
	V     int            // Vector length
	G     *ECPoint       // G value for commitments of a single value
	H     *ECPoint       // H value for commitments of a single value

	BaseG *ECPoint // secp256k1 curve Base G
}

type VectorBase struct {
	Gs []*ECPoint
	Hs []*ECPoint
	H  *ECPoint
	G  *ECPoint
	Q  *big.Int // group order
}

var ECPedersen cryptoParams

var vecLength = 128

var bigIntMax *big.Int = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(vecLength)), nil)

func NewECPoint(x, y *big.Int) *ECPoint {
	if !ECPedersen.Curve.IsOnCurve(x, y) {
		if Debug && DebugFull {
			fmt.Printf("NewECPoint(%s, %s) is not on the curve", x, y)
		}
		return nil
	}
	ret := new(ECPoint)
	ret.X = x
	ret.Y = y
	return ret
}

func newECPointNoCheck(x, y *big.Int) *ECPoint {
	ret := new(ECPoint)
	ret.X = x
	ret.Y = y
	return ret
}

// Equal returns true if points p (self) and p2 (arg) are the  same.
func (p *ECPoint) Equal(p2 *ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

func BaseGMult(s []byte) *ECPoint {
	//	X, Y := ECPedersen.Curve.ScalarBaseMult(s)
	//	res2 := newECPointNoCheck(X, Y)
	//	fmt.Println("res", res)

	res := ECPedersen.BaseG.MultBytes(s)
	//	fmt.Println("res2", res2)

	/*
		fmt.Println("X, Y", X, Y)


		X0, Y0 := ECPedersen.Curve.ScalarMult(GX, GY, s)

		fmt.Println("X0, Y0", X0, Y0)
	*/

	return res
}

// Mult multiplies point p by scalar s and returns the resulting point
func (p *ECPoint) Mult(s *big.Int) *ECPoint {
	modS := new(big.Int).Mod(s, ECPedersen.N)
	X, Y := ECPedersen.Curve.ScalarMult(p.X, p.Y, modS.Bytes())
	return newECPointNoCheck(X, Y)
}

// Mult multiplies point p by scalar s (in bytes) and returns the resulting point
func (p *ECPoint) MultBytes(s []byte) *ECPoint {
	X, Y := ECPedersen.Curve.ScalarMult(p.X, p.Y, s)
	return newECPointNoCheck(X, Y)
}

// Add adds points p and p2 and returns the resulting point
func (p *ECPoint) Add(p2 *ECPoint) *ECPoint {
	X, Y := ECPedersen.Curve.Add(p.X, p.Y, p2.X, p2.Y)
	return newECPointNoCheck(X, Y)
}

func (p *ECPoint) Sub(p2 *ECPoint) *ECPoint {
	negP2 := p2.Neg()
	//	X, Y := ECForBinding.C.Add(p.X, p.Y, negP2.X, negP2.Y)
	X, Y := ECPedersen.Curve.Add(p.X, p.Y, negP2.X, negP2.Y)
	return newECPointNoCheck(X, Y)
}

// Neg returns the additive inverse of point p
func (p *ECPoint) Neg() *ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, ECPedersen.Curve.Params().P) // mod P is fine here because we're describing a curve point
	return newECPointNoCheck(p.X, modValue)
}

func (c cryptoParams) ZeroECPoint() *ECPoint {
	return newECPointNoCheck(big.NewInt(0), big.NewInt(0))
}

func GetVectorBase() *VectorBase {
	return ECPedersen.getVectorBase()
}

func (c cryptoParams) getVectorBase() *VectorBase {
	return &VectorBase{Gs: c.Gs, Hs: c.Hs, G: c.G, H: c.H, Q: c.N}
}

func NewVectorBase(Gs []*ECPoint, Hs []*ECPoint, G *ECPoint, H *ECPoint, Q *big.Int) *VectorBase {
	return &VectorBase{Gs: Gs, Hs: Hs, G: G, H: H, Q: Q}
}

func ECPointFromBytes(b []byte) (*ECPoint, error) {
	ret := new(ECPoint)
	// convert b to x,y using ecies
	pubKey, err := ecies.NewPublicKeyFromBytes(b)

	if err != nil {
		return ret, err
	}

	ret.X = pubKey.X
	ret.Y = pubKey.Y

	return ret, nil
}

func (p *ECPoint) Bytes() []byte {
	return elliptic.MarshalCompressed(ECPedersen.Curve, p.X, p.Y)
}

func (p *ECPoint) B64Address() string {
	pubKey := elliptic.MarshalCompressed(ECPedersen.Curve, p.X, p.Y)
	return base64.StdEncoding.EncodeToString(pubKey)
}

func (p *ECPoint) Bech32Address() string {
	var addressBytes []byte

	if cmdcfg.QadenaUsesEthSecP256k1 {
		// Ethereum-style: Keccak256 of uncompressed pubkey (without 0x04 prefix), last 20 bytes
		uncompressed := elliptic.Marshal(ECPedersen.Curve, p.X, p.Y)
		hash := ethcrypto.Keccak256(uncompressed[1:]) // skip 0x04 prefix
		addressBytes = hash[len(hash)-20:]
	} else {
		// Cosmos-style: RIPEMD160(SHA256(compressedPubKey))
		pubKey := elliptic.MarshalCompressed(ECPedersen.Curve, p.X, p.Y)
		sha := sha256.Sum256(pubKey)
		hasher := ripemd160.New()
		hasher.Write(sha[:])
		addressBytes = hasher.Sum(nil)
	}

	// Convert to bech32 string using cosmos-sdk
	bech32Addr, err := sdk.Bech32ifyAddressBytes(sdk.GetConfig().GetBech32AccountAddrPrefix(), addressBytes)
	if err != nil {
		return ""
	}

	return bech32Addr
}

// binding ECPoint

// Equal returns true if points p (self) and p2 (arg) are the  same.
func (p *ECPoint) BindingEqual(p2 *ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

// NewECPrimeGroupKeyV2 returns the curve (field),
// Generator 1 x&y, Generator 2 x&y, order of the generators
func NewECPrimeGroupKeyV2(n int) cryptoParams {
	curve := btcec.S256()

	var u *ECPoint = MapInto(HashString("U"))
	var cg *ECPoint = MapInto(HashString("G"))
	var ch *ECPoint = MapInto(HashString("H"))

	if Debug && DebugFull {
		fmt.Println("U", u)
		fmt.Println("G", cg)
		fmt.Println("H", ch)
	}

	gVals := make([]*ECPoint, n)
	hVals := make([]*ECPoint, n)

	for i := 0; i < n; i++ {
		gVals[i] = MapInto(PaddedHash("G", i))
	}

	for i := 0; i < n; i++ {
		hVals[i] = MapInto(PaddedHash("H", i))
	}

	curValue := btcec.S256().Gx
	if Debug && DebugFull {
		fmt.Println("Gx", curValue)
	}

	if Debug && DebugFull {
		fmt.Println("G", cg)
		fmt.Println("H", ch)
	}

	gx, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	gy, _ := hex.DecodeString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

	BaseGX := new(big.Int).SetBytes(gx)
	BaseGY := new(big.Int).SetBytes(gy)

	if Debug && DebugFull {
		fmt.Println("BaseGX, BaseGY", BaseGX, BaseGY)
	}

	BaseG := newECPointNoCheck(BaseGX, BaseGY)

	return cryptoParams{
		curve,
		gVals,
		hVals,
		curve.N,
		u,
		n,
		cg,
		ch,
		BaseG,
	}
}

// c=r*G+a*H
// where c is the commitment
// r is the blinding factor
// G is the pedersen commit
// a is the commited value
// H is the curved point (which is known)

// ret.A = the commited value
// ret.X = the blinding factor
// ret.C = the commitment which has the formula of c=a*G+r*H
func NewPedersenCommit(amount, x *big.Int) *PedersenCommit {
	if amount == nil {
		return nil
	}
	ret := new(PedersenCommit)

	ret.A = new(big.Int).Mod(amount, ECPedersen.N)

	if Debug && DebugFull {
		if ret.A.Cmp(amount) != 0 {
			fmt.Println("A (mod N)", ret.A)
		} else {
			fmt.Println("A", ret.A)
		}
	}

	if x == nil {
		x, _ = GenerateRandomBlindingFactor()
	}

	ret.X = new(big.Int).Mod(x, ECPedersen.N)
	if Debug && DebugFull {
		if ret.X.Cmp(x) != 0 {
			fmt.Println("X (mod N)", ret.X)
		} else {
			fmt.Println("X", ret.X)
		}
	}

	// print G
	if Debug && DebugFull {
		fmt.Println("G", ECPedersen.G, hex.EncodeToString(ECPedersen.G.X.Bytes()), hex.EncodeToString(ECPedersen.G.Y.Bytes()))
	}
	// print H
	if Debug && DebugFull {
		fmt.Println("H", ECPedersen.H, hex.EncodeToString(ECPedersen.H.X.Bytes()), hex.EncodeToString(ECPedersen.H.Y.Bytes()))
	}

	ga := ECPedersen.G.Mult(ret.A)
	hx := ECPedersen.H.Mult(ret.X)
	ret.C = ga.Add(hx)

	if Debug && DebugFull {
		fmt.Println("ga", ga)
		fmt.Println("hx", hx)
		fmt.Println("C", ret.C)
	}

	return ret
}

func GenerateRandomBlindingFactor() (n *big.Int, err error) {
	fmt.Println("GenerateRandomBlindingFactor", ECPedersen.N)
	r, err := RandomNumber256()
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(r, ECPedersen.N), nil
}

/*
func (p *PedersenCommit) UpdatePedersenCommitXValue(x *big.Int) {
	p.X = x
	C := ECPedersen.G.Mult(p.A).Add(ECPedersen.H.Mult(p.X)) //commitment to amount with blinding factor x
	p.C = C
}
*/

// takes input & transfer, computes "change.A = input.A - transfer.A" & blinding factor change.X (note that input.A - transfer.A - change.A = 0)
func SubPedersenCommit(input, transfer *PedersenCommit) *PedersenCommit {
	if input == nil || transfer == nil {
		return nil
	}
	if Debug && DebugFull {
		fmt.Println("SubPedersenCommit", input)
	}
	diff := big.NewInt(0)
	diff.Sub(input.A, transfer.A)
	if Debug && DebugFull {
		fmt.Println("diff", diff)
	}
	if diff.Cmp(BigIntZero) < 0 {
		if Debug && DebugFull {
			fmt.Println("cannot commit transfer=", transfer.A, ">", "input=", input.A)
		}
		return nil
	}

	changeX := big.NewInt(0)
	changeX.Sub(input.X, transfer.X)
	change := NewPedersenCommit(diff, changeX)

	if Debug && DebugFull {
		fmt.Println("input", PrettyPrint(input))
		fmt.Println("minus transfer", PrettyPrint(transfer))
		fmt.Println("output", PrettyPrint(change))
	}
	return change
}

func SubPedersenCommitNoMinCheck(input, transfer *PedersenCommit) *PedersenCommit {
	if input == nil || transfer == nil {
		return nil
	}
	if Debug && DebugFull {
		fmt.Println("SubPedersenCommitNoMinCheck", input)
	}
	diff := big.NewInt(0)
	diff.Sub(input.A, transfer.A)
	if Debug && DebugFull {
		fmt.Println("diff", diff)
	}

	changeX := big.NewInt(0)
	changeX.Sub(input.X, transfer.X)
	change := NewPedersenCommit(diff, changeX)

	if Debug && DebugFull {
		fmt.Println("input", PrettyPrint(input))
		fmt.Println("minus transfer", PrettyPrint(transfer))
		fmt.Println("output", PrettyPrint(change))
	}
	return change
}

// takes input & transfer, computes "output.A  = input.A + transfer.A" & blinding factor output.X (note that output.A - input.A - transfer.A = 0)
func AddPedersenCommit(input, transfer *PedersenCommit) *PedersenCommit {
	if input == nil || transfer == nil {
		return nil
	}

	if Debug && DebugFull {
		fmt.Println("AddPedersenCommit", input)
	}

	sum := big.NewInt(0)
	sum.Add(input.A, transfer.A)
	if Debug && DebugFull {
		fmt.Println("sum", sum)
	}
	if sum.Cmp(bigIntMax) > 0 {
		if Debug && DebugFull {
			fmt.Println("cannot commit input=", input.A, "+ transfer=", transfer.A, "> max=", bigIntMax)
		}
		return nil
	}

	sumX := big.NewInt(0)
	sumX.Add(input.X, transfer.X)
	if Debug && DebugFull {
		fmt.Println("sumX", sumX)
	}
	output := NewPedersenCommit(sum, sumX)

	if Debug && DebugFull {
		fmt.Println("input", PrettyPrint(input))
		fmt.Println("plus transfer", PrettyPrint(transfer))
		fmt.Println("output", PrettyPrint(output))
	}
	return output
}

// takes input & transfer, computes "output.A  = input.A + transfer.A" & blinding factor output.X (note that output.A - input.A - transfer.A = 0)
func AddPedersenCommitNoMaxCheck(input, transfer *PedersenCommit) *PedersenCommit {
	if input == nil || transfer == nil {
		return nil
	}

	if Debug && DebugFull {
		fmt.Println("AddPedersenCommitNoMaxCheck", input)
	}

	sum := big.NewInt(0)
	sum.Add(input.A, transfer.A)
	if Debug && DebugFull {
		fmt.Println("sum", sum)
	}
	sumX := big.NewInt(0)
	sumX.Add(input.X, transfer.X)
	if Debug && DebugFull {
		fmt.Println("sumX", sumX)
	}
	output := NewPedersenCommit(sum, sumX)

	if Debug && DebugFull {
		fmt.Println("input", PrettyPrint(input))
		fmt.Println("plus transfer", PrettyPrint(transfer))
		fmt.Println("output", PrettyPrint(output))
	}
	return output
}

func ComparePedersenCommit(p *PedersenCommit, q *PedersenCommit) bool {
	if p != nil && q != nil {
		if (*p.C).Equal(q.C) {
			return true
		}
	}

	return false
}

func BlindPedersenCommit(p *PedersenCommit) {
	if p == nil {
		return
	}

	p.A = BigIntZero
	p.X = BigIntZero
}

// valid just means that the commitment is not nil and the commitment point is not nil
func ValidPedersenCommit(p *PedersenCommit) bool {
	if p == nil || p.C == nil || p.C.X == nil || p.C.Y == nil {
		return false
	}
	return true
}

// validate means that the commitment is valid and that the commitment point is the correct point for the commitment -- note that p must have A and X set correctly
func ValidatePedersenCommit(p *PedersenCommit) bool {
	if p == nil {
		return false
	}
	test := NewPedersenCommit(p.A, p.X)
	if Debug && DebugFull {
		// print p
		fmt.Println("ValidatePedersenCommit p", p)
		fmt.Println("ValidatePedersenCommit test", test)
	}
	return p.C.Equal(test.C)
}

func ValidateSubPedersenCommit(input, output, change *PedersenCommit) bool {
	if input == nil || output == nil || change == nil {
		return false
	}

	neg_output := output.C.Neg()
	if Debug && DebugFull {
		fmt.Println("neg_output", neg_output)
	}

	neg_change := change.C.Neg()
	if Debug && DebugFull {
		fmt.Println("neg_change", neg_change)
	}

	check := input.C.Add(neg_output).Add(neg_change)

	if Debug && DebugFull {
		fmt.Println("check", check)
	}

	if check.X.Cmp(BigIntZero) != 0 || check.Y.Cmp(BigIntZero) != 0 {
		if Debug && DebugFull {
			fmt.Println("failed validation")
		}
		return false
	}

	if Debug && DebugFull {
		fmt.Println("validated")
	}
	return true
}

func ValidateAddPedersenCommit(input, transfer, output *PedersenCommit) bool {
	if input == nil || output == nil || transfer == nil {
		return false
	}

	neg_output := output.C.Neg()
	if Debug && DebugFull {
		fmt.Println("neg_output", neg_output)
	}

	check := input.C.Add(neg_output).Add(transfer.C)

	if Debug && DebugFull {
		fmt.Println("check", check)
	}

	if check.X.Cmp(BigIntZero) != 0 || check.Y.Cmp(BigIntZero) != 0 {
		if Debug && DebugFull {
			fmt.Println("failed validation")
		}
		return false
	}

	if Debug && DebugFull {
		fmt.Println("validated")
	}
	return true
}

func init() {
	ECPedersen = NewECPrimeGroupKeyV2(vecLength)
	// print ECPedersen.G
	//	fmt.Println("ECPedersen.G", ECPedersen.G)
	//	fmt.Println("ECPedersen.H", ECPedersen.H)

	//	ECForBinding = CryptoParamsForBinding{
	//		secp256k1.SECP256K1(),
	//		secp256k1.SECP256K1().Params().N,
	//	}
}
