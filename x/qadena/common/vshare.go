package common

import (
	"bytes"
	"fmt"
	"hash"
	"time"

	"encoding/hex"

	"encoding/base64"
	"strings"

	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/c3qtech/qadena_v3/x/qadena/types"

	ecies "github.com/ecies/go/v2"

	"crypto/aes"
	"crypto/cipher"

	proto "github.com/cosmos/gogoproto/proto"
)

var testVShareEncryption = false

/*
*	Contains bind along with other data needed for verification
*	Doesn't contain E for efficiency since it's sent separately
 */

type VShareSignatory struct {
	EncSignatoryVShare []byte
	VShareBind         *VShareBindData
	Time               time.Time
}

type VSharePubKInfo struct {
	PubK     string
	NodeID   string
	NodeType string
}

type VSharedSecret struct {
	S1 *ECPoint
	S2 *ECPoint
}

type BulkVShare struct {
	ccPubK           []VSharePubKInfo
	vSharedSecrets   []*VSharedSecret
	sharedSecretHash []byte
	hash             hash.Hash
}

type VShareBindData struct {
	Data []*vshareBindDataInternal
}

type vshareBindDataInternal struct {
	W, Z *big.Int
	C    *ECPoint         // g^k
	Y    *ECPointInfo     // recipient public key
	Cc   []*ECPointInfo   // cc public keys
	R    *VSharedSecret   // recipient encrypted S
	R_   []*VSharedSecret // cc encrypted S
}

/*
*	Creates bind data according to Binding El Gamal
 */
func newVShareBindData(Encrypted []byte, S *VSharedSecret, ccPubK []VSharePubKInfo) (bind_data *vshareBindDataInternal, err error) {

	ret := new(vshareBindDataInternal)

	var k, j []byte
	err = nil

	// select a random number k
	k = GenerateSharedSecret()

	// select a random number j
	j = GenerateSharedSecret()

	if len(ccPubK) == 0 {
		return nil, types.ErrVShareCreation
	}

	dstPubK := ccPubK[0]
	ccPubK = ccPubK[1:]

	dstPubK.PubK = strings.TrimSuffix(dstPubK.PubK, "_pubk")

	pubkbytes, err := base64.StdEncoding.DecodeString(dstPubK.PubK)

	if err != nil {
		fmt.Println("Error decoding dstPubK!")
		return nil, types.ErrVShareCreation
	}

	// convert dstPubK to ECPoint
	tmpY, err := ECPointFromBytes(pubkbytes)

	if Debug && DebugFull {
		fmt.Println("tmpY is ", tmpY.String())
		fmt.Println("baseG is ", ECPedersen.BaseG.String())
	}

	if err != nil {
		fmt.Println("Error converting dstPubK!")
		return nil, types.ErrVShareCreation
	}

	Y := new(ECPointInfo)
	Y.ECPoint = tmpY
	Y.NodeType = dstPubK.NodeType
	Y.NodeID = dstPubK.NodeID

	// C = g^k
	C := BaseGMult(k)

	// S but in big.Int
	//	ess := new(big.Int).SetBytes(S)

	// D = g^j
	D := BaseGMult(j)

	if Debug && DebugFull {
		fmt.Println("C:", PrettyPrint(C))
		fmt.Println("D:", PrettyPrint(D))
	}

	// make an array of slices to hold each vshare recipient's enciphered S
	R_ := make([]*VSharedSecret, len(ccPubK))
	// init R_
	for i := range R_ {
		R_[i] = new(VSharedSecret)
	}
	F_ := make([]*ECPoint, len(ccPubK))
	Cc_ := make([]*ECPointInfo, len(ccPubK))

	// init Cc_
	for i := range Cc_ {
		Cc_[i] = new(ECPointInfo)
	}

	// make an array of slices to hold a "letter" for each cc
	//  L_ := make([][]byte, len(cc))

	var R VSharedSecret
	// create R_ entries; the Y_^k * S; transferee (R) first
	YToTheK := Y.ECPoint.MultBytes(k)
	R.S1 = YToTheK
	R.S1 = R.S1.Add(S.S1)
	R.S2 = YToTheK
	R.S2 = R.S2.Add(S.S2)

	if Debug && DebugFull {
		fmt.Println("R.S1:", PrettyPrint(R.S1))
		fmt.Println("R.S2:", PrettyPrint(R.S2))
	}

	// the rest of the R_ entries for the cc'd
	for i, v := range ccPubK {
		v.PubK = strings.TrimSuffix(v.PubK, "_pubk")

		pubkbytes, err := base64.StdEncoding.DecodeString(v.PubK)

		if err != nil {
			return nil, types.ErrVShareCreation
		}

		// convert from string to big.Int
		Cc_[i].ECPoint, err = ECPointFromBytes(pubkbytes)
		if err != nil {
			return nil, types.ErrVShareCreation
		}
		Cc_[i].NodeType = v.NodeType
		Cc_[i].NodeID = v.NodeID
		Y_ := Cc_[i]

		// Y_^k * S
		Y_ToTheK := Y_.ECPoint.MultBytes(k)
		R_[i].S1 = Y_ToTheK
		R_[i].S1 = R_[i].S1.Add(S.S1)

		R_[i].S2 = Y_ToTheK
		R_[i].S2 = R_[i].S2.Add(S.S2)

		Y_OverY := Y_.ECPoint.Sub(Y.ECPoint)
		Y_OverYToTheJ := Y_OverY.MultBytes(j)
		F_[i] = Y_OverYToTheJ

		// print F
		if Debug && DebugFull {
			fmt.Println("F_[", i, "]", PrettyPrint(F_[i]))
		}
	}

	if Debug && DebugFull {
		fmt.Println("R_:", PrettyPrint(R_))
		fmt.Println("F_:", PrettyPrint(F_))
		fmt.Println("Cc_:", PrettyPrint(Cc_))
	}

	// create an empty array and its slice of nothing; don't use this underlying array since it has zero capacity
	s := []byte{}[:0]
	s = append(s, Encrypted[:]...)
	s = append(s, C.Bytes()[:]...)
	s = append(s, R.S1.Bytes()[:]...)
	s = append(s, R.S2.Bytes()[:]...)
	for _, r := range R_ {
		s = append(s, r.S1.Bytes()[:]...)
		s = append(s, r.S2.Bytes()[:]...)
	}
	s = append(s, D.Bytes()[:]...)
	// this is F
	for _, f := range F_ {
		s = append(s, f.Bytes()[:]...)
	}

	if Debug && DebugFull {
		fmt.Println("s:", hex.EncodeToString(s))
	}

	// create w by hashing E, C, R, R_<recipient>, D, F_ and the like if > 2 recipients
	hasher := sha256.New()
	_, err = hasher.Write(s)
	if err != nil {
		fmt.Println("SHA256 error: ", err)
		return ret, err
	}
	warr := hasher.Sum(nil)
	w := new(big.Int).SetBytes(warr)

	if Debug && DebugFull {
		fmt.Println("w:", w)
	}

	// create z = w * k + j (mod q)
	z := new(big.Int).Mul(w, new(big.Int).SetBytes(k))
	z = new(big.Int).Add(z, new(big.Int).SetBytes(j))
	z = new(big.Int).Mod(z, ECPedersen.N)

	if Debug && DebugFull {
		fmt.Println("z:", z)
	}

	ret.W = w
	ret.Z = z
	ret.C = C
	ret.Y = Y
	ret.R = &R
	ret.R_ = R_
	ret.Cc = Cc_

	return ret, nil
}

func (data *vshareBindDataInternal) vShareBVerify(encrypted []byte) bool {
	//
	// convert encryptedHex to bytes
	E := encrypted

	w := data.W.Bytes()
	z := data.Z.Bytes()

	// Cw
	Cw := data.C.MultBytes(w)
	if Debug && DebugFull {
		fmt.Println("Cw:", PrettyPrint(Cw))
	}
	// Gz
	Gz := BaseGMult(z)
	if Debug && DebugFull {
		fmt.Println("Gz:", PrettyPrint(Gz))
	}
	// D
	D := Gz.Sub(Cw)
	if Debug && DebugFull {
		fmt.Println("D:", PrettyPrint(D))
	}

	// make an array for the "letters" (F, I, ...)  of those receiveing a "carbon copy"
	F_ := make([]*ECPoint, len(data.Cc))

	// compute the "letters" for each "carbon copy" recipient
	for i, v := range data.Cc {
		// F
		Y_OverY := v.ECPoint.Sub(data.Y.ECPoint)
		Y_OverYToTheZ := Y_OverY.MultBytes(z)

		if Debug && DebugFull {
			fmt.Println("Y_OverYToTheZ:", PrettyPrint(Y_OverYToTheZ))
		}

		R_OverR := data.R_[i].S1.Sub(data.R.S1)
		R_OverRMToTheW := R_OverR.MultBytes(w)

		if Debug && DebugFull {
			fmt.Println("R_OverRMToTheW:", PrettyPrint(R_OverRMToTheW))
		}

		F_[i] = Y_OverYToTheZ.Sub(R_OverRMToTheW)

		// print F
		if Debug && DebugFull {
			fmt.Println("S1 F_[", i, "]", PrettyPrint(F_[i]))
		}

		// double-check the other F
		R_OverR = data.R_[i].S2.Sub(data.R.S2)
		R_OverRMToTheW = R_OverR.MultBytes(w)
		OtherF := Y_OverYToTheZ.Sub(R_OverRMToTheW)

		if Debug && DebugFull {
			fmt.Println("S2 F_[", i, "", PrettyPrint(OtherF))
		}

		if !F_[i].BindingEqual(OtherF) {
			if Debug && DebugFull {
				fmt.Println("F_[i] != OtherF")
			}
			return false
		}
	}

	// create an empty array and its slice of nothing; don't use this underlying array since it has zero capacity
	s := []byte{}[:0]
	s = append(s, E[:]...)
	s = append(s, data.C.Bytes()[:]...)
	s = append(s, data.R.S1.Bytes()[:]...)
	s = append(s, data.R.S2.Bytes()[:]...)
	for _, v := range data.R_ {
		s = append(s, v.S1.Bytes()[:]...)
		s = append(s, v.S2.Bytes()[:]...)
	}
	s = append(s, D.Bytes()[:]...)
	for _, v := range F_ {
		s = append(s, v.Bytes()[:]...)
	}

	// create w by hashing E, C, D, R_<recipient>, F, I and the like if > 2 recipients
	hasher := sha256.New()
	_, err := hasher.Write(s)
	if err != nil {
		fmt.Println("SHA256 error: ", err)
		return false
	}
	warr := hasher.Sum(nil)
	wPrime := new(big.Int).SetBytes(warr)
	wPrime = new(big.Int).Mod(wPrime, ECPedersen.N) // here later on

	if Debug && DebugFull {
		fmt.Println("wPrime:", wPrime)
		fmt.Println("data.W:", data.W)
	}
	return wPrime.Cmp(data.W) == 0
}

func (data *VShareBindData) GetSSIntervalPubKID() string {
	_, pubKID := data.FindB64AddressAndBech32AddressByNodeIDAndType(types.SSNodeID, types.SSNodeType)
	if Debug && DebugFull {
		fmt.Println("found SSIntervalPubKID", pubKID)
	}
	return pubKID
}

func (data *VShareBindData) GetJarIntervalPubKID() string {
	_, pubKID := data.FindB64AddressAndBech32AddressByNodeType(types.JarNodeType)
	return pubKID
}

func (data *VShareBindData) GetValidDecryptAsAddresses() string {
	addr := ""
	addr = addr + data.Data[0].Y.NodeID + "," + data.Data[0].Y.NodeType + "," + data.Data[0].Y.ECPoint.Bech32Address()
	for j := 0; j < len(data.Data[0].Cc); j++ {
		addr = addr + " | " + data.Data[0].Cc[j].NodeID + "," + data.Data[0].Cc[j].NodeType + "," + data.Data[0].Cc[j].ECPoint.Bech32Address()
	}
	return addr
}

func (data *VShareBindData) GetJarID() string {
	if data == nil {
		return ""
	}
	if len(data.Data) != 2 {
		return ""
	}

	if data.Data[0].Y.NodeType == types.JarNodeType && data.Data[1].Y.NodeType == types.JarNodeType {
		return data.Data[0].Y.NodeID
	}
	for j := 0; j < len(data.Data[0].Cc); j++ {
		if data.Data[0].Cc[j].NodeType == types.JarNodeType && data.Data[1].Cc[j].NodeType == types.JarNodeType {
			return data.Data[0].Cc[j].NodeID
		}
	}
	return ""
}

func (data *VShareBindData) FindB64AddressAndBech32AddressByNodeType(nodeType string) (b64Address string, bech32Address string) {
	if data == nil {
		return "", ""
	}
	if len(data.Data) != 2 {
		return "", ""
	}

	if data.Data[0].Y.NodeType == nodeType && data.Data[1].Y.NodeType == nodeType {
		return data.Data[0].Y.ECPoint.B64Address(), data.Data[0].Y.ECPoint.Bech32Address()
	}
	for j := 0; j < len(data.Data[0].Cc); j++ {
		if data.Data[0].Cc[j].NodeType == nodeType && data.Data[1].Cc[j].NodeType == nodeType {
			return data.Data[0].Cc[j].ECPoint.B64Address(), data.Data[0].Cc[j].ECPoint.Bech32Address()
		}
	}
	return "", ""
}

func (data *VShareBindData) FindB64AddressAndBech32AddressByNodeIDAndType(nodeID string, nodeType string) (b64Address string, bech32Address string) {
	if data == nil {
		return "", ""
	}
	if len(data.Data) != 2 {
		return "", ""
	}

	if data.Data[0].Y.NodeID == nodeID && data.Data[0].Y.NodeType == nodeType && data.Data[1].Y.NodeID == nodeID && data.Data[1].Y.NodeType == nodeType {
		return data.Data[0].Y.ECPoint.B64Address(), data.Data[0].Y.ECPoint.Bech32Address()
	}
	for j := 0; j < len(data.Data[0].Cc); j++ {
		if data.Data[0].Cc[j].NodeID == nodeID && data.Data[0].Cc[j].NodeType == nodeType && data.Data[1].Cc[j].NodeID == nodeID && data.Data[1].Cc[j].NodeType == nodeType {
			return data.Data[0].Cc[j].ECPoint.B64Address(), data.Data[0].Cc[j].ECPoint.Bech32Address()
		}
	}
	return "", ""
}

func (data *VShareBindData) FindB64Address(bech32addr string) string {
	if data == nil {
		return ""
	}
	if len(data.Data) != 2 {
		return ""
	}

	if data.Data[0].Y.ECPoint.Bech32Address() == bech32addr && data.Data[1].Y.ECPoint.Bech32Address() == bech32addr {
		return data.Data[0].Y.ECPoint.B64Address()
	}
	for j := 0; j < len(data.Data[0].Cc); j++ {
		if data.Data[0].Cc[j].ECPoint.Bech32Address() == bech32addr && data.Data[1].Cc[j].ECPoint.Bech32Address() == bech32addr {
			return data.Data[0].Cc[j].ECPoint.B64Address()
		}
	}

	return ""
}

func (data *VShareBindData) FindVSharePubKInfo(pubK VSharePubKInfo) bool {
	if data == nil {
		return false
	}
	if len(data.Data) != 2 {
		return false
	}

	pubkbytes, err := base64.StdEncoding.DecodeString(pubK.PubK)

	if err != nil {
		fmt.Println("Error decoding pubK!")
		return false
	}

	// convert dstPubK to ECPoint
	pubkECPoint, err := ECPointFromBytes(pubkbytes)

	if err != nil {
		fmt.Println("Error converting pubK to ECPoint!")
		return false
	}

	if data.Data[0].Y.ECPoint.Equal(pubkECPoint) && data.Data[0].Y.NodeID == pubK.NodeID && data.Data[0].Y.NodeType == pubK.NodeType && data.Data[1].Y.ECPoint.Equal(pubkECPoint) && data.Data[1].Y.NodeID == pubK.NodeID && data.Data[1].Y.NodeType == pubK.NodeType {
		return true
	}

	for j := 0; j < len(data.Data[0].Cc); j++ {
		if data.Data[0].Cc[j].ECPoint.Equal(pubkECPoint) && data.Data[0].Cc[j].NodeID == pubK.NodeID && data.Data[0].Cc[j].NodeType == pubK.NodeType && data.Data[1].Cc[j].ECPoint.Equal(pubkECPoint) && data.Data[1].Cc[j].NodeID == pubK.NodeID && data.Data[1].Cc[j].NodeType == pubK.NodeType {
			return true
		}
	}

	return false
}

func (data *VShareBindData) VShareBVerify(encrypted []byte) bool {
	// if there are no bind data, return false
	if len(data.Data) == 0 {
		return false
	}

	for i := 0; i < len(data.Data); i++ {
		if !data.Data[i].vShareBVerify(encrypted) {
			return false
		}
	}
	return true
}

/*
For verifiable shares
DONE:  we use 2 ECPoints for the VShareSecret
*/

func ProtoMarshalAndVShareBEncryptStep1(ccPubK []VSharePubKInfo) (bulkVShare *BulkVShare) {
	var bv BulkVShare
	bv.vSharedSecrets = make([]*VSharedSecret, 2)

	for i := 0; i < 2; i++ {
		bv.vSharedSecrets[i] = generateVSharedSecret()

		// print sharedSecret
		if Debug && DebugFull {
			fmt.Println("S1:", i, PrettyPrint(bv.vSharedSecrets[i].S1))
			fmt.Println("S2:", i, PrettyPrint(bv.vSharedSecrets[i].S2))
		}
	}

	// sha256 hash of sharedSecret.X and sharedSecret.Y
	sharedSecretBytes := append(bv.vSharedSecrets[0].S1.Bytes()[1:], bv.vSharedSecrets[1].S1.Bytes()[1:]...)

	// panic if sharedSecretBytes length is not 64
	if len(sharedSecretBytes) != 64 {
		panic("sharedSecretBytes length is not 64")
	}

	// print sharedSecretBytes
	if Debug && DebugFull {
		fmt.Println("sharedSecretBytes:", hex.EncodeToString(sharedSecretBytes))
	}

	sharedSecretHash := sha256.Sum256(sharedSecretBytes)

	bv.sharedSecretHash = sharedSecretHash[:]

	bv.hash = sha256.New()
	bv.ccPubK = ccPubK

	bulkVShare = &bv

	return
}

func ProtoMarshalAndVShareBEncryptStep2(bulkVShare *BulkVShare, v proto.Message) (encrypted []byte) {
	v_b, _ := proto.Marshal(v)

	cipherText := sharedSecretEncrypt(bulkVShare.sharedSecretHash, v_b)

	// hash cipherText
	bulkVShare.hash.Write(cipherText)

	return cipherText
}

func MarshalAndVShareBEncryptStep3(bulkVShare *BulkVShare) (bindData *VShareBindData) {

	bindData = new(VShareBindData)
	bindData.Data = make([]*vshareBindDataInternal, 2)

	// create bindData
	eHash := bulkVShare.hash.Sum(nil)
	// print eHash
	if Debug && DebugFull {
		fmt.Println("eHash:", hex.EncodeToString(eHash))
	}
	for i := 0; i < 2; i++ {
		bindDataInternal, err := newVShareBindData(eHash, bulkVShare.vSharedSecrets[i], bulkVShare.ccPubK)

		if err != nil {
			fmt.Println("Error creating bind data!")
			return nil
		}

		bindData.Data[i] = bindDataInternal
	}

	return bindData
}

func ProtoMarshalAndVShareBEncrypt(ccPubK []VSharePubKInfo, v proto.Message) (encrypted []byte, bindData *VShareBindData) {
	v_b, _ := proto.Marshal(v)

	if Debug && DebugFull {
		fmt.Println("proto v_b", hex.EncodeToString(v_b))
	}

	bindData = new(VShareBindData)

	bindData.Data = make([]*vshareBindDataInternal, 2)

	sharedSecrets := make([]*VSharedSecret, 2)

	// loop 2 times

	for i := 0; i < 2; i++ {
		sharedSecrets[i] = generateVSharedSecret()

		// print sharedSecret
		if Debug && DebugFull {
			fmt.Println("S1:", i, PrettyPrint(sharedSecrets[i].S1))
			fmt.Println("S2:", i, PrettyPrint(sharedSecrets[i].S2))
		}
	}

	// sharedSecretBytes is [1:] of sharedDescrets[0].S1 and [1:] of sharedDescrets[1].S1
	sharedSecretBytes := append(sharedSecrets[0].S1.Bytes()[1:], sharedSecrets[1].S1.Bytes()[1:]...)

	// panic if sharedSecretBytes length is not 64
	if len(sharedSecretBytes) != 64 {
		panic("sharedSecretBytes length is not 64")
	}

	// print sharedSecretBytes
	if Debug && DebugFull {
		fmt.Println("sharedSecretBytes:", hex.EncodeToString(sharedSecretBytes))
	}

	sharedSecretHash := sha256.Sum256(sharedSecretBytes)

	if Debug && DebugFull {
		fmt.Println("sharedSecretHash:", hex.EncodeToString(sharedSecretHash[:]))
	}

	cipherText := sharedSecretEncrypt(sharedSecretHash[:], v_b)

	if Debug && DebugFull {
		fmt.Println("ciphertext encrypted hex", hex.EncodeToString(cipherText))
	}

	for i := 0; i < 2; i++ {
		// create bindData
		bindDataInternal, err := newVShareBindData(cipherText, sharedSecrets[i], ccPubK)

		if err != nil {
			fmt.Println("Error creating bind data!")
			return nil, nil
		}

		bindData.Data[i] = bindDataInternal
	}

	return cipherText, bindData
}

func VShareBDecryptAndProtoUnmarshal(priv string, pubK string, bindData *VShareBindData, encrypted []byte, v proto.Message) error {
	if priv == "" {
		return types.ErrGenericEncryption
	}

	privkhex := priv

	if strings.HasSuffix(priv, "_privk") {
		// strip the pubkid from the beginning
		split := strings.Split(priv, "_privkhex:")

		if len(split) != 2 {
			fmt.Println("invalid priv key", priv)
			return types.ErrGenericEncryption
		}

		privkhex = split[0]
		if Debug && DebugFull {
			fmt.Println("privkhex", privkhex)
		}
	}

	var plain_text []byte

	privk, err := ecies.NewPrivateKeyFromHex(privkhex)
	if err != nil {
		fmt.Println("Couldn't create private key from hex")
		return types.ErrGenericEncryption
	}

	pubK = strings.TrimSuffix(pubK, "_pubk")

	pubkbytes, err := base64.StdEncoding.DecodeString(pubK)

	if err != nil {
		fmt.Println("Error decoding pubK!")
		return types.ErrGenericEncryption
	}

	// convert pubK to ECPoint
	Y, err := ECPointFromBytes(pubkbytes)

	if err != nil {
		fmt.Println("Error converting pubK!")
		return types.ErrGenericEncryption
	} else {
		if Debug && DebugFull {
			fmt.Println("Y is ", Y.String())
		}
	}

	encryptedSharedSecrets := make([]*VSharedSecret, len(bindData.Data))

	for i := 0; i < len(bindData.Data); i++ {
		// check if Y is the same as bindData.Y
		if Y.Equal(bindData.Data[i].Y.ECPoint) {
			encryptedSharedSecrets[i] = bindData.Data[i].R
		} else {
			// find the encrypted shared secret ECPoint in bindData.R_
			// print lenght of bindData.R_[i].Cc
			if Debug && DebugFull {
				fmt.Println("length of bindData.R_[i].Cc", len(bindData.Data[i].Cc))
			}
			for j, v := range bindData.Data[i].Cc {
				if Y.Equal(v.ECPoint) {
					encryptedSharedSecrets[i] = bindData.Data[i].R_[j]
					break
				}
			}
		}
		if encryptedSharedSecrets[i] == nil {
			fmt.Println("failed decryption, couldn't find the right encrypted shared secret based on the public key")
			return types.ErrGenericEncryption
		}
		if Debug && DebugFull {
			// print encryptedSharedSecret.S1.X and Y
			fmt.Println("encryptedSharedSecret", i, "S1", PrettyPrint(encryptedSharedSecrets[i].S1))
			// print encryptedSharedSecret.S2.X and Y
			fmt.Println("encryptedSharedSecret", i, "S2:", PrettyPrint(encryptedSharedSecrets[i].S2))
		}
	}

	sharedSecrets := make([]*VSharedSecret, len(bindData.Data))

	for i := 0; i < len(bindData.Data); i++ {
		// decrypt the encrypted shared secret ECPoint
		// compute S based on RM
		Cx := bindData.Data[i].C.MultBytes(privk.Bytes())
		sharedSecrets[i] = new(VSharedSecret)
		sharedSecrets[i].S1 = encryptedSharedSecrets[i].S1.Sub(Cx)
		sharedSecrets[i].S2 = encryptedSharedSecrets[i].S2.Sub(Cx)

		// print S1.X and Y
		if Debug && DebugFull {
			fmt.Println("decrypted", i, "S1", PrettyPrint(sharedSecrets[i].S1))
			fmt.Println("decrypted", i, "S2", PrettyPrint(sharedSecrets[i].S2))
		}
	}

	sharedSecretBytes := append(sharedSecrets[0].S1.Bytes()[1:], sharedSecrets[1].S1.Bytes()[1:]...)

	// print sharedSecretBytes
	if Debug && DebugFull {
		fmt.Println("sharedSecretBytes:", hex.EncodeToString(sharedSecretBytes))
	}

	sharedSecretHash := sha256.Sum256([]byte(sharedSecretBytes))

	// decrypt the encrypted data
	plain_text = sharedSecretDecrypt(sharedSecretHash[:], encrypted)
	if plain_text == nil {
		fmt.Println(err)
		return types.ErrGenericEncryption
	}

	if Debug && DebugFull {
		fmt.Println("ciphertext decrypted hex", hex.EncodeToString(plain_text))
	}

	res := proto.Unmarshal(plain_text, v)
	if res != nil {
		return types.ErrGenericEncryption
	}
	return nil
}

func GenerateSharedSecret() (sharedSecret []byte) {
	privateKey, err := ecies.GenerateKey()
	if err != nil {
		fmt.Println("cannot generate shared secret")
	}
	//  logger.Debug("key size " + strconv.FormatInt(int64(len(pk.D.Bytes())), 10))
	if testVShareEncryption {
		sharedSecret, _ = hex.DecodeString("5321d8cd34c5b255977f2af43dc69011f6fffb6cde44a487912b31bde6a7aabf")
	} else {
		sharedSecret = privateKey.D.Bytes()
	}
	return
}

func generateVSharedSecret() (sharedSecret *VSharedSecret) {
	var out VSharedSecret
	privateKey1, err := ecies.GenerateKey()
	if err != nil {
		fmt.Println("cannot generate shared secret")
	}
	privateKey2, err := ecies.GenerateKey()
	if err != nil {
		fmt.Println("cannot generate shared secret")
	}

	if testVShareEncryption {
		x, _ := big.NewInt(0).SetString("97368617487603714092414532914124097846147079533749946779008061592908669241131", 10)
		y, _ := big.NewInt(0).SetString("38012604707558131976206218819154704038994600591102383397891123254401931774169", 10)
		out.S1 = NewECPoint(x, y)
		x, _ = big.NewInt(0).SetString("10933688225293634337800930413737356245078722676670001755825505019306063008595", 10)
		y, _ = big.NewInt(0).SetString("29026341325685103236884838969810081548457453006295014773090950353179945034432", 10)
		out.S2 = NewECPoint(x, y)
		sharedSecret = &out
	} else {
		//  logger.Debug("key size " + strconv.FormatInt(int64(len(pk.D.Bytes())), 10))
		out.S1 = NewECPoint(privateKey1.PublicKey.X, privateKey1.PublicKey.Y)
		out.S2 = NewECPoint(privateKey2.PublicKey.X, privateKey2.PublicKey.Y)

		sharedSecret = &out
		return
	}

	return
}

// sharedSecretEncrypt/Decrypt are similar to ECIES
func sharedSecretEncrypt(sharedSecret []byte, msg []byte) []byte {
	var ct bytes.Buffer

	// mostly cloned code from ECIES

	// AES encryption
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		fmt.Println("cannot create new aes block")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}

	if testVShareEncryption {
		nonce, _ = hex.DecodeString("8bb59c1d6e8a3f47e3eec29d901f897a")
	}

	ct.Write(nonce)

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		fmt.Println("cannot create aes gcm")
	}

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)

	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	ct.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]
	ct.Write(ciphertext)

	return ct.Bytes()
}

func sharedSecretDecrypt(ss []byte, msg []byte) []byte {
	if len(msg) <= (16 + 16) {
		fmt.Println("invalid length of message")
		return nil
	}

	// AES decryption part
	nonce := msg[:16]
	tag := msg[16:32]

	// Create Golang-accepted ciphertext
	ciphertext := bytes.Join([][]byte{msg[32:], tag}, nil)

	block, err := aes.NewCipher(ss)
	if err != nil {
		fmt.Println("cannot create new aes block: %w", err)
		return nil
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		fmt.Println("cannot create gcm cipher: %w", err)
		return nil
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("cannot decrypt ciphertext: %w", err)
		return nil
	}

	return plaintext
}
