package template

const EddsaTemplate = `

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	"github.com/consensys/gurvy/{{toLower .Curve}}/fr"
	"github.com/consensys/gurvy/{{toLower .Curve}}/twistededwards"
	"golang.org/x/crypto/blake2b"
)

var ErrNotOnCurve = errors.New("point not on curve")

// Signature represents an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA for notation
type Signature struct {
	R twistededwards.Point
	S fr.Element // not in Montgomery form
}

// PublicKey eddsa signature object
// cf https://en.wikipedia.org/wiki/EdDSA for notation
type PublicKey struct {
	A twistededwards.Point
}

// PrivateKey private key of an eddsa instance
type PrivateKey struct {
	randSrc [32]byte   // randomizer (non need to convert it when doing scalar mul --> random = H(randSrc,msg))
	scalar  fr.Element // secret scalar (non need to convert it when doing scalar mul)
}

// Eddsa stores parameters to generate and verify eddsa signature
type Eddsa struct {
	curveParams *twistededwards.CurveParams
	h           hash.Hash
}

// New creates an instance of eddsa
func New(seed [32]byte, c twistededwards.CurveParams, hFunc hash.Hash) (Eddsa, PublicKey, PrivateKey) {

	var tmp big.Int

	var res Eddsa
	var pub PublicKey
	var priv PrivateKey

	res.h = hFunc

	h := blake2b.Sum512(seed[:])
	for i := 0; i < 32; i++ {
		priv.randSrc[i] = h[i+32]
	}

	// prune the key
	// https://tools.ietf.org/html/rfc8032#section-5.1.5, key generation
	h[0] &= 0xF8
	h[31] &= 0x7F
	h[31] |= 0x40

	// reverse first bytes because setBytes interpret stream as big endian
	// but in eddsa specs s is the first 32 bytes in little endian
	for i, j := 0, 32; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	tmp.SetBytes(h[:32])
	priv.scalar.SetBigInt(&tmp).FromMont()
	res.curveParams = &c

	pub.A.ScalarMul(&c.Base, c, priv.scalar)

	return res, pub, priv
}

// Sign sign a message (in Montgomery form)
// cf https://en.wikipedia.org/wiki/EdDSA for the notations
// Eddsa is supposed to be built upon Edwards (or twisted Edwards) curves having 256 bits group size and cofactor=4 or 8
func Sign(eddsaContext Eddsa, message fr.Element, pub PublicKey, priv PrivateKey) (Signature, error) {

	res := Signature{}

	var tmp big.Int
	var randScalar fr.Element

	// randSrc = privKey.randSrc || msg (-> message = MSB message .. LSB message)
	randSrc := make([]byte, 64)
	for i, v := range priv.randSrc {
		randSrc[i] = v
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, message)
	if err != nil {
		return res, err
	}
	bufb := buf.Bytes()
	for i := 0; i < 32; i++ {
		randSrc[32+i] = bufb[i]
	}

	// randBytes = H(randSrc)
	randBytes := blake2b.Sum512(randSrc[:])
	tmp.SetBytes(randBytes[:32])
	randScalar.SetBigInt(&tmp).FromMont()

	// compute R = randScalar*Base
	res.R.ScalarMul(&eddsaContext.curveParams.Base, *eddsaContext.curveParams, randScalar)
	if !res.R.IsOnCurve(*eddsaContext.curveParams) {
		return Signature{}, ErrNotOnCurve
	}

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []fr.Element{
		res.R.X,
		res.R.Y,
		pub.A.X,
		pub.A.Y,
		message,
	}
	eddsaContext.h.Reset()
	for i := 0; i < len(data); i++ {
		eddsaContext.h.Write(data[i].Bytes())
	}
	hramBin := eddsaContext.h.Sum([]byte{})
	var hram fr.Element
	hram.SetBytes(hramBin).FromMont() // FromMont() because it will serve as a scalar in the scalar multiplication

	// Compute s = randScalarInt + H(R,A,M)*S
	// going with big int to do ops mod curve order
	var hramInt, sInt, randScalarInt big.Int
	hram.ToBigInt(&hramInt)
	priv.scalar.ToBigInt(&sInt)
	randScalar.ToBigInt(&randScalarInt)
	hramInt.Mul(&hramInt, &sInt).
		Add(&hramInt, &randScalarInt).
		Mod(&hramInt, &eddsaContext.curveParams.Order)
	res.S.SetBigInt(&hramInt).FromMont()

	return res, nil
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(eddsaContext Eddsa, sig Signature, message fr.Element, pub PublicKey) (bool, error) {

	// verify that pubKey and R are on the curve
	if !pub.A.IsOnCurve(*eddsaContext.curveParams) {
		return false, ErrNotOnCurve
	}

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []fr.Element{
		sig.R.X,
		sig.R.Y,
		pub.A.X,
		pub.A.Y,
		message,
	}
	eddsaContext.h.Reset()
	for i := 0; i < len(data); i++ {
		eddsaContext.h.Write(data[i].Bytes())
	}
	hramBin := eddsaContext.h.Sum([]byte{})
	var hram fr.Element
	hram.SetBytes(hramBin).FromMont() // FromMont() because it will serve as a scalar in the scalar multiplication

	// lhs = cofactor*S*Base
	var lhs twistededwards.Point
	lhs.ScalarMul(&eddsaContext.curveParams.Base, *eddsaContext.curveParams, sig.S).
		ScalarMul(&lhs, *eddsaContext.curveParams, eddsaContext.curveParams.Cofactor)

	if !lhs.IsOnCurve(*eddsaContext.curveParams) {
		return false, ErrNotOnCurve
	}

	// rhs = cofactor*(R + H(R,A,M)*A)
	var rhs twistededwards.Point
	rhs.ScalarMul(&pub.A, *eddsaContext.curveParams, hram).
		Add(&rhs, &sig.R, *eddsaContext.curveParams).
		ScalarMul(&rhs, *eddsaContext.curveParams, eddsaContext.curveParams.Cofactor)
	if !rhs.IsOnCurve(*eddsaContext.curveParams) {
		return false, ErrNotOnCurve
	}

	// verifies that cofactor*S*Base=cofactor*(R + H(R,A,M)*A)
	if !lhs.X.Equal(&rhs.X) || !lhs.Y.Equal(&rhs.Y) {
		return false, nil
	}
	return true, nil
}

`
