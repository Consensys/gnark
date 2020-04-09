/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package eddsa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/consensys/gnark/cryptolib/hash/mimc/bls381"
	"github.com/consensys/gurvy/bls381/fr"
	"github.com/consensys/gurvy/bls381/twistededwards"
	"golang.org/x/crypto/blake2b"
)

var ErrNotOnCurve = errors.New("point not on curve")

// PrivateKey private key of an eddsa instance
type PrivateKey struct {
	randSrc [32]byte   // randomizer (non need to convert it when doing scalar mul --> random = H(randSrc,msg))
	scalar  fr.Element // secret scalar (non need to convert it when doing scalar mul)
	EdCurve *twistededwards.CurveParams
}

// Signature represents an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA for notation
type Signature struct {
	R       twistededwards.Point
	S       fr.Element // not in Montgomery form
	EdCurve *twistededwards.CurveParams
}

// PublicKey eddsa signature object
// cf https://en.wikipedia.org/wiki/EdDSA for notation
type PublicKey struct {
	A twistededwards.Point
}

// New creates an instance of eddsa
func New(seed [32]byte, c twistededwards.CurveParams) (PrivateKey, PublicKey) {

	var value big.Int
	var pub PublicKey
	var priv PrivateKey

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
	value.SetBytes(h[:32])
	priv.scalar.SetBigInt(&value).FromMont()
	priv.EdCurve = &c

	pub.A.ScalarMul(&c.Base, c, priv.scalar)

	return priv, pub
}

// Sign sign a message (in Montgomery form)
// cf https://en.wikipedia.org/wiki/EdDSA for the notations
// Eddsa is supposed to be built upon Edwards (or twisted Edwards) curves having 256 bits group size and cofactor=4 or 8
func Sign(privateKey PrivateKey, publicKey PublicKey, message fr.Element) (Signature, error) {

	res := Signature{}

	// check that base point is on the curve
	if !privateKey.EdCurve.Base.IsOnCurve(*privateKey.EdCurve) {
		return res, ErrNotOnCurve
	}

	var tmp big.Int
	var randScalar fr.Element

	// randSrc = privKey.randSrc || msg (-> message = MSB message .. LSB message)
	randSrc := make([]byte, 64)
	for i, v := range privateKey.randSrc {
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
	res.R.ScalarMul(&privateKey.EdCurve.Base, *privateKey.EdCurve, randScalar)
	if !res.R.IsOnCurve(*privateKey.EdCurve) {
		return Signature{}, ErrNotOnCurve
	}

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []fr.Element{
		res.R.X,
		res.R.Y,
		publicKey.A.X,
		publicKey.A.Y,
		message,
	}

	hram := bls381.NewMiMC("seed").Hash(data...)
	hram.FromMont()

	// Compute s = randScalarInt + H(R,A,M)*S
	// going with big int to do ops mod curve order
	var hramInt, sInt, randScalarInt big.Int
	hram.ToBigInt(&hramInt)
	privateKey.scalar.ToBigInt(&sInt)
	randScalar.ToBigInt(&randScalarInt)
	hramInt.Mul(&hramInt, &sInt).
		Add(&hramInt, &randScalarInt).
		Mod(&hramInt, &privateKey.EdCurve.Order)
	res.S.SetBigInt(&hramInt).FromMont()
	res.EdCurve = privateKey.EdCurve

	return res, nil
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(pubKey PublicKey, sig Signature, message fr.Element) (bool, error) {

	// verify that pubKey and R are on the curve
	if !pubKey.A.IsOnCurve(*sig.EdCurve) {
		return false, ErrNotOnCurve
	}

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []fr.Element{
		sig.R.X,
		sig.R.Y,
		pubKey.A.X,
		pubKey.A.Y,
		message,
	}
	hram := bls381.NewMiMC("seed").Hash(data...)
	hram.FromMont()

	// lhs = cofactor*S*Base
	var lhs twistededwards.Point
	lhs.ScalarMul(&sig.EdCurve.Base, *sig.EdCurve, sig.S).
		ScalarMul(&lhs, *sig.EdCurve, sig.EdCurve.Cofactor)

	if !lhs.IsOnCurve(*sig.EdCurve) {
		return false, ErrNotOnCurve
	}

	// rhs = cofactor*(R + H(R,A,M)*A)
	var rhs twistededwards.Point
	rhs.ScalarMul(&pubKey.A, *sig.EdCurve, hram).
		Add(&rhs, &sig.R, *sig.EdCurve).
		ScalarMul(&rhs, *sig.EdCurve, sig.EdCurve.Cofactor)
	if !rhs.IsOnCurve(*sig.EdCurve) {
		return false, ErrNotOnCurve
	}

	// verifies that cofactor*S*Base=cofactor*(R + H(R,A,M)*A)
	if !lhs.X.Equal(&rhs.X) || !lhs.Y.Equal(&rhs.Y) {
		return false, nil
	}
	return true, nil
}
