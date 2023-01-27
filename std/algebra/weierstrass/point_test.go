package weierstrass

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var testCurve = ecc.BN254

type NegTest[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
}

func (c *NegTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.Neg(&c.P)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestNeg(t *testing.T) {
	assert := test.NewAssert(t)
	secpCurve := secp256k1.S256()
	yn := new(big.Int).Sub(secpCurve.P, secpCurve.Gy)
	circuit := NegTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := NegTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gy),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](yn),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type AddTest[T, S emulated.FieldParams] struct {
	P, Q, R AffinePoint[T]
}

func (c *AddTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.Add(&c.P, &c.Q)
	cr.AssertIsEqual(res, &c.R)
	return nil
}

func TestAdd(t *testing.T) {
	assert := test.NewAssert(t)
	secpCurve := secp256k1.S256()
	xd, yd := secpCurve.Double(secpCurve.Gx, secpCurve.Gy)
	xa, ya := secpCurve.Add(xd, yd, secpCurve.Gx, secpCurve.Gy)
	circuit := AddTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := AddTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gy),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](xd),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](yd),
		},
		R: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](xa),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](ya),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type DoubleTest[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
}

func (c *DoubleTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.Double(&c.P)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestDouble(t *testing.T) {
	assert := test.NewAssert(t)
	secpCurve := secp256k1.S256()
	xd, yd := secpCurve.Double(secpCurve.Gx, secpCurve.Gy)
	circuit := DoubleTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := DoubleTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gy),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](xd),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](yd),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type ScalarMulTest[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
	S    emulated.Element[S]
}

func (c *ScalarMulTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	secpCurve := secp256k1.S256()
	s, ok := new(big.Int).SetString("44693544921776318736021182399461740191514036429448770306966433218654680512345", 10)
	assert.True(ok)
	sx, sy := secpCurve.ScalarMult(secpCurve.Gx, secpCurve.Gy, s.Bytes())

	circuit := ScalarMulTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := ScalarMulTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](secpCurve.Gy),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](sx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](sy),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
}

func TestScalarMul2(t *testing.T) {
	assert := test.NewAssert(t)
	s, ok := new(big.Int).SetString("14108069686105661647148607545884343550368786660735262576656400957535521042679", 10)
	assert.True(ok)
	var res bn254.G1Affine
	_, _, gen, _ := bn254.Generators()
	res.ScalarMultiplication(&gen, s)

	circuit := ScalarMulTest[emulated.BN254Fp, emulated.BN254Fr]{}
	witness := ScalarMulTest[emulated.BN254Fp, emulated.BN254Fr]{
		S: emulated.ValueOf[emulated.BN254Fr](s),
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](gen.X.BigInt(new(big.Int))),
			Y: emulated.ValueOf[emulated.BN254Fp](gen.Y.BigInt(new(big.Int))),
		},
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](res.X.BigInt(new(big.Int))),
			Y: emulated.ValueOf[emulated.BN254Fp](res.Y.BigInt(new(big.Int))),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
}
