package sw_emulated

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fp_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
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
	_, g := secp256k1.Generators()
	var yn fp_secp.Element
	yn.Neg(&g.Y)
	circuit := NegTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := NegTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](g.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](g.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](g.X),
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
	res1 := cr.add(&c.P, &c.Q)
	res2 := cr.AddUnified(&c.P, &c.Q)
	cr.AssertIsEqual(res1, &c.R)
	cr.AssertIsEqual(res2, &c.R)
	return nil
}

func TestAdd(t *testing.T) {
	assert := test.NewAssert(t)
	var dJac, aJac secp256k1.G1Jac
	g, _ := secp256k1.Generators()
	dJac.Double(&g)
	aJac.Set(&dJac).
		AddAssign(&g)
	var dAff, aAff secp256k1.G1Affine
	dAff.FromJacobian(&dJac)
	aAff.FromJacobian(&aJac)
	circuit := AddTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := AddTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](g.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](g.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](dAff.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](dAff.Y),
		},
		R: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](aAff.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](aAff.Y),
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
	res1 := cr.double(&c.P)
	res2 := cr.AddUnified(&c.P, &c.P)
	cr.AssertIsEqual(res1, &c.Q)
	cr.AssertIsEqual(res2, &c.Q)
	return nil
}

func TestDouble(t *testing.T) {
	assert := test.NewAssert(t)
	g, _ := secp256k1.Generators()
	var dJac secp256k1.G1Jac
	dJac.Double(&g)
	var dAff secp256k1.G1Affine
	dAff.FromJacobian(&dJac)
	circuit := DoubleTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := DoubleTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](g.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](g.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](dAff.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](dAff.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type TripleTest[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
}

func (c *TripleTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.triple(&c.P)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestTriple(t *testing.T) {
	assert := test.NewAssert(t)
	g, _ := secp256k1.Generators()
	var dJac secp256k1.G1Jac
	dJac.Double(&g).AddAssign(&g)
	var dAff secp256k1.G1Affine
	dAff.FromJacobian(&dJac)
	circuit := TripleTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := TripleTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](g.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](g.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](dAff.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](dAff.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type DoubleAndAddTest[T, S emulated.FieldParams] struct {
	P, Q, R AffinePoint[T]
}

func (c *DoubleAndAddTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.doubleAndAdd(&c.P, &c.Q)
	cr.AssertIsEqual(res, &c.R)
	return nil
}

func TestDoubleAndAdd(t *testing.T) {
	assert := test.NewAssert(t)
	var pJac, qJac, rJac secp256k1.G1Jac
	g, _ := secp256k1.Generators()
	pJac.Double(&g)
	qJac.Set(&g)
	rJac.Double(&pJac).
		AddAssign(&qJac)
	var pAff, qAff, rAff secp256k1.G1Affine
	pAff.FromJacobian(&pJac)
	qAff.FromJacobian(&qJac)
	rAff.FromJacobian(&rJac)
	circuit := DoubleAndAddTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := DoubleAndAddTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pAff.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pAff.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](qAff.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](qAff.Y),
		},
		R: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](rAff.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](rAff.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type AddUnifiedEdgeCases[T, S emulated.FieldParams] struct {
	P, Q, R AffinePoint[T]
}

func (c *AddUnifiedEdgeCases[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.AddUnified(&c.P, &c.Q)
	cr.AssertIsEqual(res, &c.R)
	return nil
}

func TestAddUnifiedEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	var infinity bn254.G1Affine
	_, _, g, _ := bn254.Generators()
	var r fr_bn.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S, Sn bn254.G1Affine
	S.ScalarMultiplication(&g, s)
	Sn.Neg(&S)

	circuit := AddUnifiedEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{}

	// (0,0) + (0,0) == (0,0)
	witness1 := AddUnifiedEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
		R: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness1, testCurve.ScalarField())
	assert.NoError(err)

	// S + (0,0) == S
	witness2 := AddUnifiedEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
		},
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
		R: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness2, testCurve.ScalarField())
	assert.NoError(err)

	// (0,0) + S == S
	witness3 := AddUnifiedEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
		},
		R: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness3, testCurve.ScalarField())
	assert.NoError(err)

	// S + (-S) == (0,0)
	witness4 := AddUnifiedEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
		},
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](Sn.X),
			Y: emulated.ValueOf[emulated.BN254Fp](Sn.Y),
		},
		R: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness4, testCurve.ScalarField())
	assert.NoError(err)

	// (-S) + S == (0,0)
	witness5 := AddUnifiedEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](Sn.X),
			Y: emulated.ValueOf[emulated.BN254Fp](Sn.Y),
		},
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
		},
		R: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness5, testCurve.ScalarField())
	assert.NoError(err)
}

type ScalarMulBaseTest[T, S emulated.FieldParams] struct {
	Q AffinePoint[T]
	S emulated.Element[S]
}

func (c *ScalarMulBaseTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.ScalarMulBase(&c.S)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestScalarMulBase(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S secp256k1.G1Affine
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := ScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMulBase2(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bn254.Generators()
	var r fr_bn.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S bn254.G1Affine
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulBaseTest[emulated.BN254Fp, emulated.BN254Fr]{}
	witness := ScalarMulBaseTest[emulated.BN254Fp, emulated.BN254Fr]{
		S: emulated.ValueOf[emulated.BN254Fr](s),
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
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
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S secp256k1.G1Affine
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := ScalarMulTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](g.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](g.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMul2(t *testing.T) {
	assert := test.NewAssert(t)
	var r fr_bn.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var res bn254.G1Affine
	_, _, gen, _ := bn254.Generators()
	res.ScalarMultiplication(&gen, s)

	circuit := ScalarMulTest[emulated.BN254Fp, emulated.BN254Fr]{}
	witness := ScalarMulTest[emulated.BN254Fp, emulated.BN254Fr]{
		S: emulated.ValueOf[emulated.BN254Fr](s),
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](gen.X),
			Y: emulated.ValueOf[emulated.BN254Fp](gen.Y),
		},
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](res.X),
			Y: emulated.ValueOf[emulated.BN254Fp](res.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type ScalarMulEdgeCases[T, S emulated.FieldParams] struct {
	P, R AffinePoint[T]
	S    emulated.Element[S]
}

func (c *ScalarMulEdgeCases[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S)
	cr.AssertIsEqual(res, &c.R)
	return nil
}

func TestScalarMulEdgeCasesEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	var infinity bn254.G1Affine
	_, _, g, _ := bn254.Generators()
	var r fr_bn.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S bn254.G1Affine
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{}

	// s * (0,0) == (0,0)
	witness1 := ScalarMulEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{
		S: emulated.ValueOf[emulated.BN254Fr](s),
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
		R: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness1, testCurve.ScalarField())
	assert.NoError(err)

	// 0 * S == (0,0)
	witness2 := ScalarMulEdgeCases[emulated.BN254Fp, emulated.BN254Fr]{
		S: emulated.ValueOf[emulated.BN254Fr](new(big.Int)),
		P: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](S.X),
			Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
		},
		R: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness2, testCurve.ScalarField())
	assert.NoError(err)
}
