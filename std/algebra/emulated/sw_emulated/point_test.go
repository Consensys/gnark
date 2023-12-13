package sw_emulated

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fp_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fp_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

var testCurve = ecc.BN254

type MarshalScalarTest[T, S emulated.FieldParams] struct {
	X emulated.Element[S]
	R []frontend.Variable
}

func (c *MarshalScalarTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	br := cr.MarshalScalar(c.X)
	for i := 0; i < len(c.R); i++ {
		api.AssertIsEqual(c.R[i], br[i])
	}
	return nil
}

func TestMarshalScalar(t *testing.T) {
	assert := test.NewAssert(t)
	var r fr_bw6761.Element
	r.SetRandom()
	rBytes := r.Marshal()
	nbBytes := fr_bw6761.Bytes
	nbBits := nbBytes * 8
	circuit := &MarshalScalarTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		R: make([]frontend.Variable, nbBits),
	}
	witness := &MarshalScalarTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		X: emulated.ValueOf[emulated.BW6761Fr](r),
		R: make([]frontend.Variable, nbBits),
	}
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			witness.R[i*8+j] = (rBytes[i] >> (7 - j)) & 1
		}
	}
	err := test.IsSolved(circuit, witness, testCurve.ScalarField())
	assert.NoError(err)
}

type MarshalG1Test[T, S emulated.FieldParams] struct {
	G AffinePoint[T]
	R []frontend.Variable
}

func (c *MarshalG1Test[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	br := cr.MarshalG1(c.G)
	for i := 0; i < len(c.R); i++ {
		api.AssertIsEqual(c.R[i], br[i])
	}
	return nil
}

func TestMarshalG1(t *testing.T) {
	assert := test.NewAssert(t)
	testFn := func(r fr_bw6761.Element) {
		var P bw6761.G1Affine
		P.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
		gBytes := P.Marshal()
		nbBytes := 2 * fp_bw6761.Bytes
		nbBits := nbBytes * 8
		circuit := &MarshalG1Test[emulated.BW6761Fp, emulated.BW6761Fr]{
			R: make([]frontend.Variable, nbBits),
		}
		witness := &MarshalG1Test[emulated.BW6761Fp, emulated.BW6761Fr]{
			G: AffinePoint[emulated.BW6761Fp]{
				X: emulated.ValueOf[emulated.BW6761Fp](P.X),
				Y: emulated.ValueOf[emulated.BW6761Fp](P.Y),
			},
			R: make([]frontend.Variable, nbBits),
		}
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				witness.R[i*8+j] = (gBytes[i] >> (7 - j)) & 1
			}
		}
		err := test.IsSolved(circuit, witness, testCurve.ScalarField())
		assert.NoError(err)
	}
	assert.Run(func(assert *test.Assert) {
		var r fr_bw6761.Element
		r.SetRandom()
		testFn(r)
	})
	assert.Run(func(assert *test.Assert) {
		var r fr_bw6761.Element
		r.SetZero()
		testFn(r)
	})
}

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

type AddUnifiedEdgeCasesTest[T, S emulated.FieldParams] struct {
	P, Q, R AffinePoint[T]
}

func (c *AddUnifiedEdgeCasesTest[T, S]) Define(api frontend.API) error {
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

	circuit := AddUnifiedEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{}

	// (0,0) + (0,0) == (0,0)
	witness1 := AddUnifiedEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{
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
	witness2 := AddUnifiedEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{
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
	witness3 := AddUnifiedEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{
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
	witness4 := AddUnifiedEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{
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
	witness5 := AddUnifiedEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{
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

func TestScalarMulBase3(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bls12381.Generators()
	var r fr_bls381.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S bls12381.G1Affine
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulBaseTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{}
	witness := ScalarMulBaseTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{
		S: emulated.ValueOf[emulated.BLS12381Fr](s),
		Q: AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](S.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](S.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMulBase4(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bw6761.Generators()
	var r fr_bw6761.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S bw6761.G1Affine
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulBaseTest[emulated.BW6761Fp, emulated.BW6761Fr]{}
	witness := ScalarMulBaseTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S: emulated.ValueOf[emulated.BW6761Fr](s),
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](S.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](S.Y),
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

func TestScalarMul3(t *testing.T) {
	assert := test.NewAssert(t)
	var r fr_bls381.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var res bls12381.G1Affine
	_, _, gen, _ := bls12381.Generators()
	res.ScalarMultiplication(&gen, s)

	circuit := ScalarMulTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{}
	witness := ScalarMulTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{
		S: emulated.ValueOf[emulated.BLS12381Fr](s),
		P: AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](gen.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](gen.Y),
		},
		Q: AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](res.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](res.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMul4(t *testing.T) {
	assert := test.NewAssert(t)
	p256 := elliptic.P256()
	s, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	px, py := p256.ScalarBaseMult(s.Bytes())

	circuit := ScalarMulTest[emulated.P256Fp, emulated.P256Fr]{}
	witness := ScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S: emulated.ValueOf[emulated.P256Fr](s),
		P: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p256.Params().Gx),
			Y: emulated.ValueOf[emulated.P256Fp](p256.Params().Gy),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](px),
			Y: emulated.ValueOf[emulated.P256Fp](py),
		},
	}
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMul5(t *testing.T) {
	assert := test.NewAssert(t)
	p384 := elliptic.P384()
	s, err := rand.Int(rand.Reader, p384.Params().N)
	assert.NoError(err)
	px, py := p384.ScalarBaseMult(s.Bytes())

	circuit := ScalarMulTest[emulated.P384Fp, emulated.P384Fr]{}
	witness := ScalarMulTest[emulated.P384Fp, emulated.P384Fr]{
		S: emulated.ValueOf[emulated.P384Fr](s),
		P: AffinePoint[emulated.P384Fp]{
			X: emulated.ValueOf[emulated.P384Fp](p384.Params().Gx),
			Y: emulated.ValueOf[emulated.P384Fp](p384.Params().Gy),
		},
		Q: AffinePoint[emulated.P384Fp]{
			X: emulated.ValueOf[emulated.P384Fp](px),
			Y: emulated.ValueOf[emulated.P384Fp](py),
		},
	}
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMul6(t *testing.T) {
	assert := test.NewAssert(t)
	var r fr_bw6761.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var res bw6761.G1Affine
	_, _, gen, _ := bw6761.Generators()
	res.ScalarMultiplication(&gen, s)

	circuit := ScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{}
	witness := ScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S: emulated.ValueOf[emulated.BW6761Fr](s),
		P: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](res.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](res.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type ScalarMulEdgeCasesTest[T, S emulated.FieldParams] struct {
	P, R AffinePoint[T]
	S    emulated.Element[S]
}

func (c *ScalarMulEdgeCasesTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.ScalarMulGeneric(&c.P, &c.S)
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

	circuit := ScalarMulEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{}

	// s * (0,0) == (0,0)
	witness1 := ScalarMulEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{
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
	witness2 := ScalarMulEdgeCasesTest[emulated.BN254Fp, emulated.BN254Fr]{
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

type IsOnCurveTest[T, S emulated.FieldParams] struct {
	Q AffinePoint[T]
}

func (c *IsOnCurveTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	cr.AssertIsOnCurve(&c.Q)
	return nil
}

func TestIsOnCurve(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var Q, infinity secp256k1.G1Affine
	Q.ScalarMultiplication(&g, s)

	// Q=[s]G is on curve
	circuit := IsOnCurveTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness1 := IsOnCurveTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Q.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Q.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness1, testCurve.ScalarField())
	assert.NoError(err)

	// (0,0) is on curve
	witness2 := IsOnCurveTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](infinity.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness2, testCurve.ScalarField())
	assert.NoError(err)
}

func TestIsOnCurve2(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bn254.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var Q, infinity bn254.G1Affine
	Q.ScalarMultiplication(&g, s)

	// Q=[s]G is on curve
	circuit := IsOnCurveTest[emulated.BN254Fp, emulated.BN254Fr]{}
	witness1 := IsOnCurveTest[emulated.BN254Fp, emulated.BN254Fr]{
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](Q.X),
			Y: emulated.ValueOf[emulated.BN254Fp](Q.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness1, testCurve.ScalarField())
	assert.NoError(err)

	// (0,0) is on curve
	witness2 := IsOnCurveTest[emulated.BN254Fp, emulated.BN254Fr]{
		Q: AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BN254Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness2, testCurve.ScalarField())
	assert.NoError(err)
}

func TestIsOnCurve3(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bls12381.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var Q, infinity bls12381.G1Affine
	Q.ScalarMultiplication(&g, s)

	// Q=[s]G is on curve
	circuit := IsOnCurveTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{}
	witness1 := IsOnCurveTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Q: AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Q.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Q.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness1, testCurve.ScalarField())
	assert.NoError(err)

	// (0,0) is on curve
	witness2 := IsOnCurveTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{
		Q: AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness2, testCurve.ScalarField())
	assert.NoError(err)
}

type JointScalarMulBaseTest[T, S emulated.FieldParams] struct {
	P, Q   AffinePoint[T]
	S1, S2 emulated.Element[S]
}

func (c *JointScalarMulBaseTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.JointScalarMulBase(&c.P, &c.S2, &c.S1)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestJointScalarMulBase(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	var p secp256k1.G1Affine
	p.Double(&g)
	var r1, r2 fr_secp.Element
	_, _ = r1.SetRandom()
	_, _ = r2.SetRandom()
	s1 := new(big.Int)
	r1.BigInt(s1)
	s2 := new(big.Int)
	r2.BigInt(s2)
	var Sj secp256k1.G1Jac
	Sj.JointScalarMultiplicationBase(&p, s1, s2)
	var S secp256k1.G1Affine
	S.FromJacobian(&Sj)

	circuit := JointScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := JointScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		S1: emulated.ValueOf[emulated.Secp256k1Fr](s1),
		S2: emulated.ValueOf[emulated.Secp256k1Fr](s2),
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](p.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](p.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type MultiScalarMulTest[T, S emulated.FieldParams] struct {
	Points  []AffinePoint[T]
	Scalars []emulated.Element[S]
	Res     AffinePoint[T]
}

func (c *MultiScalarMulTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	ps := make([]*AffinePoint[T], len(c.Points))
	for i := range c.Points {
		ps[i] = &c.Points[i]
	}
	ss := make([]*emulated.Element[S], len(c.Scalars))
	for i := range c.Scalars {
		ss[i] = &c.Scalars[i]
	}
	res, err := cr.MultiScalarMul(ps, ss)
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 4
	P := make([]bw6761.G1Affine, nbLen)
	S := make([]fr_bw6761.Element, nbLen)
	for i := 0; i < nbLen; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res bw6761.G1Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]AffinePoint[emulated.BW6761Fp], len(P))
	for i := range cP {
		cP[i] = AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](P[i].X),
			Y: emulated.ValueOf[emparams.BW6761Fp](P[i].Y),
		}
	}
	cS := make([]emulated.Element[emparams.BW6761Fr], len(S))
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BW6761Fr](S[i])
	}
	assignment := MultiScalarMulTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  cP,
		Scalars: cS,
		Res: AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](res.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](res.Y),
		},
	}
	err = test.IsSolved(&MultiScalarMulTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  make([]AffinePoint[emparams.BW6761Fp], nbLen),
		Scalars: make([]emulated.Element[emparams.BW6761Fr], nbLen),
	}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type ScalarMulTestBounded[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
	S    emulated.Element[S]
	bits int
}

func (c *ScalarMulTestBounded[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.ScalarMulGeneric(&c.P, &c.S, algopts.WithNbScalarBits(c.bits))
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestScalarMulBounded(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	nbBits := 13
	mask := big.NewInt(1)
	mask.Lsh(mask, uint(nbBits))
	mask.Sub(mask, big.NewInt(1))
	s.And(s, mask)
	var S secp256k1.G1Affine
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulTestBounded[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		bits: nbBits,
	}
	witness := ScalarMulTestBounded[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
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

//

type JointScalarMulTest[T, S emulated.FieldParams] struct {
	P1, P2, Q AffinePoint[T]
	S1, S2    emulated.Element[S]
}

func (c *JointScalarMulTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.jointScalarMul(&c.P1, &c.P2, &c.S1, &c.S2)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestJointScalarMul6(t *testing.T) {
	assert := test.NewAssert(t)
	var r1, r2 fr_bw6761.Element
	_, _ = r1.SetRandom()
	_, _ = r2.SetRandom()
	s1 := new(big.Int)
	s2 := new(big.Int)
	r1.BigInt(s1)
	r2.BigInt(s2)
	var res, tmp, gen2 bw6761.G1Affine
	_, _, gen1, _ := bw6761.Generators()
	gen2.Double(&gen1)
	tmp.ScalarMultiplication(&gen1, s1)
	res.ScalarMultiplication(&gen2, s2)
	res.Add(&res, &tmp)

	circuit := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{}
	witness := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](s1),
		S2: emulated.ValueOf[emulated.BW6761Fr](s2),
		P1: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen1.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen1.Y),
		},
		P2: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen2.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen2.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](res.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](res.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}
