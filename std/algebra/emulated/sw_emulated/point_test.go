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

func TestMarshalG1OnBN254(t *testing.T) {
	assert := test.NewAssert(t)
	testFn := func(r fr_bn.Element) {
		var P bn254.G1Affine
		P.ScalarMultiplicationBase(r.BigInt(new(big.Int)))

		gBytes := P.Marshal()

		nbBytes := 2 * fr_bn.Bytes
		nbBits := nbBytes * 8
		circuit := &MarshalG1Test[emulated.BN254Fp, emulated.BN254Fr]{
			R: make([]frontend.Variable, nbBits),
		}
		witness := &MarshalG1Test[emulated.BN254Fp, emulated.BN254Fr]{
			G: AffinePoint[emulated.BN254Fp]{
				X: emulated.ValueOf[emulated.BN254Fp](P.X),
				Y: emulated.ValueOf[emulated.BN254Fp](P.Y),
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
		var r fr_bn.Element
		r.SetRandom()
		testFn(r)
	})
	assert.Run(func(assert *test.Assert) {
		var r fr_bn.Element
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
	p256 := elliptic.P256()
	s, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	px, py := p256.ScalarBaseMult(s.Bytes())

	circuit := ScalarMulBaseTest[emulated.P256Fp, emulated.P256Fr]{}
	witness := ScalarMulBaseTest[emulated.P256Fp, emulated.P256Fr]{
		S: emulated.ValueOf[emulated.P256Fr](s),
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](px),
			Y: emulated.ValueOf[emulated.P256Fp](py),
		},
	}
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMulBase5(t *testing.T) {
	assert := test.NewAssert(t)
	p384 := elliptic.P384()
	s, err := rand.Int(rand.Reader, p384.Params().N)
	assert.NoError(err)
	px, py := p384.ScalarBaseMult(s.Bytes())

	circuit := ScalarMulBaseTest[emulated.P384Fp, emulated.P384Fr]{}
	witness := ScalarMulBaseTest[emulated.P384Fp, emulated.P384Fr]{
		S: emulated.ValueOf[emulated.P384Fr](s),
		Q: AffinePoint[emulated.P384Fp]{
			X: emulated.ValueOf[emulated.P384Fp](px),
			Y: emulated.ValueOf[emulated.P384Fp](py),
		},
	}
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestScalarMulBase6(t *testing.T) {
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
	res := cr.ScalarMul(&c.P, &c.S, algopts.WithCompleteArithmetic())
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

func TestJointScalarMulBase4(t *testing.T) {
	assert := test.NewAssert(t)
	p256 := elliptic.P256()
	s1, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	s2, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	p1x, p1y := p256.ScalarBaseMult(s1.Bytes())
	resx, resy := p256.ScalarMult(p1x, p1y, s1.Bytes())
	tmpx, tmpy := p256.ScalarBaseMult(s2.Bytes())
	resx, resy = p256.Add(resx, resy, tmpx, tmpy)

	circuit := JointScalarMulBaseTest[emulated.P256Fp, emulated.P256Fr]{}
	witness := JointScalarMulBaseTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](s2),
		S2: emulated.ValueOf[emulated.P256Fr](s1),
		P: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p1x),
			Y: emulated.ValueOf[emulated.P256Fp](p1y),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](resx),
			Y: emulated.ValueOf[emulated.P256Fp](resy),
		},
	}
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type MultiScalarMulEdgeCasesTest[T, S emulated.FieldParams] struct {
	Points  []AffinePoint[T]
	Scalars []emulated.Element[S]
	Res     AffinePoint[T]
}

func (c *MultiScalarMulEdgeCasesTest[T, S]) Define(api frontend.API) error {
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
	res, err := cr.MultiScalarMul(ps, ss, algopts.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMulEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 5
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
	cS := make([]emulated.Element[emparams.BW6761Fr], len(S))
	var infinity bw6761.G1Affine

	// s1 * (0,0) + s2 * (0,0) + s3 * (0,0) + s4 * (0,0)  + s5 * (0,0) == (0,0)
	for i := range cP {
		cP[i] = AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](infinity.Y),
		}
	}
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BW6761Fr](S[i])
	}
	assignment1 := MultiScalarMulEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  cP,
		Scalars: cS,
		Res: AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&MultiScalarMulEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  make([]AffinePoint[emparams.BW6761Fp], nbLen),
		Scalars: make([]emulated.Element[emparams.BW6761Fr], nbLen),
	}, &assignment1, ecc.BN254.ScalarField())
	assert.NoError(err)

	// 0 * P1 + 0 * P2 + 0 * P3 + 0 * P4 + 0 * P5 == (0,0)
	for i := range cP {
		cP[i] = AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](P[i].X),
			Y: emulated.ValueOf[emparams.BW6761Fp](P[i].Y),
		}
	}
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BW6761Fr](0)
	}
	assignment2 := MultiScalarMulEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  cP,
		Scalars: cS,
		Res: AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&MultiScalarMulEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  make([]AffinePoint[emparams.BW6761Fp], nbLen),
		Scalars: make([]emulated.Element[emparams.BW6761Fr], nbLen),
	}, &assignment2, ecc.BN254.ScalarField())
	assert.NoError(err)

	// s1 * (0,0) + s2 * P2 + s3 * (0,0) + s4 * P4 + 0 * P5 == s2 * P + s4 * P4
	var res3 bw6761.G1Affine
	res3.ScalarMultiplication(&P[1], S[1].BigInt(new(big.Int)))
	res.ScalarMultiplication(&P[3], S[3].BigInt(new(big.Int)))
	res3.Add(&res3, &res)
	for i := range cP {
		cP[i] = AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](P[i].X),
			Y: emulated.ValueOf[emparams.BW6761Fp](P[i].Y),
		}
	}
	cP[0] = AffinePoint[emparams.BW6761Fp]{
		X: emulated.ValueOf[emparams.BW6761Fp](infinity.X),
		Y: emulated.ValueOf[emparams.BW6761Fp](infinity.Y),
	}
	cP[2] = AffinePoint[emparams.BW6761Fp]{
		X: emulated.ValueOf[emparams.BW6761Fp](infinity.X),
		Y: emulated.ValueOf[emparams.BW6761Fp](infinity.Y),
	}
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BW6761Fr](S[i])
	}
	cS[4] = emulated.ValueOf[emparams.BW6761Fr](0)
	assignment3 := MultiScalarMulEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  cP,
		Scalars: cS,
		Res: AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](res3.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](res3.Y),
		},
	}
	err = test.IsSolved(&MultiScalarMulEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  make([]AffinePoint[emparams.BW6761Fp], nbLen),
		Scalars: make([]emulated.Element[emparams.BW6761Fr], nbLen),
	}, &assignment3, ecc.BN254.ScalarField())
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

type MultiScalarMulFoldedEdgeCasesTest[T, S emulated.FieldParams] struct {
	Points  []AffinePoint[T]
	Scalars []emulated.Element[S]
	Res     AffinePoint[T]
}

func (c *MultiScalarMulFoldedEdgeCasesTest[T, S]) Define(api frontend.API) error {
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
	res, err := cr.MultiScalarMul(ps, ss, algopts.WithFoldingScalarMul(), algopts.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarFoldedEdgeCasesMul(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 5
	P := make([]bw6761.G1Affine, nbLen)
	S := make([]fr_bw6761.Element, nbLen)
	S[0].SetOne()
	S[1].SetRandom()
	S[2].Square(&S[1])
	S[3].Mul(&S[1], &S[2])
	S[4].Mul(&S[1], &S[3])
	for i := 0; i < nbLen; i++ {
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res, infinity bw6761.G1Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]AffinePoint[emulated.BW6761Fp], len(P))
	cS := make([]emulated.Element[emparams.BW6761Fr], len(S))

	// s^0 * (0,0) + s^1 * (0,0) + s^2 * (0,0) + s^3 * (0,0)  + s^4 * (0,0) == (0,0)
	for i := range cP {
		cP[i] = AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](infinity.Y),
		}
	}
	// s0 = s
	S[0].Set(&S[1])
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BW6761Fr](S[i])
	}
	assignment1 := MultiScalarMulFoldedEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  cP,
		Scalars: cS,
		Res: AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&MultiScalarMulFoldedEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  make([]AffinePoint[emparams.BW6761Fp], nbLen),
		Scalars: make([]emulated.Element[emparams.BW6761Fr], nbLen),
	}, &assignment1, ecc.BN254.ScalarField())
	assert.NoError(err)

	// 0^0 * P1 + 0 * P2 + 0 * P3 + 0 * P4 + 0 * P5 == P1
	for i := range cP {
		cP[i] = AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](P[i].X),
			Y: emulated.ValueOf[emparams.BW6761Fp](P[i].Y),
		}
	}
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BW6761Fr](0)
	}
	assignment2 := MultiScalarMulFoldedEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  cP,
		Scalars: cS,
		Res: AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](P[0].X),
			Y: emulated.ValueOf[emparams.BW6761Fp](P[0].Y),
		},
	}
	err = test.IsSolved(&MultiScalarMulFoldedEdgeCasesTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  make([]AffinePoint[emparams.BW6761Fp], nbLen),
		Scalars: make([]emulated.Element[emparams.BW6761Fr], nbLen),
	}, &assignment2, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiScalarMulFoldedTest[T, S emulated.FieldParams] struct {
	Points  []AffinePoint[T]
	Scalars []emulated.Element[S]
	Res     AffinePoint[T]
}

func (c *MultiScalarMulFoldedTest[T, S]) Define(api frontend.API) error {
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
	res, err := cr.MultiScalarMul(ps, ss, algopts.WithFoldingScalarMul())
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarFoldedMul(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 4
	P := make([]bw6761.G1Affine, nbLen)
	S := make([]fr_bw6761.Element, nbLen)
	// [s^0]P0 + [s^1]P1 + [s^2]P2 + [s^3]P3 = P0 + [s]P1 + [s^2]P2 + [s^3]P3
	S[0].SetOne()
	S[1].SetRandom()
	S[2].Square(&S[1])
	S[3].Mul(&S[1], &S[2])
	for i := 0; i < nbLen; i++ {
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
	// s0 = s
	S[0].Set(&S[1])
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BW6761Fr](S[i])
	}
	assignment := MultiScalarMulFoldedTest[emparams.BW6761Fp, emparams.BW6761Fr]{
		Points:  cP,
		Scalars: cS,
		Res: AffinePoint[emparams.BW6761Fp]{
			X: emulated.ValueOf[emparams.BW6761Fp](res.X),
			Y: emulated.ValueOf[emparams.BW6761Fp](res.Y),
		},
	}
	err = test.IsSolved(&MultiScalarMulFoldedTest[emparams.BW6761Fp, emparams.BW6761Fr]{
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
	res := cr.scalarMulGeneric(&c.P, &c.S, algopts.WithNbScalarBits(c.bits))
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

func TestJointScalarMul4(t *testing.T) {
	assert := test.NewAssert(t)
	p256 := elliptic.P256()
	s1, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	s2, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	p1x, p1y := p256.ScalarBaseMult(s1.Bytes())
	p2x, p2y := p256.ScalarBaseMult(s2.Bytes())
	resx, resy := p256.ScalarMult(p1x, p1y, s1.Bytes())
	tmpx, tmpy := p256.ScalarMult(p2x, p2y, s2.Bytes())
	resx, resy = p256.Add(resx, resy, tmpx, tmpy)

	circuit := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{}
	witness := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](s1),
		S2: emulated.ValueOf[emulated.P256Fr](s2),
		P1: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p1x),
			Y: emulated.ValueOf[emulated.P256Fp](p1y),
		},
		P2: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p2x),
			Y: emulated.ValueOf[emulated.P256Fp](p2y),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](resx),
			Y: emulated.ValueOf[emulated.P256Fp](resy),
		},
	}
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

// We explicitly choose here P1 and P2 s.t. P1+P2 = Φ(G) (G the base point).
// This should sometimes (when the sub-scalars are positive in the hint)
// triggers the edge case Q + R + Φ(Q) + Φ(R) + G == inf
func TestJointScalarMulSpecial6(t *testing.T) {
	assert := test.NewAssert(t)
	var r1, r2 fr_bw6761.Element
	_, _ = r1.SetRandom()
	_, _ = r2.SetRandom()
	s1 := new(big.Int)
	s2 := new(big.Int)
	r1.BigInt(s1)
	r2.BigInt(s2)
	var res, tmp, p1, p2 bw6761.G1Affine
	// P1
	p1.ScalarMultiplicationBase(s1)
	// P2 = Φ(G)-P1
	_, _, g, _ := bw6761.Generators()
	var lambdaGLV big.Int
	lambdaGLV.SetString("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945", 10) // (x⁵-3x⁴+3x³-x+1)
	g.ScalarMultiplication(&g, &lambdaGLV)
	p2.Sub(&g, &p1)
	// res = [s1]P+[s2]P
	tmp.ScalarMultiplication(&p1, s1)
	res.ScalarMultiplication(&p2, s2)
	res.Add(&res, &tmp)

	circuit := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{}
	witness := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](s1),
		S2: emulated.ValueOf[emulated.BW6761Fr](s2),
		P1: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](p1.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](p1.Y),
		},
		P2: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](p2.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](p2.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](res.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](res.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type JointScalarMulEdgeCasesTest[T, S emulated.FieldParams] struct {
	P1, P2, Q AffinePoint[T]
	S1, S2    emulated.Element[S]
}

func (c *JointScalarMulEdgeCasesTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.jointScalarMul(&c.P1, &c.P2, &c.S1, &c.S2, algopts.WithCompleteArithmetic())
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestJointScalarMulEdgeCases6(t *testing.T) {
	assert := test.NewAssert(t)
	var r1, r2 fr_bw6761.Element
	_, _ = r1.SetRandom()
	_, _ = r2.SetRandom()
	s1 := new(big.Int)
	s2 := new(big.Int)
	r1.BigInt(s1)
	r2.BigInt(s2)
	var res1, res2, gen2, infinity bw6761.G1Affine
	_, _, gen1, _ := bw6761.Generators()
	gen2.Double(&gen1)
	res1.ScalarMultiplication(&gen1, s1)
	res2.ScalarMultiplication(&gen2, s2)

	circuit := JointScalarMulEdgeCasesTest[emulated.BW6761Fp, emulated.BW6761Fr]{}
	// s1*(0,0) + s2*(0,0) == (0,0)
	witness1 := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](s1),
		S2: emulated.ValueOf[emulated.BW6761Fr](s2),
		P1: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](infinity.Y),
		},
		P2: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](infinity.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](infinity.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness1, testCurve.ScalarField())
	assert.NoError(err)

	// s1*P + s2*(0,0) == s1*P
	witness2 := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](s1),
		S2: emulated.ValueOf[emulated.BW6761Fr](s2),
		P1: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen1.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen1.Y),
		},
		P2: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](infinity.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](res1.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](res1.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness2, testCurve.ScalarField())
	assert.NoError(err)

	// s1*(0,0) + s2*Q == s2*Q
	witness3 := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](s1),
		S2: emulated.ValueOf[emulated.BW6761Fr](s2),
		P1: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](infinity.Y),
		},
		P2: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen2.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen2.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](res2.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](res2.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness3, testCurve.ScalarField())
	assert.NoError(err)

	// 0*P + 0*Q == (0,0)
	witness4 := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](0),
		S2: emulated.ValueOf[emulated.BW6761Fr](0),
		P1: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen1.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen1.Y),
		},
		P2: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen2.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen2.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](infinity.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](infinity.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness4, testCurve.ScalarField())
	assert.NoError(err)

	// 0*P + s2*Q == s2*Q
	witness5 := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](0),
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
			X: emulated.ValueOf[emulated.BW6761Fp](res2.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](res2.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness5, testCurve.ScalarField())
	assert.NoError(err)

	// s1*P + 0*Q == s1*P
	witness6 := JointScalarMulTest[emulated.BW6761Fp, emulated.BW6761Fr]{
		S1: emulated.ValueOf[emulated.BW6761Fr](s1),
		S2: emulated.ValueOf[emulated.BW6761Fr](0),
		P1: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen1.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen1.Y),
		},
		P2: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](gen2.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](gen2.Y),
		},
		Q: AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](res1.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](res1.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness6, testCurve.ScalarField())
	assert.NoError(err)
}

func TestJointScalarMulEdgeCases4(t *testing.T) {
	assert := test.NewAssert(t)
	p256 := elliptic.P256()
	s1, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	s2, err := rand.Int(rand.Reader, p256.Params().N)
	assert.NoError(err)
	p1x, p1y := p256.ScalarBaseMult(s1.Bytes())
	p2x, p2y := p256.ScalarBaseMult(s2.Bytes())
	res1x, res1y := p256.ScalarMult(p1x, p1y, s1.Bytes())
	res2x, res2y := p256.ScalarMult(p2x, p2y, s2.Bytes())

	circuit := JointScalarMulEdgeCasesTest[emulated.P256Fp, emulated.P256Fr]{}
	// s1*(0,0) + s2*(0,0) == (0,0)
	witness1 := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](s1),
		S2: emulated.ValueOf[emulated.P256Fr](s2),
		P1: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](0),
			Y: emulated.ValueOf[emulated.P256Fp](0),
		},
		P2: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](0),
			Y: emulated.ValueOf[emulated.P256Fp](0),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](0),
			Y: emulated.ValueOf[emulated.P256Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness1, testCurve.ScalarField())
	assert.NoError(err)

	// s1*P + s2*(0,0) == s1*P
	witness2 := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](s1),
		S2: emulated.ValueOf[emulated.P256Fr](s2),
		P1: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p1x),
			Y: emulated.ValueOf[emulated.P256Fp](p1y),
		},
		P2: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](0),
			Y: emulated.ValueOf[emulated.P256Fp](0),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](res1x),
			Y: emulated.ValueOf[emulated.P256Fp](res1y),
		},
	}
	err = test.IsSolved(&circuit, &witness2, testCurve.ScalarField())
	assert.NoError(err)

	// s1*(0,0) + s2*Q == s2*Q
	witness3 := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](s1),
		S2: emulated.ValueOf[emulated.P256Fr](s2),
		P1: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](0),
			Y: emulated.ValueOf[emulated.P256Fp](0),
		},
		P2: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p2x),
			Y: emulated.ValueOf[emulated.P256Fp](p2y),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](res2x),
			Y: emulated.ValueOf[emulated.P256Fp](res2y),
		},
	}
	err = test.IsSolved(&circuit, &witness3, testCurve.ScalarField())
	assert.NoError(err)

	// 0*P + 0*Q == (0,0)
	witness4 := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](0),
		S2: emulated.ValueOf[emulated.P256Fr](0),
		P1: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p1x),
			Y: emulated.ValueOf[emulated.P256Fp](p1y),
		},
		P2: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p2x),
			Y: emulated.ValueOf[emulated.P256Fp](p2y),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](0),
			Y: emulated.ValueOf[emulated.P256Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness4, testCurve.ScalarField())
	assert.NoError(err)

	// 0*P + s2*Q == s2*Q
	witness5 := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](0),
		S2: emulated.ValueOf[emulated.P256Fr](s2),
		P1: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p1x),
			Y: emulated.ValueOf[emulated.P256Fp](p1y),
		},
		P2: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p2x),
			Y: emulated.ValueOf[emulated.P256Fp](p2y),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](res2x),
			Y: emulated.ValueOf[emulated.P256Fp](res2y),
		},
	}
	err = test.IsSolved(&circuit, &witness5, testCurve.ScalarField())
	assert.NoError(err)

	// s1*P + 0*Q == s1*P
	witness6 := JointScalarMulTest[emulated.P256Fp, emulated.P256Fr]{
		S1: emulated.ValueOf[emulated.P256Fr](s1),
		S2: emulated.ValueOf[emulated.P256Fr](0),
		P1: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p1x),
			Y: emulated.ValueOf[emulated.P256Fp](p1y),
		},
		P2: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](p2x),
			Y: emulated.ValueOf[emulated.P256Fp](p2y),
		},
		Q: AffinePoint[emulated.P256Fp]{
			X: emulated.ValueOf[emulated.P256Fp](res1x),
			Y: emulated.ValueOf[emulated.P256Fp](res1y),
		},
	}
	err = test.IsSolved(&circuit, &witness6, testCurve.ScalarField())
	assert.NoError(err)
}

type MuxCircuitTest[T, S emulated.FieldParams] struct {
	Selector frontend.Variable
	Inputs   [8]AffinePoint[T]
	Expected AffinePoint[T]
}

func (c *MuxCircuitTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	els := make([]*AffinePoint[T], len(c.Inputs))
	for i := range c.Inputs {
		els[i] = &c.Inputs[i]
	}
	res := cr.Mux(c.Selector, els...)
	cr.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMux(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MuxCircuitTest[emulated.BN254Fp, emulated.BN254Fr]{}
	r := make([]fr_bn.Element, len(circuit.Inputs))
	for i := range r {
		r[i].SetRandom()
	}
	selector, _ := rand.Int(rand.Reader, big.NewInt(int64(len(r))))
	expectedR := r[selector.Int64()]
	expected := new(bn254.G1Affine).ScalarMultiplicationBase(expectedR.BigInt(new(big.Int)))
	witness := MuxCircuitTest[emulated.BN254Fp, emulated.BLS12381Fr]{
		Selector: selector,
		Expected: AffinePoint[emparams.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](expected.X),
			Y: emulated.ValueOf[emulated.BN254Fp](expected.Y),
		},
	}
	for i := range r {
		eli := new(bn254.G1Affine).ScalarMultiplicationBase(r[i].BigInt(new(big.Int)))
		witness.Inputs[i] = AffinePoint[emparams.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](eli.X),
			Y: emulated.ValueOf[emulated.BN254Fp](eli.Y),
		}
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}
