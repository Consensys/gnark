package sw_bn254

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type addG2Circuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *addG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.add(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Add(&in1, &in2)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type doubleG2Circuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *doubleG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.double(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	var in1Jac, resJac bn254.G2Jac
	in1Jac.FromAffine(&in1)
	resJac.Double(&in1Jac)
	res.FromJacobian(&resJac)
	witness := doubleG2Circuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&doubleG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type doubleAndAddG2Circuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *doubleAndAddG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.doubleAndAdd(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleAndAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Double(&in1).
		Add(&res, &in2)
	witness := doubleAndAddG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&doubleAndAddG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type scalarMulG2BySeedCircuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *scalarMulG2BySeedCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.scalarMulBySeed(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2BySeedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	x0, _ := new(big.Int).SetString("4965661367192848881", 10)
	res.ScalarMultiplication(&in1, x0)
	witness := scalarMulG2BySeedCircuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2BySeedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type endomorphismG2Circuit struct {
	In1 G2Affine
}

func (c *endomorphismG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res1 := g2.phi(&c.In1)
	res2 := g2.psi(&c.In1)
	res2 = g2.psi(res2)
	g2.AssertIsEqual(res1, res2)
	return nil
}

func TestEndomorphismG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	witness := endomorphismG2Circuit{
		In1: NewG2Affine(in1),
	}
	err := test.IsSolved(&endomorphismG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type scalarMulG2GLVAndFakeGLVCircuit struct {
	In  G2Affine
	Res G2Affine
	S   Scalar
}

func (c *scalarMulG2GLVAndFakeGLVCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.In, &c.S)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2GLVAndFakeGLV(t *testing.T) {
	assert := test.NewAssert(t)
	// Use a fixed scalar for reproducibility
	s := big.NewInt(12345)
	var sFr fr.Element
	sFr.SetBigInt(s)

	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	res.ScalarMultiplication(&in1, s)

	witness := scalarMulG2GLVAndFakeGLVCircuit{
		In:  NewG2Affine(in1),
		S:   NewScalar(sFr),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2GLVAndFakeGLVCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestScalarMulG2GLVAndFakeGLVRandom(t *testing.T) {
	assert := test.NewAssert(t)
	// Use a random scalar
	s, _ := rand.Int(rand.Reader, fr.Modulus())
	var sFr fr.Element
	sFr.SetBigInt(s)

	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	res.ScalarMultiplication(&in1, s)

	witness := scalarMulG2GLVAndFakeGLVCircuit{
		In:  NewG2Affine(in1),
		S:   NewScalar(sFr),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2GLVAndFakeGLVCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
