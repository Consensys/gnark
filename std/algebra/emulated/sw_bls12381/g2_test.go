package sw_bls12381

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type addG2Circuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *addG2Circuit) Define(api frontend.API) error {
	g2 := NewG2(api)
	res := g2.add(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Add(&in1, &in2)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestAddG2FailureCaseTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Double(&in1)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{}, &witness, ecc.BN254.ScalarField())
	// the add() function cannot handle identical inputs
	assert.Error(err)
}

type addG2UnifiedCircuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *addG2UnifiedCircuit) Define(api frontend.API) error {
	g2 := NewG2(api)
	res := g2.addUnified(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestAddG2UnifiedTestSolveAdd(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Add(&in1, &in2)
	witness := addG2UnifiedCircuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2UnifiedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestAddG2UnifiedTestSolveDbl(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Double(&in1)
	witness := addG2UnifiedCircuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2UnifiedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestAddG2UnifiedTestSolveEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	_, p := randomG1G2Affines()
	var np, zero bls12381.G2Affine
	np.Neg(&p)
	zero.Sub(&p, &p)

	// p + (-p) == (0, 0)
	witness := addG2UnifiedCircuit{
		In1: NewG2Affine(p),
		In2: NewG2Affine(np),
		Res: NewG2Affine(zero),
	}
	err := test.IsSolved(&addG2UnifiedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	// (-p) + p == (0, 0)
	witness2 := addG2UnifiedCircuit{
		In1: NewG2Affine(np),
		In2: NewG2Affine(p),
		Res: NewG2Affine(zero),
	}
	err2 := test.IsSolved(&addG2UnifiedCircuit{}, &witness2, ecc.BN254.ScalarField())
	assert.NoError(err2)

	// p + (0, 0) == p
	witness3 := addG2UnifiedCircuit{
		In1: NewG2Affine(p),
		In2: NewG2Affine(zero),
		Res: NewG2Affine(p),
	}
	err3 := test.IsSolved(&addG2UnifiedCircuit{}, &witness3, ecc.BN254.ScalarField())
	assert.NoError(err3)

	// (0, 0) + p == p
	witness4 := addG2UnifiedCircuit{
		In1: NewG2Affine(zero),
		In2: NewG2Affine(p),
		Res: NewG2Affine(p),
	}
	err4 := test.IsSolved(&addG2UnifiedCircuit{}, &witness4, ecc.BN254.ScalarField())
	assert.NoError(err4)

	// (0, 0) + (0, 0) == (0, 0)
	witness5 := addG2UnifiedCircuit{
		In1: NewG2Affine(zero),
		In2: NewG2Affine(zero),
		Res: NewG2Affine(zero),
	}
	err5 := test.IsSolved(&addG2UnifiedCircuit{}, &witness5, ecc.BN254.ScalarField())
	assert.NoError(err5)

}

type doubleG2Circuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *doubleG2Circuit) Define(api frontend.API) error {
	g2 := NewG2(api)
	res := g2.double(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	var in1Jac, resJac bls12381.G2Jac
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
	g2 := NewG2(api)
	res := g2.doubleAndAdd(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleAndAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
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
	g2 := NewG2(api)
	res := g2.scalarMulBySeed(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2BySeedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	x0, _ := new(big.Int).SetString("15132376222941642752", 10)
	res.ScalarMultiplication(&in1, x0).Neg(&res)
	witness := scalarMulG2BySeedCircuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2BySeedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
