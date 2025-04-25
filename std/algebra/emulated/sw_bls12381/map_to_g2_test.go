package sw_bls12381

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/test"
)

type TestG2IsogenyCircuit struct {
	In       G2Affine
	Expected G2Affine
}

func (c *TestG2IsogenyCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res := g2.isogeny(&c.In)
	g2.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestG2Isogeny(t *testing.T) {
	assert := test.NewAssert(t)
	_, in := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Set(&in)
	hash_to_curve.G2Isogeny(&res.X, &res.Y)
	assignment := TestG2IsogenyCircuit{
		In:       NewG2Affine(in),
		Expected: NewG2Affine(res),
	}
	err := test.IsSolved(&TestG2IsogenyCircuit{}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type clearCofactorCircuit struct {
	In  G2Affine
	Res G2Affine
}

func (c *clearCofactorCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ClearCofactor(&c.In)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestClearCofactorTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in := randomG1G2Affines()

	inAffine := NewG2Affine(in)

	in.ClearCofactor(&in)
	circuit := clearCofactorCircuit{
		In:  inAffine,
		Res: NewG2Affine(in),
	}
	witness := clearCofactorCircuit{
		In:  inAffine,
		Res: NewG2Affine(in),
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MapToCurve2Circuit struct {
	In       fields_bls12381.E2
	Expected G2Affine
}

func (c *MapToCurve2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res, err := g2.MapToCurve2(&c.In)
	if err != nil {
		return err
	}
	g2.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMapToCurve2(t *testing.T) {
	assert := test.NewAssert(t)
	var e2 bls12381.E2
	e2.A0.SetRandom()
	e2.A1.SetRandom()

	res := bls12381.MapToCurve2(&e2)

	assignment := MapToCurve2Circuit{
		In:       fields_bls12381.FromE2(&e2),
		Expected: NewG2Affine(res),
	}
	err := test.IsSolved(&MapToCurve2Circuit{}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MapToG2Circuit struct {
	In       fields_bls12381.E2
	Expected G2Affine
}

func (c *MapToG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res, err := g2.MapToG2(&c.In)
	if err != nil {
		return err
	}
	g2.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMapToG2(t *testing.T) {
	assert := test.NewAssert(t)
	var e2 bls12381.E2
	e2.A0.SetRandom()
	e2.A1.SetRandom()

	res := bls12381.MapToG2(e2)

	assignment := MapToG2Circuit{
		In:       fields_bls12381.FromE2(&e2),
		Expected: NewG2Affine(res),
	}
	err := test.IsSolved(&MapToG2Circuit{}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
