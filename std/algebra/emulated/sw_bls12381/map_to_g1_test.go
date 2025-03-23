package sw_bls12381

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// Test clear cofactor
type ClearCofactorCircuit struct {
	Point G1Affine
	Res   G1Affine
}

func (circuit *ClearCofactorCircuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}
	clearedPoint, err := ClearCofactor(g, &circuit.Point)
	if err != nil {
		return err
	}
	g.AssertIsEqual(clearedPoint, &circuit.Res)
	return nil
}

func TestClearCofactor(t *testing.T) {

	assert := test.NewAssert(t)
	_, _, g1, _ := bls12381.Generators()
	var g2 bls12381.G1Affine
	g2.ClearCofactor(&g1)
	witness := ClearCofactorCircuit{
		Point: NewG1Affine(g1),
		Res:   NewG1Affine(g2),
	}
	err := test.IsSolved(&ClearCofactorCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

// Test MapToCurve
type MapToCurve struct {
	U   FpElement
	Res G1Affine
}

func (circuit *MapToCurve) Define(api frontend.API) error {

	g, err := NewG1(api)
	if err != nil {
		return err
	}

	r, err := MapToCurve1(api, &circuit.U)
	if err != nil {
		return err
	}
	api.Println(r.Y.Limbs...)

	g.AssertIsEqual(&r, &circuit.Res)

	return nil
}

func TestMapToCurve(t *testing.T) {

	assert := test.NewAssert(t)
	var a fp.Element
	a.SetRandom()
	g := bls12381.MapToCurve1(&a)
	fmt.Printf("g.Y = %s\n", g.Y.String())

	witness := MapToCurve{
		U:   emulated.ValueOf[emulated.BLS12381Fp](a.String()),
		Res: NewG1Affine(g),
	}
	err := test.IsSolved(&MapToCurve{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
