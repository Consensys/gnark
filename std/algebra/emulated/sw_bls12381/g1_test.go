package sw_bls12381

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type tripleCircuit struct {
	In, Res G1Affine
}

func (c *tripleCircuit) Define(api frontend.API) error {
	g1, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1 struct: %w", err)
	}
	res := g1.triple(&c.In)
	g1.AssertIsEqual(res, &c.Res)
	return nil
}

type tripleCircuitConsistency struct {
	In G1Affine
}

func (c *tripleCircuitConsistency) Define(api frontend.API) error {
	g1, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1 struct: %w", err)
	}
	res1 := g1.triple(&c.In)
	res2 := g1.double(&c.In)
	res2 = g1.add(res2, &c.In)
	g1.AssertIsEqual(res1, res2)
	return nil
}

func TestTripleG1(t *testing.T) {
	assert := test.NewAssert(t)
	in, _ := randomG1G2Affines()
	var res bls12381.G1Affine
	res.Double(&in).Add(&res, &in)
	witness := tripleCircuit{
		In:  NewG1Affine(in),
		Res: NewG1Affine(res),
	}
	err := test.IsSolved(&tripleCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	witness2 := tripleCircuitConsistency{
		In: NewG1Affine(in),
	}
	err = test.IsSolved(&tripleCircuitConsistency{}, &witness2, ecc.BN254.ScalarField())
	assert.NoError(err)
}
