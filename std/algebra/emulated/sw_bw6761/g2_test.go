package sw_bw6761

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type mulG2Circuit struct {
	In, Res G2Affine
	S       Scalar

	incompleteArithmetic bool
}

func (c *mulG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	opts := []algopts.AlgebraOption{}
	if c.incompleteArithmetic {
		opts = append(opts, algopts.WithIncompleteArithmetic())
	}
	res := g2.ScalarMul(&c.In, &c.S, opts...)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2EdgeCases(t *testing.T) {
	_, _, _, gen := bw6761.Generators()
	var zero, negGen, sevenGen bw6761.G2Affine
	negGen.Neg(&gen)
	sevenGen.ScalarMultiplication(&gen, big.NewInt(7))

	testCases := []struct {
		name                 string
		point                bw6761.G2Affine
		scalar               *big.Int
		expected             bw6761.G2Affine
		incompleteArithmetic bool
	}{
		{name: "zero-scalar", point: gen, scalar: big.NewInt(0), expected: zero},
		{name: "one", point: gen, scalar: big.NewInt(1), expected: gen},
		{name: "minus-one", point: gen, scalar: big.NewInt(-1), expected: negGen},
		{name: "zero-point", point: zero, scalar: big.NewInt(7), expected: zero},
		{name: "incomplete-option", point: gen, scalar: big.NewInt(7), expected: sevenGen, incompleteArithmetic: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := mulG2Circuit{
				incompleteArithmetic: tc.incompleteArithmetic,
			}
			witness := mulG2Circuit{
				In:                   NewG2Affine(tc.point),
				S:                    emulated.ValueOf[ScalarField](tc.scalar),
				Res:                  NewG2Affine(tc.expected),
				incompleteArithmetic: tc.incompleteArithmetic,
			}
			err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
			assert.NoError(err)
		})
	}
}
