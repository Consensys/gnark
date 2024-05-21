package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type ZeroCircuit[T FieldParams] struct {
	Var    Element[T]
	IsZero frontend.Variable `gnark:",public"`
}

func (c *ZeroCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.IsZero(&c.Var)
	f.api.AssertIsEqual(res, c.IsZero)
	return nil
}

func TestZeroCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	type T = BLS12381Fp
	var circuit, witness ZeroCircuit[T]
	{
		//Non-zero
		el := Element[T]{
			Limbs:    []frontend.Variable{0, 1, 0, 1, 0, 1},
			overflow: 0,
			internal: true,
		}
		witness.Var = el
		witness.IsZero = 0

		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}
	{
		//Zero
		el := Element[T]{
			Limbs:    []frontend.Variable{0, 0, 0, 0, 0, 0},
			overflow: 0,
			internal: true,
		}
		witness.Var = el
		witness.IsZero = 1

		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}
}
