package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

type hintCircuit struct {
	A, B frontend.Variable
}

func (circuit *hintCircuit) Define(api frontend.API) error {
	res, err := api.Compiler().NewHint(mulBy7, 1, circuit.A)
	if err != nil {
		return fmt.Errorf("mulBy7: %w", err)
	}
	a7 := res[0]
	_a7 := api.Mul(circuit.A, 7)

	api.AssertIsEqual(a7, _a7)
	api.AssertIsEqual(a7, circuit.B)
	res, err = api.Compiler().NewHint(make3, 1)
	if err != nil {
		return fmt.Errorf("make3: %w", err)
	}
	c := res[0]
	c = api.Mul(c, c)
	api.AssertIsEqual(c, 9)

	return nil
}

type vectorDoubleCircuit struct {
	A []frontend.Variable
	B []frontend.Variable
}

func (c *vectorDoubleCircuit) Define(api frontend.API) error {
	res, err := api.Compiler().NewHint(dvHint, len(c.B), c.A...)
	if err != nil {
		return fmt.Errorf("double newhint: %w", err)
	}
	if len(res) != len(c.B) {
		return fmt.Errorf("expected len %d, got %d", len(c.B), len(res))
	}
	for i := range res {
		api.AssertIsEqual(api.Mul(2, c.A[i]), c.B[i])
		api.AssertIsEqual(res[i], c.B[i])
	}
	return nil
}

type recursiveHint struct {
	A frontend.Variable
}

func (circuit *recursiveHint) Define(api frontend.API) error {
	// first hint produces wire w1
	w1, _ := api.Compiler().NewHint(make3, 1)

	// this linear expression is not recorded in a R1CS just yet
	linearExpression := api.Add(circuit.A, w1[0])

	// api.ToBinary calls another hint (bits.NBits) with linearExpression as input
	// however, when the solver will resolve bits[...] it will need to detect w1 as a dependency
	// in order to compute the correct linearExpression value
	bits := api.ToBinary(linearExpression, 6)

	a := api.FromBinary(bits...)

	api.AssertIsEqual(a, 45)

	return nil
}

func init() {
	{
		good := []frontend.Circuit{
			&recursiveHint{
				A: 42,
			},
		}

		bad := []frontend.Circuit{
			&recursiveHint{
				A: 1,
			},
		}

		addNewEntry("recursive_hint", &recursiveHint{}, good, bad, nil, make3, bits.GetHints()[1])
	}

	{
		good := []frontend.Circuit{
			&hintCircuit{
				A: 42,
				B: 42 * 7,
			},
		}

		bad := []frontend.Circuit{
			&hintCircuit{
				A: 42,
				B: 42,
			},
		}

		addNewEntry("hint", &hintCircuit{}, good, bad, nil, mulBy7, make3)
	}

	{
		good := []frontend.Circuit{
			&vectorDoubleCircuit{
				A: []frontend.Variable{
					1, 2, 3, 4, 5, 6, 7, 8,
				},
				B: []frontend.Variable{
					2, 4, 6, 8, 10, 12, 14, 16,
				},
			},
		}

		bad := []frontend.Circuit{
			&vectorDoubleCircuit{
				A: []frontend.Variable{
					1, 2, 3, 4, 5, 6, 7, 8,
				},
				B: []frontend.Variable{
					1, 2, 3, 4, 5, 6, 7, 8,
				},
			},
		}
		addNewEntry("multi-output-hint", &vectorDoubleCircuit{A: make([]frontend.Variable, 8), B: make([]frontend.Variable, 8)}, good, bad, nil, dvHint)
	}
}

var mulBy7 = func(q *big.Int, inputs []*big.Int, result []*big.Int) error {
	result[0].Mul(inputs[0], big.NewInt(7)).Mod(result[0], q)
	return nil
}

var make3 = func(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	result[0].SetUint64(3)
	return nil
}

var dvHint = func(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	two := big.NewInt(2)
	for i := range inputs {
		res[i].Mul(two, inputs[i])
	}
	return nil
}
