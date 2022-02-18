package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

type hintCircuit struct {
	A, B frontend.Variable
}

func (circuit *hintCircuit) Define(api frontend.API) error {
	res, err := api.NewHint(mulBy7, 1, circuit.A)
	if err != nil {
		return fmt.Errorf("mulBy7: %w", err)
	}
	a7 := res[0]
	_a7 := api.Mul(circuit.A, 7)

	api.AssertIsEqual(a7, _a7)
	api.AssertIsEqual(a7, circuit.B)
	res, err = api.NewHint(make3, 1)
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
	res, err := api.NewHint(dvHint, len(c.B), c.A...)
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

func init() {
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

		addNewEntry("hint", &hintCircuit{}, good, bad, ecc.Implemented(), mulBy7, make3)
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
		addNewEntry("multi-output-hint", &vectorDoubleCircuit{A: make([]frontend.Variable, 8), B: make([]frontend.Variable, 8)}, good, bad, ecc.Implemented(), dvHint)
	}
}

var mulBy7 = hint.NewStaticHint(func(curveID ecc.ID, inputs []*big.Int, result []*big.Int) error {
	result[0].Mul(inputs[0], big.NewInt(7)).Mod(result[0], curveID.Info().Fr.Modulus())
	return nil
}, 1, 1)

var make3 = hint.NewStaticHint(func(curveID ecc.ID, inputs []*big.Int, result []*big.Int) error {
	result[0].SetUint64(3)
	return nil
}, 0, 1)

var dvHint = &doubleVector{}

type doubleVector struct{}

func (dv *doubleVector) UUID() hint.ID {
	return hint.UUID(dv.Call)
}

func (dv *doubleVector) Call(curveID ecc.ID, inputs []*big.Int, res []*big.Int) error {
	two := big.NewInt(2)
	for i := range inputs {
		res[i].Mul(two, inputs[i])
	}
	return nil
}

func (dv *doubleVector) NbOutputs(curveID ecc.ID, nInputs int) (nOutputs int) {
	return nInputs
}

func (dv *doubleVector) String() string {
	return "double"
}
