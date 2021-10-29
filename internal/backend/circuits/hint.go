package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type hintCircuit struct {
	A, B frontend.Variable
}

func (circuit *hintCircuit) Define(curveID ecc.ID, api frontend.API) error {
	a7 := api.NewHint(mulBy7, circuit.A)
	_a7 := api.Mul(circuit.A, 7)

	api.AssertIsEqual(a7, _a7)
	api.AssertIsEqual(a7, circuit.B)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&hintCircuit{
			A: frontend.Value(42),
			B: frontend.Value(42 * 7),
		},
	}

	bad := []frontend.Circuit{
		&hintCircuit{
			A: frontend.Value(42),
			B: frontend.Value(42),
		},
	}

	addNewEntry("hint", &hintCircuit{}, good, bad, mulBy7)
}

func mulBy7(curveID ecc.ID, inputs []*big.Int, result *big.Int) error {
	result.Mul(inputs[0], big.NewInt(7)).Mod(result, curveID.Info().Fr.Modulus())
	return nil
}
