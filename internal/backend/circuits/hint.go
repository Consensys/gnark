package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type hintCircuit struct {
	A, B frontend.Variable
}

func (circuit *hintCircuit) Define(api frontend.API) error {
	a7 := api.NewHint(mulBy7, circuit.A)
	_a7 := api.Mul(circuit.A, 7)

	api.AssertIsEqual(a7, _a7)
	api.AssertIsEqual(a7, circuit.B)
	c := api.NewHint(make3)
	c = api.Mul(c, c)
	api.AssertIsEqual(c, 9)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&hintCircuit{
			A: (42),
			B: (42 * 7),
		},
	}

	bad := []frontend.Circuit{
		&hintCircuit{
			A: (42),
			B: (42),
		},
	}

	addNewEntry("hint", &hintCircuit{}, good, bad, ecc.Implemented(), mulBy7, make3)
}

func mulBy7(curveID ecc.ID, inputs []*big.Int, result *big.Int) error {
	result.Mul(inputs[0], big.NewInt(7)).Mod(result, curveID.Info().Fr.Modulus())
	return nil
}

func make3(curveID ecc.ID, inputs []*big.Int, result *big.Int) error {
	result.SetUint64(3)
	return nil
}
