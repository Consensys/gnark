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
	res, err := api.NewHint(mulBy7, circuit.A)
	if err != nil {
		return fmt.Errorf("mulBy7: %w", err)
	}
	a7 := res[0]
	_a7 := api.Mul(circuit.A, 7)

	api.AssertIsEqual(a7, _a7)
	api.AssertIsEqual(a7, circuit.B)
	res, err = api.NewHint(make3)
	if err != nil {
		return fmt.Errorf("make3: %w", err)
	}
	c := res[0]
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

var mulBy7 = hint.NewStaticHint(func(curveID ecc.ID, inputs []*big.Int, result []*big.Int) error {
	result[0].Mul(inputs[0], big.NewInt(7)).Mod(result[0], curveID.Info().Fr.Modulus())
	return nil
}, 1, 1)

var make3 = hint.NewStaticHint(func(curveID ecc.ID, inputs []*big.Int, result []*big.Int) error {
	result[0].SetUint64(3)
	return nil
}, 0, 1)
