package test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

type hintCircuit struct {
	A, B frontend.Variable
}

func (circuit *hintCircuit) Define(curveID ecc.ID, api frontend.API) error {
	a3b := api.NewHint(hint.IthBit, circuit.A, 3)
	a25b := api.NewHint(hint.IthBit, circuit.A, 25)
	aisZero := api.NewHint(hint.IsZero, circuit.A)
	bisZero := api.NewHint(hint.IsZero, circuit.B)

	api.AssertIsEqual(aisZero, 0)
	api.AssertIsEqual(bisZero, 1)
	api.AssertIsEqual(a3b, 1)
	api.AssertIsEqual(a25b, 0)

	return nil
}

func TestBuiltinHints(t *testing.T) {
	for _, curve := range ecc.Implemented() {
		if err := IsSolved(&hintCircuit{}, &hintCircuit{
			A: (0b1000),
			B: (0),
		}, curve); err != nil {
			t.Fatal(err)
		}

		if err := IsSolved(&hintCircuit{}, &hintCircuit{
			A: (0b10),
			B: (1),
		}, curve); err == nil {
			t.Fatal("witness shouldn't solve circuit")
		}
	}

}
