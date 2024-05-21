package test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

type hintCircuit struct {
	A, B frontend.Variable
}

func (circuit *hintCircuit) Define(api frontend.API) error {
	res, err := api.Compiler().NewHint(bits.GetHints()[0], 1, circuit.A, 3)
	if err != nil {
		return fmt.Errorf("IthBit circuitA 3: %w", err)
	}
	a3b := res[0]
	res, err = api.Compiler().NewHint(bits.GetHints()[0], 1, circuit.A, 25)
	if err != nil {
		return fmt.Errorf("IthBit circuitA 25: %w", err)
	}
	a25b := res[0]

	res, err = api.Compiler().NewHint(solver.InvZeroHint, 1, circuit.A)
	if err != nil {
		return fmt.Errorf("IsZero CircuitA: %w", err)
	}
	aInvZero := res[0]

	res, err = api.Compiler().NewHint(solver.InvZeroHint, 1, circuit.B)
	if err != nil {
		return fmt.Errorf("IsZero, CircuitB")
	}
	bInvZero := res[0]

	// good witness
	expectedA := big.NewInt(8)
	expectedA.ModInverse(expectedA, api.Compiler().Field())

	api.AssertIsEqual(aInvZero, expectedA)
	api.AssertIsEqual(bInvZero, 0) // b == 0, invZero(b) == 0
	api.AssertIsEqual(a3b, 1)
	api.AssertIsEqual(a25b, 0)

	return nil
}

func TestBuiltinHints(t *testing.T) {
	for _, curve := range gnark.Curves() {
		if err := IsSolved(&hintCircuit{}, &hintCircuit{
			A: (0b1000),
			B: (0),
		}, curve.ScalarField()); err != nil {
			t.Fatal(err)
		}

		if err := IsSolved(&hintCircuit{}, &hintCircuit{
			A: (0b10),
			B: (1),
		}, curve.ScalarField()); err == nil {
			t.Fatal("witness shouldn't solve circuit")
		}
	}

}

var isDeferCalled bool

type EmptyCircuit struct {
	X frontend.Variable
}

func (c *EmptyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 0)
	api.Compiler().Defer(func(api frontend.API) error {
		isDeferCalled = true
		return nil
	})
	return nil
}

func TestPreCompileHook(t *testing.T) {
	c := &EmptyCircuit{}
	w := &EmptyCircuit{
		X: 0,
	}
	isDeferCalled = false
	err := IsSolved(c, w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if !isDeferCalled {
		t.Error("callback not called")
	}
}
