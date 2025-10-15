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

// testCircuit is a simple circuit for testing missing assignment
type testCircuit struct {
	A frontend.Variable
	B frontend.Variable
}

// Define implements the frontend.Circuit interface
func (c *testCircuit) Define(api frontend.API) error {
	// Simple constraint: A + B = 10
	api.AssertIsEqual(api.Add(c.A, c.B), 10)
	return nil
}

// TestMissingAssignment tests the error handling when a variable is not assigned (nil)
func TestMissingAssignment(t *testing.T) {
	circuit := &testCircuit{}

	// Create a witness where one variable is nil (not assigned)
	witness := &testCircuit{
		A: 5,   // A is assigned
		B: nil, // B is not assigned - this should trigger the error
	}

	// Test that IsSolved panics when a variable is missing assignment
	// We need to catch the panic since it happens in copyWitness before the defer in IsSolved
	var panicMsg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicMsg = fmt.Sprintf("%v", r)
			}
		}()
		IsSolved(circuit, witness, ecc.BN254.ScalarField())
	}()

	// Check that we got a panic with the expected message
	if panicMsg == "" {
		t.Fatal("expected panic for missing assignment, but got none")
	}

	// Check that the panic message contains the expected text
	expectedErrorMsg := "missing assignment"
	if !contains(panicMsg, expectedErrorMsg) {
		t.Fatalf("expected panic message to contain '%s', but got: %s", expectedErrorMsg, panicMsg)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
