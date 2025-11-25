package print_constraints

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit defines a simple cubic equation circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
//
//	x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

// Example_printR1CS demonstrates how to print constraints from an R1CS constraint system.
//
// This example shows how to:
//  1. Compile a circuit using frontend.Compile with [r1cs.NewBuilder]
//  2. Assert that the compiled constraint system has GetR1Cs() method
//  3. Retrieve constraints using GetR1Cs()
//  4. Print each constraint using String() method with the constraint system as [constraint.Resolver]
func Example_printR1CS() {
	// Compile the circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &CubicCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to compile circuit: %v\n", err)
		return
	}

	// Assert that the constraint system has the `R1Cs()` method. This allows us
	// to get the R1CS constraints, but without needing to assert to a specific
	// curve implementation.

	// Type assert to get access to R1CS-specific methods
	r1csSystem, ok := ccs.(interface{ GetR1Cs() []constraint.R1C })
	if !ok {
		fmt.Fprintf(os.Stderr, "constraint system is not an R1CS\n")
		return
	}

	// Get all constraints
	constraints := r1csSystem.GetR1Cs()

	// Print constraint system statistics
	fmt.Printf("Constraint System Type: R1CS\n")
	fmt.Printf("Number of constraints: %d\n", len(constraints))
	fmt.Printf("Number of public variables: %d\n", ccs.GetNbPublicVariables())
	fmt.Printf("Number of secret variables: %d\n", ccs.GetNbSecretVariables())
	fmt.Printf("Number of internal variables: %d\n", ccs.GetNbInternalVariables())
	fmt.Println()

	// Print each constraint
	fmt.Println("Constraints:")
	fmt.Println("-----------")
	for i, r1c := range constraints {
		// The String() method requires a Resolver (the constraint system implements this)
		// This formats the constraint as "L ⋅ R == O"
		fmt.Printf("Constraint %d: %s\n", i, r1c.String(ccs))
	}

	// Output:
	// Constraint System Type: R1CS
	// Number of constraints: 3
	// Number of public variables: 2
	// Number of secret variables: 1
	// Number of internal variables: 2
	//
	// Constraints:
	// -----------
	// Constraint 0: x ⋅ x == v0
	// Constraint 1: v0 ⋅ x == v1
	// Constraint 2: 1 ⋅ Y == 5 + x + v1
}
