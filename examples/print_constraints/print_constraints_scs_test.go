package print_constraints

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// Example_printSparseR1CS demonstrates how to print constraints from a SparseR1CS constraint system.
//
// This example shows how to:
//  1. Compile a circuit using frontend.Compile with [scs.NewBuilder] (PLONK/SparseR1CS)
//  2. Assert that the compiled constraint system has GetSparseR1Cs() method
//  3. Retrieve constraints using GetSparseR1Cs()
//  4. Print each constraint using String() method with the constraint system as [constraint.Resolver]
func Example_printSparseR1CS() {
	// Compile the circuit using SparseR1CS (PLONK) builder
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &CubicCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to compile circuit: %v\n", err)
		return
	}

	// Type assert to get access to SparseR1CS-specific methods
	scsSystem, ok := ccs.(interface{ GetSparseR1Cs() []constraint.SparseR1C })
	if !ok {
		fmt.Fprintf(os.Stderr, "constraint system is not a SparseR1CS\n")
		return
	}

	// Get all constraints
	constraints := scsSystem.GetSparseR1Cs()

	// Print constraint system statistics
	fmt.Printf("Constraint System Type: SparseR1CS (PLONK)\n")
	fmt.Printf("Number of constraints: %d\n", len(constraints))
	fmt.Printf("Number of public variables: %d\n", ccs.GetNbPublicVariables())
	fmt.Printf("Number of secret variables: %d\n", ccs.GetNbSecretVariables())
	fmt.Printf("Number of internal variables: %d\n", ccs.GetNbInternalVariables())
	fmt.Println()

	// Print each constraint
	fmt.Println("Constraints:")
	fmt.Println("-----------")
	for i, sparseR1c := range constraints {
		// The String() method requires a Resolver (the constraint system implements this)
		// This formats the constraint as "qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0"
		fmt.Printf("Constraint %d: %s\n", i, sparseR1c.String(ccs))
	}

	// Output:
	// Constraint System Type: SparseR1CS (PLONK)
	// Number of constraints: 4
	// Number of public variables: 1
	// Number of secret variables: 1
	// Number of internal variables: 3
	//
	// Constraints:
	// -----------
	// Constraint 0: 0 + 0 + -1⋅v0 + 1⋅(x×x) + 0 == 0
	// Constraint 1: 0 + 0 + -1⋅v1 + 1⋅(v0×x) + 0 == 0
	// Constraint 2: x + v1 + -1⋅v2 + 5 == 0
	// Constraint 3: Y + -1⋅v2 + 0 + 0 == 0
}
