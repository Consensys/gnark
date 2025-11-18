// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package print_constraints

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// Example demonstrates how to print constraints from an R1CS constraint system.
//
// This example shows how to:
//  1. Compile a circuit using frontend.Compile with r1cs.NewBuilder
//  2. Type assert the compiled constraint system to cs_bn254.R1CS
//  3. Retrieve constraints using GetR1Cs()
//  4. Print each constraint using String() method with the constraint system as Resolver
func Example() {
	// Compile the circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &CubicCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to compile circuit: %v\n", err)
		return
	}

	// Type assert to get access to R1CS-specific methods
	r1csSystem, ok := ccs.(*cs_bn254.R1CS)
	if !ok {
		fmt.Fprintf(os.Stderr, "constraint system is not an R1CS\n")
		return
	}

	// Get all constraints
	constraints := r1csSystem.GetR1Cs()

	// Print constraint system statistics
	fmt.Printf("Constraint System Type: R1CS\n")
	fmt.Printf("Number of constraints: %d\n", len(constraints))
	fmt.Printf("Number of public variables: %d\n", r1csSystem.GetNbPublicVariables())
	fmt.Printf("Number of secret variables: %d\n", r1csSystem.GetNbSecretVariables())
	fmt.Printf("Number of internal variables: %d\n", r1csSystem.GetNbInternalVariables())
	fmt.Println()

	// Print each constraint
	fmt.Println("Constraints:")
	fmt.Println("-----------")
	for i, r1c := range constraints {
		// The String() method requires a Resolver (the constraint system implements this)
		// This formats the constraint as "L ⋅ R == O"
		fmt.Printf("Constraint %d: %s\n", i, r1c.String(r1csSystem))
	}

}

// ExampleSparseR1CS demonstrates how to print constraints from a SparseR1CS constraint system.
//
// This example shows how to:
//  1. Compile a circuit using frontend.Compile with scs.NewBuilder (PLONK/SparseR1CS)
//  2. Type assert the compiled constraint system to cs_bn254.SparseR1CS
//  3. Retrieve constraints using GetSparseR1Cs()
//  4. Print each constraint using String() method with the constraint system as Resolver
func ExampleSparseR1CS() {
	// Compile the circuit using SparseR1CS (PLONK) builder
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &CubicCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to compile circuit: %v\n", err)
		return
	}

	// Type assert to get access to SparseR1CS-specific methods
	scsSystem, ok := ccs.(*cs_bn254.SparseR1CS)
	if !ok {
		fmt.Fprintf(os.Stderr, "constraint system is not a SparseR1CS\n")
		return
	}

	// Get all constraints
	constraints := scsSystem.GetSparseR1Cs()

	// Print constraint system statistics
	fmt.Printf("Constraint System Type: SparseR1CS (PLONK)\n")
	fmt.Printf("Number of constraints: %d\n", len(constraints))
	fmt.Printf("Number of public variables: %d\n", scsSystem.GetNbPublicVariables())
	fmt.Printf("Number of secret variables: %d\n", scsSystem.GetNbSecretVariables())
	fmt.Printf("Number of internal variables: %d\n", scsSystem.GetNbInternalVariables())
	fmt.Println()

	// Print each constraint
	fmt.Println("Constraints:")
	fmt.Println("-----------")
	for i, sparseR1c := range constraints {
		// The String() method requires a Resolver (the constraint system implements this)
		// This formats the constraint as "qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0"
		fmt.Printf("Constraint %d: %s\n", i, sparseR1c.String(scsSystem))
	}

}
