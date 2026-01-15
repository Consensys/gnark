//go:build ignore

// This file generates C++ verification code from actual gnark constraints.
// Run with: go run generate.go
//
// The generated code uses cvc5 to verify the actual PlonK constraints
// produced by the gnark compiler, not manually written approximations.

package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smt"
	"github.com/consensys/gnark/std/rangecheck"
)

// RangeCheckCircuit8 tests 8-bit range checks
type RangeCheckCircuit8 struct {
	X frontend.Variable
}

func (c *RangeCheckCircuit8) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	rc.Check(c.X, 8)
	return nil
}

// RangeCheckCircuit16 tests 16-bit range checks
type RangeCheckCircuit16 struct {
	X frontend.Variable
}

func (c *RangeCheckCircuit16) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	rc.Check(c.X, 16)
	return nil
}

// MultiRangeCheckCircuit tests multiple range checks
type MultiRangeCheckCircuit struct {
	A, B, C frontend.Variable
}

func (c *MultiRangeCheckCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	rc.Check(c.A, 8)
	rc.Check(c.B, 16)
	rc.Check(c.C, 32)
	return nil
}

// DecompositionCircuit tests the decomposition used in range checks
type DecompositionCircuit struct {
	Value  frontend.Variable `gnark:",public"`
	Limb0  frontend.Variable
	Limb1  frontend.Variable
	Limb2  frontend.Variable
	Limb3  frontend.Variable
}

func (c *DecompositionCircuit) Define(api frontend.API) error {
	// Manual decomposition: value = limb0 + limb1*256 + limb2*65536 + limb3*16777216
	sum := api.Add(
		c.Limb0,
		api.Mul(c.Limb1, 256),
		api.Mul(c.Limb2, 65536),
		api.Mul(c.Limb3, 16777216),
	)
	api.AssertIsEqual(sum, c.Value)

	// Range check each limb to 8 bits
	rc := rangecheck.New(api)
	rc.Check(c.Limb0, 8)
	rc.Check(c.Limb1, 8)
	rc.Check(c.Limb2, 8)
	rc.Check(c.Limb3, 8)

	return nil
}

func main() {
	fmt.Println("Generating SMT verification code from gnark constraints...")
	fmt.Println()

	// Generate code for 8-bit range check
	generateCircuit(&RangeCheckCircuit8{}, "rangecheck_8bit", "RangeCheck8Bit")

	// Generate code for 16-bit range check
	generateCircuit(&RangeCheckCircuit16{}, "rangecheck_16bit", "RangeCheck16Bit")

	// Generate code for multiple range checks
	generateCircuit(&MultiRangeCheckCircuit{}, "rangecheck_multi", "MultiRangeCheck")

	// Generate code for decomposition circuit
	generateCircuit(&DecompositionCircuit{}, "decomposition", "Decomposition")

	fmt.Println()
	fmt.Println("Generation complete!")
	fmt.Println("Compile the generated files with:")
	fmt.Println("  g++ -std=c++17 -o verify_rangecheck_8bit verify_rangecheck_8bit.cpp -lcvc5")
}

func generateCircuit(circuit frontend.Circuit, filename, testName string) {
	opts := smt.DefaultCompileOptions()
	opts.TestName = testName
	opts.Config.IncludeComments = true

	result, err := smt.CompileCircuit(circuit, opts)
	if err != nil {
		fmt.Printf("Error compiling %s: %v\n", filename, err)
		return
	}

	// Print summary
	fmt.Printf("=== %s ===\n", testName)
	result.PrintSummary()
	fmt.Printf("First 5 constraints:\n")
	for i, c := range result.Extracted.Constraints {
		if i >= 5 {
			fmt.Printf("  ... and %d more\n", len(result.Extracted.Constraints)-5)
			break
		}
		fmt.Printf("  [%d] %s\n", i, c.String)
	}
	fmt.Println()

	// Write C++ file
	cppFile := fmt.Sprintf("verify_%s.cpp", filename)
	err = result.WriteToFile(cppFile)
	if err != nil {
		fmt.Printf("Error writing %s: %v\n", cppFile, err)
		return
	}
	fmt.Printf("Generated: %s\n", cppFile)

	// Also generate SMT-LIB2 format
	opts.Format = smt.FormatSMTLIB2
	result, err = smt.CompileCircuit(circuit, opts)
	if err != nil {
		fmt.Printf("Error compiling SMT-LIB2 for %s: %v\n", filename, err)
		return
	}

	smtFile := fmt.Sprintf("verify_%s.smt2", filename)
	err = result.WriteToFile(smtFile)
	if err != nil {
		fmt.Printf("Error writing %s: %v\n", smtFile, err)
		return
	}
	fmt.Printf("Generated: %s\n", smtFile)
}
