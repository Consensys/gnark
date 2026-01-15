//go:build ignore

// This file generates soundness analysis code for emulated math constraints.
// Run with: go run generate_analysis.go
//
// It creates analysis for various emulated field operations to detect:
// 1. Under-constrained variables (can take multiple values)
// 2. Missing range checks on limbs
// 3. Improperly constrained hint outputs

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smt"
	"github.com/consensys/gnark/std/math/emulated"
)

// Emulated field parameters for secp256k1 in BN254
type Secp256k1Fp = emulated.Secp256k1Fp

// EmulatedAddCircuit - tests addition
type EmulatedAddCircuit struct {
	A emulated.Element[Secp256k1Fp]
	B emulated.Element[Secp256k1Fp]
	C emulated.Element[Secp256k1Fp] `gnark:",public"` // C = A + B
}

func (c *EmulatedAddCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	sum := field.Add(&c.A, &c.B)
	field.AssertIsEqual(sum, &c.C)
	return nil
}

// EmulatedMulCircuit - tests multiplication
type EmulatedMulCircuit struct {
	A emulated.Element[Secp256k1Fp]
	B emulated.Element[Secp256k1Fp]
	C emulated.Element[Secp256k1Fp] `gnark:",public"` // C = A * B mod p
}

func (c *EmulatedMulCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	product := field.Mul(&c.A, &c.B)
	field.AssertIsEqual(product, &c.C)
	return nil
}

// EmulatedSubCircuit - tests subtraction
type EmulatedSubCircuit struct {
	A emulated.Element[Secp256k1Fp]
	B emulated.Element[Secp256k1Fp]
	C emulated.Element[Secp256k1Fp] `gnark:",public"` // C = A - B mod p
}

func (c *EmulatedSubCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	diff := field.Sub(&c.A, &c.B)
	field.AssertIsEqual(diff, &c.C)
	return nil
}

// EmulatedDivCircuit - tests division (uses hints)
type EmulatedDivCircuit struct {
	A emulated.Element[Secp256k1Fp]
	B emulated.Element[Secp256k1Fp]
	C emulated.Element[Secp256k1Fp] `gnark:",public"` // C = A / B mod p
}

func (c *EmulatedDivCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	quotient := field.Div(&c.A, &c.B)
	field.AssertIsEqual(quotient, &c.C)
	return nil
}

// EmulatedInverseCircuit - tests inverse (uses hints)
type EmulatedInverseCircuit struct {
	A emulated.Element[Secp256k1Fp]
	B emulated.Element[Secp256k1Fp] `gnark:",public"` // B = 1/A mod p
}

func (c *EmulatedInverseCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	inv := field.Inverse(&c.A)
	field.AssertIsEqual(inv, &c.B)
	return nil
}

// BrokenEmulatedAddCircuit - missing assertion (under-constrained)
// This circuit is BROKEN - it computes sum but doesn't constrain C
type BrokenEmulatedAddCircuit struct {
	A emulated.Element[Secp256k1Fp]
	B emulated.Element[Secp256k1Fp]
	C emulated.Element[Secp256k1Fp] `gnark:",public"` // Should be A + B but isn't constrained
}

func (c *BrokenEmulatedAddCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	// BUG: We compute sum but don't assert it equals C!
	_ = field.Add(&c.A, &c.B) // Result is computed but discarded
	// Missing: field.AssertIsEqual(sum, &c.C)
	return nil
}

var (
	outputFormat = flag.String("format", "terminal", "Output format: terminal, html, json, cpp")
	outputDir    = flag.String("out", ".", "Output directory for generated files")
)

func main() {
	flag.Parse()

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║       SMT Soundness Analysis - Emulated Math Package          ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Test various emulated operations
	analyzeCircuit(&EmulatedAddCircuit{}, "emulated_add", "EmulatedAdd")
	analyzeCircuit(&EmulatedMulCircuit{}, "emulated_mul", "EmulatedMul")
	analyzeCircuit(&EmulatedSubCircuit{}, "emulated_sub", "EmulatedSub")
	analyzeCircuit(&EmulatedDivCircuit{}, "emulated_div", "EmulatedDiv")
	analyzeCircuit(&EmulatedInverseCircuit{}, "emulated_inv", "EmulatedInv")

	// Test broken circuit (should detect under-constraint)
	analyzeCircuit(&BrokenEmulatedAddCircuit{}, "broken_emulated_add", "BrokenEmulatedAdd")

	fmt.Println()
	fmt.Println("Analysis complete!")
	if *outputFormat == "cpp" {
		fmt.Println("Compile C++ with: g++ -std=c++17 -o <name> <name>.cpp -lcvc5")
	}
}

func analyzeCircuit(circuit frontend.Circuit, basename, testName string) {
	opts := smt.DefaultCompileOptions()
	opts.TestName = testName
	opts.Curve = ecc.BN254

	result, err := smt.CompileCircuit(circuit, opts)
	if err != nil {
		fmt.Printf("Error compiling %s: %v\n", basename, err)
		return
	}

	switch *outputFormat {
	case "terminal":
		// Pretty terminal output with colors
		result.WriteReport(os.Stdout, testName, smt.FormatTerminal)

	case "html":
		// HTML report
		htmlFile := fmt.Sprintf("%s/%s_report.html", *outputDir, basename)
		err = result.WriteReportToFile(htmlFile, testName)
		if err != nil {
			fmt.Printf("Error writing HTML report: %v\n", err)
			return
		}
		fmt.Printf("Generated: %s\n", htmlFile)

	case "json":
		// JSON output
		jsonFile := fmt.Sprintf("%s/%s_report.json", *outputDir, basename)
		err = result.WriteReportToFile(jsonFile, testName)
		if err != nil {
			fmt.Printf("Error writing JSON report: %v\n", err)
			return
		}
		fmt.Printf("Generated: %s\n", jsonFile)

	case "cpp":
		// C++ code for cvc5
		var buf bytes.Buffer
		cfg := smt.DefaultAnalysisConfig()
		cfg.Verbose = true
		err = smt.ExportAnalysisCpp(&buf, result.Extracted, cfg, testName)
		if err != nil {
			fmt.Printf("Error generating C++ for %s: %v\n", basename, err)
			return
		}

		cppFile := fmt.Sprintf("%s/%s_analysis.cpp", *outputDir, basename)
		err = os.WriteFile(cppFile, buf.Bytes(), 0644)
		if err != nil {
			fmt.Printf("Error writing %s: %v\n", cppFile, err)
			return
		}
		fmt.Printf("Generated: %s\n", cppFile)

	default:
		// Default: plain text summary
		fmt.Printf("=== %s ===\n", testName)
		result.PrintSummary()
		analysis := smt.StaticAnalysis(result.Extracted, testName)
		analysis.Print(os.Stdout)
		fmt.Println()
	}
}
