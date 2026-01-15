//go:build ignore

// This file generates soundness analysis code for rangecheck constraints.
// Run with: go run generate_analysis.go
//
// It creates:
// 1. Pretty terminal output with colors
// 2. HTML reports for viewing in browser
// 3. C++ programs for runtime SMT verification

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smt"
	"github.com/consensys/gnark/std/rangecheck"
)

// RangeCheck8BitCircuit - 8-bit range check
type RangeCheck8BitCircuit struct {
	X frontend.Variable
}

func (c *RangeCheck8BitCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	rc.Check(c.X, 8)
	return nil
}

// BrokenRangeCheckCircuit - intentionally under-constrained for testing
// This circuit is BROKEN - it doesn't properly range check
type BrokenRangeCheckCircuit struct {
	X frontend.Variable
}

func (c *BrokenRangeCheckCircuit) Define(api frontend.API) error {
	// Intentionally weak: only decompose but don't range check limbs
	// This should be detected as under-constrained
	api.ToBinary(c.X, 8) // Creates limbs but without proper checks in some backends
	return nil
}

// DecompositionOnlyCircuit - only recomposition, no range checks
type DecompositionOnlyCircuit struct {
	X     frontend.Variable `gnark:",public"`
	Limb0 frontend.Variable
	Limb1 frontend.Variable
}

func (c *DecompositionOnlyCircuit) Define(api frontend.API) error {
	// Only assert recomposition without range checks
	// This is UNDER-CONSTRAINED: limbs can be anything that sums to X
	recomp := api.Add(c.Limb0, api.Mul(c.Limb1, 256))
	api.AssertIsEqual(recomp, c.X)
	return nil
}

// ProperDecompositionCircuit - recomposition WITH range checks
type ProperDecompositionCircuit struct {
	X     frontend.Variable `gnark:",public"`
	Limb0 frontend.Variable
	Limb1 frontend.Variable
}

func (c *ProperDecompositionCircuit) Define(api frontend.API) error {
	// Assert recomposition
	recomp := api.Add(c.Limb0, api.Mul(c.Limb1, 256))
	api.AssertIsEqual(recomp, c.X)

	// Range check limbs
	rc := rangecheck.New(api)
	rc.Check(c.Limb0, 8)
	rc.Check(c.Limb1, 8)
	return nil
}

var (
	outputFormat = flag.String("format", "terminal", "Output format: terminal, html, json, cpp")
	outputDir    = flag.String("out", ".", "Output directory for generated files")
)

func main() {
	flag.Parse()

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║       SMT Soundness Analysis - Rangecheck Package             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Generate analysis for proper range check (should pass all tests)
	analyzeCircuit(&RangeCheck8BitCircuit{}, "rangecheck_8bit", "RangeCheck8Bit")

	// Generate analysis for decomposition without range checks (should detect issues)
	analyzeCircuit(&DecompositionOnlyCircuit{}, "decomposition_no_range", "DecompNoRange")

	// Generate analysis for proper decomposition with range checks
	analyzeCircuit(&ProperDecompositionCircuit{}, "decomposition_with_range", "DecompWithRange")

	fmt.Println()
	fmt.Println("Analysis complete!")
	if *outputFormat == "cpp" {
		fmt.Println("Compile C++ with: g++ -std=c++17 -o <name> <name>.cpp -lcvc5")
	}
}

func analyzeCircuit(circuit frontend.Circuit, basename, testName string) {
	opts := smt.DefaultCompileOptions()
	opts.TestName = testName

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
