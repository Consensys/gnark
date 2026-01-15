package smt

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// SimpleAddCircuit is a minimal test circuit
type SimpleAddCircuit struct {
	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (c *SimpleAddCircuit) Define(api frontend.API) error {
	sum := api.Add(c.X, c.Y)
	api.AssertIsEqual(sum, c.Z)
	return nil
}

// TestExportSimpleCircuit tests basic constraint extraction
func TestExportSimpleCircuit(t *testing.T) {
	circuit := &SimpleAddCircuit{}

	result, err := CompileCircuit(circuit, DefaultCompileOptions())
	if err != nil {
		t.Fatalf("CompileCircuit failed: %v", err)
	}

	// Check basic structure
	// Z is the only public variable (constant wire is handled differently in SCS)
	if result.Extracted.NbPublic != 1 {
		t.Errorf("Expected 1 public var, got %d", result.Extracted.NbPublic)
	}

	if len(result.Extracted.Constraints) == 0 {
		t.Error("Expected at least one constraint")
	}

	// Print for debugging
	result.PrintSummary()
	result.PrintConstraints()
}

// TestExportSMTLIB2 tests SMT-LIB2 export
func TestExportSMTLIB2(t *testing.T) {
	circuit := &SimpleAddCircuit{}

	opts := DefaultCompileOptions()
	opts.Format = FormatSMTLIB2

	result, err := CompileCircuit(circuit, opts)
	if err != nil {
		t.Fatalf("CompileCircuit failed: %v", err)
	}

	// Check output contains expected elements
	if !strings.Contains(result.Output, "(set-logic QF_FF)") {
		t.Error("SMT-LIB2 output missing logic declaration")
	}

	if !strings.Contains(result.Output, "(check-sat)") {
		t.Error("SMT-LIB2 output missing check-sat")
	}

	t.Log("SMT-LIB2 output:\n", result.Output)
}

// TestExportCVC5Cpp tests C++ export
func TestExportCVC5Cpp(t *testing.T) {
	circuit := &SimpleAddCircuit{}

	opts := DefaultCompileOptions()
	opts.Format = FormatCpp
	opts.TestName = "SimpleAdd"

	result, err := CompileCircuit(circuit, opts)
	if err != nil {
		t.Fatalf("CompileCircuit failed: %v", err)
	}

	// Check output contains expected elements
	if !strings.Contains(result.Output, "#include <cvc5/cvc5.h>") {
		t.Error("C++ output missing cvc5 include")
	}

	if !strings.Contains(result.Output, "FIELD_MODULUS") {
		t.Error("C++ output missing field modulus")
	}

	if !strings.Contains(result.Output, "const vector<PlonkConstraint> CONSTRAINTS") {
		t.Error("C++ output missing constraints vector")
	}

	// Verify field modulus matches BN254
	bn254Modulus := ecc.BN254.ScalarField().String()
	if !strings.Contains(result.Output, bn254Modulus) {
		t.Error("C++ output has wrong field modulus")
	}
}

// RangeCheckCircuit tests range check constraints
type RangeCheckCircuit struct {
	X frontend.Variable
}

func (c *RangeCheckCircuit) Define(api frontend.API) error {
	rangeChecker := rangecheck.New(api)
	rangeChecker.Check(c.X, 8) // 8-bit range check
	return nil
}

// TestExportRangeCheck tests extraction of actual range check constraints
func TestExportRangeCheck(t *testing.T) {
	circuit := &RangeCheckCircuit{}

	opts := DefaultCompileOptions()
	opts.TestName = "RangeCheck8Bit"

	result, err := CompileCircuit(circuit, opts)
	if err != nil {
		t.Fatalf("CompileCircuit failed: %v", err)
	}

	t.Logf("Range check circuit compiled with %d constraints", len(result.Extracted.Constraints))
	result.PrintSummary()

	// The constraints should include the decomposition and range checks
	// Print first few constraints for inspection
	for i, c := range result.Extracted.Constraints {
		if i >= 10 {
			t.Logf("... and %d more constraints", len(result.Extracted.Constraints)-10)
			break
		}
		t.Logf("Constraint %d: %s", i, c.String)
	}
}

// MulCircuit tests multiplication constraint
type MulCircuit struct {
	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (c *MulCircuit) Define(api frontend.API) error {
	product := api.Mul(c.X, c.Y)
	api.AssertIsEqual(product, c.Z)
	return nil
}

// TestExportMulConstraint tests that multiplication generates correct PlonK constraint
func TestExportMulConstraint(t *testing.T) {
	circuit := &MulCircuit{}

	result, err := CompileCircuit(circuit, DefaultCompileOptions())
	if err != nil {
		t.Fatalf("CompileCircuit failed: %v", err)
	}

	// For multiplication, we expect a constraint with qM != 0
	foundMulConstraint := false
	for _, c := range result.Extracted.Constraints {
		if c.QM.Sign() != 0 {
			foundMulConstraint = true
			t.Logf("Found multiplication constraint: %s", c.String)
			break
		}
	}

	if !foundMulConstraint {
		t.Error("Expected to find a multiplication constraint (qM != 0)")
		for i, c := range result.Extracted.Constraints {
			t.Logf("Constraint %d: qL=%s qR=%s qO=%s qM=%s qC=%s",
				i, c.QL, c.QR, c.QO, c.QM, c.QC)
		}
	}
}

// TestConstraintCoefficients verifies coefficient extraction is correct
func TestConstraintCoefficients(t *testing.T) {
	circuit := &SimpleAddCircuit{}

	result, err := CompileCircuit(circuit, DefaultCompileOptions())
	if err != nil {
		t.Fatalf("CompileCircuit failed: %v", err)
	}

	// Check standard coefficients are present
	hasZero := false
	hasOne := false
	hasMinusOne := false

	for _, coeff := range result.Extracted.Coefficients {
		if coeff.Cmp(big.NewInt(0)) == 0 {
			hasZero = true
		}
		if coeff.Cmp(big.NewInt(1)) == 0 {
			hasOne = true
		}
		// -1 in field arithmetic
		minusOne := new(big.Int).Sub(result.Extracted.Field, big.NewInt(1))
		if coeff.Cmp(minusOne) == 0 {
			hasMinusOne = true
		}
	}

	if !hasZero {
		t.Error("Missing zero coefficient")
	}
	if !hasOne {
		t.Error("Missing one coefficient")
	}
	if !hasMinusOne {
		t.Error("Missing minus one coefficient")
	}
}

// TestOutputNotEmpty verifies compiled output is valid
func TestOutputNotEmpty(t *testing.T) {
	circuit := &SimpleAddCircuit{}

	opts := DefaultCompileOptions()
	result, err := CompileCircuit(circuit, opts)
	if err != nil {
		t.Fatalf("CompileCircuit failed: %v", err)
	}

	// Verify the output is non-empty
	if len(result.Output) == 0 {
		t.Error("Output should not be empty")
	}

	// Verify constraint strings are available
	strs := result.ConstraintStrings()
	if len(strs) == 0 {
		t.Error("ConstraintStrings should not be empty")
	}
}

// BenchmarkCompileAndExtract benchmarks the constraint extraction
func BenchmarkCompileAndExtract(b *testing.B) {
	circuit := &SimpleAddCircuit{}
	opts := DefaultCompileOptions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CompileCircuit(circuit, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}
