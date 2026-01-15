package smt

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// CompileAndExport compiles a circuit to SCS and exports it to the specified format.
type ExportFormat int

const (
	FormatCpp ExportFormat = iota
	FormatSMTLIB2
)

// CompileOptions configures circuit compilation for SMT export.
type CompileOptions struct {
	// Curve specifies the elliptic curve (default: BN254)
	Curve ecc.ID
	// Format specifies the export format
	Format ExportFormat
	// TestName is used in generated C++ code
	TestName string
	// Config for export
	Config ExportConfig
}

// DefaultCompileOptions returns default compilation options.
func DefaultCompileOptions() CompileOptions {
	return CompileOptions{
		Curve:    ecc.BN254,
		Format:   FormatCpp,
		TestName: "Circuit",
		Config:   DefaultConfig(),
	}
}

// CompileResult contains the result of compiling a circuit for SMT export.
type CompileResult struct {
	// The compiled constraint system
	ConstraintSystem constraint.ConstraintSystem
	// Extracted system data
	Extracted *ExtractedSystem
	// Debug information with source locations
	DebugInfo *ExtractedDebugInfo
	// Generated code/formulas as string
	Output string
}

// CompileCircuit compiles a gnark circuit and extracts SMT data.
// This is the main entry point for testing circuit snippets with SMT solvers.
func CompileCircuit(circuit frontend.Circuit, opts CompileOptions) (*CompileResult, error) {
	// Compile the circuit to SCS
	ccs, err := frontend.Compile(opts.Curve.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Type assert to get the concrete SCS type
	var exporter ConstraintExporter
	switch opts.Curve {
	case ecc.BN254:
		scs, ok := ccs.(*cs_bn254.SparseR1CS)
		if !ok {
			return nil, fmt.Errorf("expected *cs_bn254.SparseR1CS, got %T", ccs)
		}
		exporter = scs
	default:
		return nil, fmt.Errorf("unsupported curve: %s", opts.Curve.String())
	}

	// Extract the constraint system
	extracted := Extract(exporter)

	// Extract debug info if available
	var debugInfo *ExtractedDebugInfo
	if debugExp, ok := exporter.(DebugExporter); ok {
		debugInfo = ExtractDebugInfo(debugExp)
	}

	// Generate output based on format
	var buf bytes.Buffer
	switch opts.Format {
	case FormatCpp:
		err = ExportCVC5Cpp(&buf, exporter, opts.Config, opts.TestName)
	case FormatSMTLIB2:
		err = ExportSMTLIB2(&buf, exporter, opts.Config)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to export: %w", err)
	}

	return &CompileResult{
		ConstraintSystem: ccs,
		Extracted:        extracted,
		DebugInfo:        debugInfo,
		Output:           buf.String(),
	}, nil
}

// WriteToFile writes the compiled SMT output to a file.
func (r *CompileResult) WriteToFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return os.WriteFile(path, []byte(r.Output), 0644)
}

// ConstraintStrings returns human-readable strings for all constraints.
func (r *CompileResult) ConstraintStrings() []string {
	result := make([]string, len(r.Extracted.Constraints))
	for i, c := range r.Extracted.Constraints {
		result[i] = c.String
	}
	return result
}

// PrintConstraints prints all constraints to stdout.
func (r *CompileResult) PrintConstraints() {
	fmt.Printf("Constraints (%d total):\n", len(r.Extracted.Constraints))
	for i, c := range r.Extracted.Constraints {
		fmt.Printf("  [%d] %s\n", i, c.String)
	}
}

// PrintSummary prints a summary of the constraint system.
func (r *CompileResult) PrintSummary() {
	ext := r.Extracted
	fmt.Printf("Field: %s\n", ext.Field.String())
	fmt.Printf("Variables: %d public, %d secret, %d internal\n",
		ext.NbPublic, ext.NbSecret, ext.NbInternal)
	fmt.Printf("Unique Coefficients: %d\n", len(ext.Coefficients))
	fmt.Printf("Constraints: %d\n", len(ext.Constraints))
}

// Analyze runs soundness analysis on the compiled circuit.
func (r *CompileResult) Analyze(name string) *AnalysisResult {
	return StaticAnalysis(r.Extracted, name)
}

// GenerateReport creates a prettified report with source locations.
func (r *CompileResult) GenerateReport(name string) *Report {
	analysis := r.Analyze(name)
	return NewReport(r.Extracted, analysis, r.DebugInfo)
}

// WriteReport generates and writes a report in the specified format.
func (r *CompileResult) WriteReport(w io.Writer, name string, format ReportFormat) error {
	report := r.GenerateReport(name)
	return report.Write(w, format)
}

// WriteReportToFile generates and writes a report to a file.
// The format is determined by the file extension:
// - .html -> HTML format
// - .json -> JSON format
// - otherwise -> Terminal format (with colors)
func (r *CompileResult) WriteReportToFile(path, name string) error {
	var format ReportFormat
	ext := filepath.Ext(path)
	switch ext {
	case ".html":
		format = FormatHTML
	case ".json":
		format = FormatJSON
	default:
		format = FormatText
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	return r.WriteReport(f, name, format)
}

// VerifyWithPlonk attempts to verify the circuit with PlonK backend.
// This is useful for sanity checking before SMT verification.
func VerifyWithPlonk(circuit frontend.Circuit, assignment frontend.Circuit) error {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}

	pk, vk, err := plonk.Setup(ccs, nil, nil)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("witness failed: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("public witness failed: %w", err)
	}

	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		return fmt.Errorf("prove failed: %w", err)
	}

	return plonk.Verify(proof, vk, publicWitness)
}
