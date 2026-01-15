package smt

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
)

// SimpleECAddCircuit wraps the ALT_BN128_ADD precompile (0x06) - a simpler circuit
type SimpleECAddCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	X1       sw_emulated.AffinePoint[emulated.BN254Fp]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *SimpleECAddCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := evmprecompiles.ECAdd(api, &c.X0, &c.X1)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

// SimpleECMulCircuit wraps the ALT_BN128_MUL precompile (0x07)
type SimpleECMulCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	U        emulated.Element[emulated.BN254Fr]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *SimpleECMulCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := evmprecompiles.ECMul(api, &c.X0, &c.U)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

// TestAnalyzeECAdd analyzes just the ECAdd circuit (smaller than ECRecover)
func TestAnalyzeECAdd(t *testing.T) {
	circuit := &SimpleECAddCircuit{}

	opts := DefaultCompileOptions()
	opts.TestName = "ECAdd_BN254"
	opts.WithProfiling = false // Disable profiling to speed up

	t.Log("Compiling ECAdd circuit...")
	result, err := CompileCircuit(circuit, opts)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	t.Log("Circuit compiled successfully!")
	t.Logf("  Constraints: %d", len(result.Extracted.Constraints))
	t.Logf("  Variables: %d public, %d secret, %d internal",
		result.Extracted.NbPublic, result.Extracted.NbSecret, result.Extracted.NbInternal)

	// Only run full analysis if circuit is small enough
	if len(result.Extracted.Constraints) > 50000 {
		t.Log("Circuit too large for full analysis, generating basic report...")
	} else {
		t.Log("Running static analysis...")
		analysis := result.Analyze("ECAdd_BN254")
		t.Logf("  Issues found: %d", len(analysis.Issues))
		for _, issue := range analysis.Issues {
			t.Logf("    [%s] %s: %s", issue.Severity, issue.Type, issue.Description)
		}
	}

	// Print constraint patterns (fast operation)
	t.Log("Constraint patterns:")
	patterns := AnalyzeConstraintPatterns(result.Extracted)
	for _, p := range patterns {
		t.Logf("  %s", p)
	}

	// Write basic HTML report
	outputDir := filepath.Join(os.TempDir(), "gnark-smt-reports")
	os.MkdirAll(outputDir, 0755)
	reportPath := filepath.Join(outputDir, "ECAdd_BN254.html")

	// Create report with analysis results
	t.Log("Generating HTML report...")
	analysis := result.Analyze("ECAdd_BN254")
	report := NewReport(result.Extracted, analysis, nil)
	report.Patterns = patterns

	f, err := os.Create(reportPath)
	if err != nil {
		t.Fatalf("Failed to create report file: %v", err)
	}
	defer f.Close()

	if err := report.Write(f, FormatHTML); err != nil {
		t.Fatalf("Failed to write report: %v", err)
	}
	t.Logf("Report written to: %s", reportPath)
}

// TestAnalyzeMultipleSimple analyzes multiple simpler circuits with size limits
func TestAnalyzeMultipleSimple(t *testing.T) {
	type circuitInfo struct {
		name        string
		circuit     frontend.Circuit
		description string
	}

	circuits := []circuitInfo{
		{
			name:        "ECAdd_BN254",
			circuit:     &SimpleECAddCircuit{},
			description: "BN254 elliptic curve point addition (precompile 0x06)",
		},
		{
			name:        "ECMul_BN254",
			circuit:     &SimpleECMulCircuit{},
			description: "BN254 elliptic curve scalar multiplication (precompile 0x07)",
		},
	}

	outputDir := filepath.Join(os.TempDir(), "gnark-smt-reports")
	os.MkdirAll(outputDir, 0755)
	t.Logf("Output directory: %s", outputDir)

	var summaries []string

	for _, ci := range circuits {
		t.Run(ci.name, func(t *testing.T) {
			t.Logf("Analyzing %s: %s", ci.name, ci.description)

			opts := DefaultCompileOptions()
			opts.TestName = ci.name
			opts.WithProfiling = false

			result, err := CompileCircuit(ci.circuit, opts)
			if err != nil {
				t.Logf("WARNING: Failed to compile %s: %v", ci.name, err)
				summaries = append(summaries, fmt.Sprintf("%s: COMPILE ERROR - %v", ci.name, err))
				return
			}

			summary := fmt.Sprintf("%s: %d constraints, %d public, %d secret, %d internal vars",
				ci.name,
				len(result.Extracted.Constraints),
				result.Extracted.NbPublic,
				result.Extracted.NbSecret,
				result.Extracted.NbInternal)

			// Constraint pattern analysis (fast)
			patterns := AnalyzeConstraintPatterns(result.Extracted)

			// Only do full analysis for smaller circuits
			var issues []Issue
			if len(result.Extracted.Constraints) <= 10000 {
				analysis := result.Analyze(ci.name)
				issues = analysis.Issues
				if len(issues) > 0 {
					criticalCount := 0
					warningCount := 0
					for _, issue := range issues {
						if issue.Severity == "critical" {
							criticalCount++
						} else if issue.Severity == "warning" {
							warningCount++
						}
					}
					summary += fmt.Sprintf(" | Issues: %d critical, %d warnings", criticalCount, warningCount)
				} else {
					summary += " | No issues found"
				}
			} else {
				summary += " | (skipped full analysis - too large)"
			}

			summaries = append(summaries, summary)

			// Generate HTML report
			report := &Report{
				CircuitName:   ci.name,
				Field:         result.Extracted.Field.String()[:20] + "...",
				NbPublic:      result.Extracted.NbPublic,
				NbSecret:      result.Extracted.NbSecret,
				NbInternal:    result.Extracted.NbInternal,
				NbConstraints: len(result.Extracted.Constraints),
				Patterns:      patterns,
				Constraints:   result.Extracted.Constraints,
			}

			// Convert issues
			for _, issue := range issues {
				report.Issues = append(report.Issues, ReportIssue{
					Severity:    issue.Severity,
					Type:        issue.Type,
					Description: issue.Description,
					Details:     issue.Details,
				})
			}

			reportPath := filepath.Join(outputDir, fmt.Sprintf("%s_report.html", ci.name))
			f, err := os.Create(reportPath)
			if err != nil {
				t.Logf("Failed to create report: %v", err)
				return
			}
			defer f.Close()

			if err := report.Write(f, FormatHTML); err != nil {
				t.Logf("Failed to write report: %v", err)
			} else {
				t.Logf("Report written to: %s", reportPath)
			}

			// Log details
			t.Logf("  Constraints: %d", len(result.Extracted.Constraints))
			t.Logf("  Variables: %d public, %d secret, %d internal",
				result.Extracted.NbPublic, result.Extracted.NbSecret, result.Extracted.NbInternal)
			for _, p := range patterns {
				t.Logf("  Pattern: %s", p)
			}
		})
	}

	// Print summary
	t.Log("\n========================================")
	t.Log("ANALYSIS SUMMARY")
	t.Log("========================================")
	for _, s := range summaries {
		t.Log(s)
	}
	t.Logf("\nReports written to: %s", outputDir)
}
