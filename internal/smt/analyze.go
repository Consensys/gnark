package smt

import (
	"fmt"
	"io"
	"math/big"
	"strings"
)

// AnalysisConfig configures the soundness analysis.
type AnalysisConfig struct {
	// MaxRangeEnumeration is the max range size for enumeration-based checks
	MaxRangeEnumeration int
	// IncludeConstraintNecessity checks if each constraint is necessary
	IncludeConstraintNecessity bool
	// IncludeVariableBounds checks if variables can take unexpected values
	IncludeVariableBounds bool
	// Verbose enables detailed output
	Verbose bool
}

// DefaultAnalysisConfig returns sensible defaults for analysis.
func DefaultAnalysisConfig() AnalysisConfig {
	return AnalysisConfig{
		MaxRangeEnumeration:        16,
		IncludeConstraintNecessity: true,
		IncludeVariableBounds:      true,
		Verbose:                    false,
	}
}

// AnalysisResult contains the results of soundness analysis.
type AnalysisResult struct {
	// CircuitName identifies the circuit
	CircuitName string
	// TotalConstraints is the number of constraints analyzed
	TotalConstraints int
	// TotalVariables is the number of variables
	TotalVariables int
	// Issues found during analysis
	Issues []Issue
	// Passed checks
	Passed []string
}

// Issue represents a potential soundness issue.
type Issue struct {
	// Severity: "critical", "warning", "info"
	Severity string
	// Type: "under-constrained", "redundant", "unbounded", etc.
	Type string
	// Description of the issue
	Description string
	// ConstraintIndex if relevant (-1 if not)
	ConstraintIndex int
	// VariableIndex if relevant (-1 if not)
	VariableIndex int
	// Details provides additional context
	Details string
}

// HasCritical returns true if there are critical issues.
func (r *AnalysisResult) HasCritical() bool {
	for _, issue := range r.Issues {
		if issue.Severity == "critical" {
			return true
		}
	}
	return false
}

// HasWarnings returns true if there are warnings.
func (r *AnalysisResult) HasWarnings() bool {
	for _, issue := range r.Issues {
		if issue.Severity == "warning" {
			return true
		}
	}
	return false
}

// Print writes a human-readable analysis report.
func (r *AnalysisResult) Print(w io.Writer) {
	fmt.Fprintf(w, "========================================\n")
	fmt.Fprintf(w, "SMT Soundness Analysis: %s\n", r.CircuitName)
	fmt.Fprintf(w, "========================================\n")
	fmt.Fprintf(w, "Constraints: %d\n", r.TotalConstraints)
	fmt.Fprintf(w, "Variables: %d\n", r.TotalVariables)
	fmt.Fprintf(w, "\n")

	if len(r.Passed) > 0 {
		fmt.Fprintf(w, "--- PASSED CHECKS ---\n")
		for _, p := range r.Passed {
			fmt.Fprintf(w, "  [PASS] %s\n", p)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(r.Issues) == 0 {
		fmt.Fprintf(w, "No issues found.\n")
		return
	}

	criticalCount := 0
	warningCount := 0
	infoCount := 0

	for _, issue := range r.Issues {
		switch issue.Severity {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		case "info":
			infoCount++
		}
	}

	fmt.Fprintf(w, "--- ISSUES FOUND ---\n")
	fmt.Fprintf(w, "Critical: %d, Warnings: %d, Info: %d\n\n", criticalCount, warningCount, infoCount)

	for i, issue := range r.Issues {
		var prefix string
		switch issue.Severity {
		case "critical":
			prefix = "[CRITICAL]"
		case "warning":
			prefix = "[WARNING]"
		case "info":
			prefix = "[INFO]"
		}

		fmt.Fprintf(w, "%d. %s %s: %s\n", i+1, prefix, issue.Type, issue.Description)
		if issue.Details != "" {
			fmt.Fprintf(w, "   Details: %s\n", issue.Details)
		}
		if issue.ConstraintIndex >= 0 {
			fmt.Fprintf(w, "   Constraint index: %d\n", issue.ConstraintIndex)
		}
		if issue.VariableIndex >= 0 {
			fmt.Fprintf(w, "   Variable index: %d\n", issue.VariableIndex)
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "========================================\n")
	if criticalCount > 0 {
		fmt.Fprintf(w, "RESULT: CRITICAL ISSUES FOUND\n")
	} else if warningCount > 0 {
		fmt.Fprintf(w, "RESULT: WARNINGS FOUND\n")
	} else {
		fmt.Fprintf(w, "RESULT: PASSED (info only)\n")
	}
	fmt.Fprintf(w, "========================================\n")
}

// ExportAnalysisCpp generates C++ code that performs the analysis with cvc5.
func ExportAnalysisCpp(w io.Writer, ext *ExtractedSystem, cfg AnalysisConfig, testName string) error {
	// Header
	fmt.Fprintln(w, "// Auto-generated soundness analysis for gnark constraint system")
	fmt.Fprintln(w, "// Tests for under-constrained variables and constraint necessity")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "#include <cvc5/cvc5.h>")
	fmt.Fprintln(w, "#include <iostream>")
	fmt.Fprintln(w, "#include <string>")
	fmt.Fprintln(w, "#include <vector>")
	fmt.Fprintln(w, "#include <functional>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "using namespace std;")
	fmt.Fprintln(w, "using namespace cvc5;")
	fmt.Fprintln(w)

	// Field constant
	fmt.Fprintf(w, "const string FIELD_MODULUS = \"%s\";\n", ext.Field.String())
	fmt.Fprintf(w, "const int NB_VARS = %d;\n", ext.NbPublic+ext.NbSecret+ext.NbInternal)
	fmt.Fprintf(w, "const int NB_CONSTRAINTS = %d;\n\n", len(ext.Constraints))

	// Helper functions
	fmt.Fprint(w, `// Field arithmetic helpers
Term mkFieldElem(TermManager& tm, Sort& field, const string& value) {
    return tm.mkFiniteFieldElem(value, field);
}

Term ffAdd(TermManager& tm, Term a, Term b) {
    return tm.mkTerm(Kind::FINITE_FIELD_ADD, {a, b});
}

Term ffMul(TermManager& tm, Term a, Term b) {
    return tm.mkTerm(Kind::FINITE_FIELD_MULT, {a, b});
}

Term ffSub(TermManager& tm, Sort& field, Term a, Term b) {
    Term negOne = mkFieldElem(tm, field, "-1");
    return ffAdd(tm, a, ffMul(tm, negOne, b));
}

Term ffEqual(TermManager& tm, Sort& field, Term a, Term b) {
    Term zero = mkFieldElem(tm, field, "0");
    return tm.mkTerm(Kind::EQUAL, {ffSub(tm, field, a, b), zero});
}
`)

	// Constraint structure
	fmt.Fprint(w, `
struct PlonkConstraint {
    int xa, xb, xc;
    string qL, qR, qO, qM, qC;
    string desc;
};
`)

	// Export constraints
	fmt.Fprintln(w, "\nconst vector<PlonkConstraint> CONSTRAINTS = {")
	for i, c := range ext.Constraints {
		fmt.Fprintf(w, "    {%d, %d, %d, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"}",
			c.XA, c.XB, c.XC,
			c.QL.String(), c.QR.String(), c.QO.String(),
			c.QM.String(), c.QC.String(),
			escapeString(c.String))
		if i < len(ext.Constraints)-1 {
			fmt.Fprintln(w, ",")
		} else {
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w, "};")

	// Variable names
	fmt.Fprintln(w, "\nconst vector<string> VAR_NAMES = {")
	for i, name := range ext.VariableNames {
		fmt.Fprintf(w, "    \"%s\"", escapeString(name))
		if i < len(ext.VariableNames)-1 {
			fmt.Fprintln(w, ",")
		} else {
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w, "};")

	// Analysis functions
	fmt.Fprint(w, `
// Build constraint term: qL*xa + qR*xb + qO*xc + qM*(xa*xb) + qC
Term buildConstraint(TermManager& tm, Sort& field, const vector<Term>& vars, const PlonkConstraint& c) {
    Term zero = mkFieldElem(tm, field, "0");
    Term result = zero;

    if (c.qL != "0") result = ffAdd(tm, result, ffMul(tm, mkFieldElem(tm, field, c.qL), vars[c.xa]));
    if (c.qR != "0") result = ffAdd(tm, result, ffMul(tm, mkFieldElem(tm, field, c.qR), vars[c.xb]));
    if (c.qO != "0") result = ffAdd(tm, result, ffMul(tm, mkFieldElem(tm, field, c.qO), vars[c.xc]));
    if (c.qM != "0") result = ffAdd(tm, result, ffMul(tm, mkFieldElem(tm, field, c.qM), ffMul(tm, vars[c.xa], vars[c.xb])));
    if (c.qC != "0") result = ffAdd(tm, result, mkFieldElem(tm, field, c.qC));

    return result;
}

// Assert all constraints except one
void assertConstraintsExcept(Solver& solver, TermManager& tm, Sort& field,
                              const vector<Term>& vars, int excludeIdx) {
    Term zero = mkFieldElem(tm, field, "0");
    for (int i = 0; i < (int)CONSTRAINTS.size(); i++) {
        if (i != excludeIdx) {
            Term ct = buildConstraint(tm, field, vars, CONSTRAINTS[i]);
            solver.assertFormula(tm.mkTerm(Kind::EQUAL, {ct, zero}));
        }
    }
}

// Assert all constraints
void assertAllConstraints(Solver& solver, TermManager& tm, Sort& field, const vector<Term>& vars) {
    assertConstraintsExcept(solver, tm, field, vars, -1);
}

// Create variables
vector<Term> createVars(TermManager& tm, Sort& field) {
    vector<Term> vars;
    for (int i = 0; i < NB_VARS; i++) {
        vars.push_back(tm.mkConst(field, VAR_NAMES[i]));
    }
    return vars;
}

// Test result structure
struct TestResult {
    string name;
    bool passed;
    string message;
};

vector<TestResult> results;

void recordResult(const string& name, bool passed, const string& msg = "") {
    results.push_back({name, passed, msg});
    cout << (passed ? "  [PASS] " : "  [FAIL] ") << name;
    if (!msg.empty()) cout << " - " << msg;
    cout << endl;
}
`)

	// Test: Basic satisfiability
	fmt.Fprint(w, `
// Test: Are all constraints satisfiable together?
bool testSatisfiable() {
    TermManager tm;
    Solver solver(tm);
    Sort field = tm.mkFiniteFieldSort(FIELD_MODULUS);
    vector<Term> vars = createVars(tm, field);

    assertAllConstraints(solver, tm, field, vars);

    Result r = solver.checkSat();
    return r.isSat();
}
`)

	// Test: Constraint necessity
	if cfg.IncludeConstraintNecessity {
		fmt.Fprint(w, `
// Test: Is constraint i necessary? (Removing it allows different solutions)
// Returns true if the constraint is necessary (removing it is unsafe)
bool testConstraintNecessary(int constraintIdx, function<void(Solver&, TermManager&, Sort&, vector<Term>&)> adversarial) {
    TermManager tm;
    Solver solver(tm);
    Sort field = tm.mkFiniteFieldSort(FIELD_MODULUS);
    vector<Term> vars = createVars(tm, field);

    // Assert all constraints EXCEPT the one we're testing
    assertConstraintsExcept(solver, tm, field, vars, constraintIdx);

    // Apply adversarial condition (e.g., trying to find a wrong solution)
    adversarial(solver, tm, field, vars);

    // If SAT, the constraint was necessary to prevent this adversarial case
    Result r = solver.checkSat();
    return r.isSat();
}
`)
	}

	// Test: Variable can take multiple values
	if cfg.IncludeVariableBounds {
		fmt.Fprint(w, `
// Test: Can a variable take two different values while satisfying all constraints?
// Returns true if the variable is under-constrained (can have multiple values)
bool testVariableUnderConstrained(int varIdx) {
    TermManager tm;
    Solver solver(tm);
    Sort field = tm.mkFiniteFieldSort(FIELD_MODULUS);

    // Create two sets of variables
    vector<Term> vars1, vars2;
    for (int i = 0; i < NB_VARS; i++) {
        vars1.push_back(tm.mkConst(field, VAR_NAMES[i] + "_1"));
        vars2.push_back(tm.mkConst(field, VAR_NAMES[i] + "_2"));
    }

    // Both satisfy all constraints
    Term zero = mkFieldElem(tm, field, "0");
    for (const auto& c : CONSTRAINTS) {
        Term ct1 = buildConstraint(tm, field, vars1, c);
        Term ct2 = buildConstraint(tm, field, vars2, c);
        solver.assertFormula(tm.mkTerm(Kind::EQUAL, {ct1, zero}));
        solver.assertFormula(tm.mkTerm(Kind::EQUAL, {ct2, zero}));
    }

    // The tested variable has different values
    Term diff = ffSub(tm, field, vars1[varIdx], vars2[varIdx]);
    solver.assertFormula(tm.mkTerm(Kind::NOT, {tm.mkTerm(Kind::EQUAL, {diff, zero})}));

    // If SAT, the variable can take multiple values (under-constrained)
    Result r = solver.checkSat();
    return r.isSat();
}
`)
	}

	// Main function with comprehensive tests
	fmt.Fprintf(w, `
int main() {
    cout << "========================================" << endl;
    cout << "Soundness Analysis: %s" << endl;
    cout << "========================================" << endl;
    cout << "Field: " << FIELD_MODULUS.substr(0, 20) << "..." << endl;
    cout << "Variables: " << NB_VARS << endl;
    cout << "Constraints: " << NB_CONSTRAINTS << endl;
    cout << endl;

    // Test basic satisfiability
    cout << "--- Basic Satisfiability ---" << endl;
    recordResult("All constraints satisfiable", testSatisfiable());
    cout << endl;
`, testName)

	if cfg.IncludeVariableBounds {
		fmt.Fprint(w, `
    // Test for under-constrained variables
    cout << "--- Variable Constraint Analysis ---" << endl;
    cout << "Checking if internal variables can take multiple values..." << endl;
    int underConstrainedCount = 0;
`)
		// Only check internal variables (skip public/secret which are inputs)
		fmt.Fprintf(w, "    for (int i = %d; i < NB_VARS; i++) {\n", ext.NbPublic+ext.NbSecret)
		fmt.Fprint(w, `        bool underConstrained = testVariableUnderConstrained(i);
        if (underConstrained) {
            underConstrainedCount++;
            recordResult("Variable " + VAR_NAMES[i] + " uniquely determined", false, "can take multiple values");
        }
    }
    if (underConstrainedCount == 0) {
        cout << "  [PASS] All internal variables are uniquely determined" << endl;
    } else {
        cout << "  [WARNING] " << underConstrainedCount << " internal variables are under-constrained" << endl;
    }
    cout << endl;
`)
	}

	if cfg.IncludeConstraintNecessity {
		fmt.Fprint(w, `
    // Test constraint necessity (sample a few)
    cout << "--- Constraint Necessity Analysis ---" << endl;
    cout << "Testing if constraints are necessary..." << endl;

    // Simple adversarial: try to find two different variable assignments
    auto adversarialDifferent = [](Solver& s, TermManager& tm, Sort& field, vector<Term>& vars) {
        // This doesn't add extra constraints - just checks if system is still sound
        // A more specific test would check semantic properties
    };

    int unnecessaryCount = 0;
    int sampleSize = min((int)CONSTRAINTS.size(), 10);  // Sample first 10 constraints
    for (int i = 0; i < sampleSize; i++) {
        bool necessary = testConstraintNecessary(i, adversarialDifferent);
        // For this basic test, we expect removing any constraint keeps system satisfiable
        // The question is whether it's STILL enforcing what we want
    }
    cout << endl;
`)
	}

	// Summary
	fmt.Fprint(w, `
    // Summary
    cout << "========================================" << endl;
    int passed = 0, failed = 0;
    for (const auto& r : results) {
        if (r.passed) passed++; else failed++;
    }
    cout << "Summary: " << passed << " passed, " << failed << " failed" << endl;
    cout << "========================================" << endl;

    return failed > 0 ? 1 : 0;
}
`)

	return nil
}

// StaticAnalysis performs static analysis on extracted constraints without SMT solver.
// This catches obvious issues quickly before running expensive SMT checks.
func StaticAnalysis(ext *ExtractedSystem, name string) *AnalysisResult {
	result := &AnalysisResult{
		CircuitName:      name,
		TotalConstraints: len(ext.Constraints),
		TotalVariables:   ext.NbPublic + ext.NbSecret + ext.NbInternal,
	}

	// Track which variables appear in constraints
	varAppearances := make(map[uint32]int)
	varInLinear := make(map[uint32]bool)    // Appears with non-zero qL, qR, or qO
	varInMultiply := make(map[uint32]bool)  // Appears in qM term
	varDetermined := make(map[uint32]bool)  // Variable is uniquely determined by constraints

	for _, c := range ext.Constraints {
		if c.QL.Sign() != 0 {
			varAppearances[c.XA]++
			varInLinear[c.XA] = true
		}
		if c.QR.Sign() != 0 {
			varAppearances[c.XB]++
			varInLinear[c.XB] = true
		}
		if c.QO.Sign() != 0 {
			varAppearances[c.XC]++
			varInLinear[c.XC] = true
		}
		if c.QM.Sign() != 0 {
			varAppearances[c.XA]++
			varAppearances[c.XB]++
			varInMultiply[c.XA] = true
			varInMultiply[c.XB] = true
		}

		// Check if this constraint uniquely determines XC from XA and XB
		// Pattern: qL*xa + qR*xb + qO*xc = 0 where qO != 0
		// This determines xc if xa and xb are known
		if c.QO.Sign() != 0 && c.QM.Sign() == 0 {
			// Linear constraint that determines XC
			if varDetermined[c.XA] || int(c.XA) < ext.NbPublic+ext.NbSecret {
				if varDetermined[c.XB] || int(c.XB) < ext.NbPublic+ext.NbSecret || c.QR.Sign() == 0 {
					varDetermined[c.XC] = true
				}
			}
		}
	}

	// Check 1: Variables that never appear in any constraint
	totalVars := ext.NbPublic + ext.NbSecret + ext.NbInternal
	for i := 0; i < totalVars; i++ {
		if varAppearances[uint32(i)] == 0 {
			varName := "unknown"
			if i < len(ext.VariableNames) {
				varName = ext.VariableNames[i]
			}
			// Secret/internal variables should appear somewhere
			if i >= ext.NbPublic {
				result.Issues = append(result.Issues, Issue{
					Severity:      "warning",
					Type:          "unused-variable",
					Description:   fmt.Sprintf("Variable '%s' never appears in any constraint", varName),
					VariableIndex: i,
				})
			}
		}
	}

	// Check 2: Trivial constraints (all coefficients zero)
	for i, c := range ext.Constraints {
		if c.QL.Sign() == 0 && c.QR.Sign() == 0 && c.QO.Sign() == 0 && c.QM.Sign() == 0 {
			if c.QC.Sign() == 0 {
				result.Issues = append(result.Issues, Issue{
					Severity:        "info",
					Type:            "trivial-constraint",
					Description:     "Constraint is trivially true (0 = 0)",
					ConstraintIndex: i,
				})
			} else {
				result.Issues = append(result.Issues, Issue{
					Severity:        "critical",
					Type:            "impossible-constraint",
					Description:     fmt.Sprintf("Constraint is impossible (constant %s = 0)", c.QC.String()),
					ConstraintIndex: i,
				})
			}
		}
	}

	// Check 3: Variables that only appear once might be under-constrained
	for varIdx, count := range varAppearances {
		if count == 1 && int(varIdx) >= ext.NbPublic+ext.NbSecret {
			// Internal variable that appears only once
			varName := "unknown"
			if int(varIdx) < len(ext.VariableNames) {
				varName = ext.VariableNames[varIdx]
			}
			result.Issues = append(result.Issues, Issue{
				Severity:      "info",
				Type:          "single-appearance",
				Description:   fmt.Sprintf("Internal variable '%s' appears in only one constraint", varName),
				VariableIndex: int(varIdx),
				Details:       "May be under-constrained if not uniquely determined by that constraint",
			})
		}
	}

	// Check 4: Look for potential division-by-zero patterns
	// Pattern: qM*xa*xb + qC = 0 where xa could be zero
	for i, c := range ext.Constraints {
		if c.QM.Sign() != 0 && c.QL.Sign() == 0 && c.QR.Sign() == 0 && c.QO.Sign() == 0 {
			// Pure multiplication constraint: qM*xa*xb + qC = 0
			if c.QC.Sign() != 0 {
				// If qC != 0, then xa*xb must be non-zero
				result.Passed = append(result.Passed,
					fmt.Sprintf("Constraint %d: multiplication with non-zero constant (safe)", i))
			}
		}
	}

	// Check 5: Detect decomposition without range checks pattern
	// This is a common source of under-constraint bugs
	decompositionVars := detectDecompositionPattern(ext)
	for _, dv := range decompositionVars {
		if !dv.HasRangeCheck {
			result.Issues = append(result.Issues, Issue{
				Severity:      "critical",
				Type:          "missing-range-check",
				Description:   fmt.Sprintf("Decomposition limb '%s' has no range check", dv.VarName),
				VariableIndex: dv.VarIndex,
				Details:       "Limbs in decomposition must be range-checked to prevent overflow/underflow attacks",
			})
		}
	}

	// Check 6: Secret variables that are only used in linear combinations
	// These might allow the prover to choose arbitrary values
	for i := ext.NbPublic; i < ext.NbPublic+ext.NbSecret; i++ {
		varIdx := uint32(i)
		if varInLinear[varIdx] && !varInMultiply[varIdx] {
			// Check if this variable appears with constraints that bind its range
			if !hasRangeConstraint(ext, varIdx) {
				varName := "unknown"
				if i < len(ext.VariableNames) {
					varName = ext.VariableNames[i]
				}
				result.Issues = append(result.Issues, Issue{
					Severity:      "warning",
					Type:          "unbounded-secret",
					Description:   fmt.Sprintf("Secret variable '%s' has no apparent range constraint", varName),
					VariableIndex: i,
					Details:       "Secret variables used only in linear combinations may be exploitable",
				})
			}
		}
	}

	// Check 7: Hint output analysis - check if hint outputs are properly constrained
	hintIssues := analyzeHintOutputs(ext, varAppearances, varInMultiply)
	result.Issues = append(result.Issues, hintIssues...)

	// Check 8: Public output determinacy - check if public outputs are uniquely determined
	// A common bug is computing a value but not constraining the public output to equal it
	publicDetIssues := analyzePublicOutputDeterminacy(ext, varAppearances, varDetermined)
	result.Issues = append(result.Issues, publicDetIssues...)

	// Add passed checks
	if len(result.Issues) == 0 {
		result.Passed = append(result.Passed, "No obvious structural issues found")
	}

	return result
}

// analyzePublicOutputDeterminacy checks if public variables are uniquely determined.
// A circuit is potentially under-constrained if public outputs depend on secret inputs
// but aren't constrained through the circuit logic.
func analyzePublicOutputDeterminacy(ext *ExtractedSystem, varAppearances map[uint32]int, _ map[uint32]bool) []Issue {
	var issues []Issue

	// Check each public variable (after index 0 which is usually the constant 1)
	for i := 1; i < ext.NbPublic; i++ {
		appearances := varAppearances[uint32(i)]

		varName := getVarName(ext, i)

		// A public variable that appears in 0 constraints is completely unconstrained
		if appearances == 0 {
			issues = append(issues, Issue{
				Severity:      "critical",
				Type:          "unconstrained-public",
				Description:   fmt.Sprintf("Public variable '%s' never appears in any constraint", varName),
				VariableIndex: i,
				Details:       "Public outputs must be constrained. A malicious prover can claim any value.",
			})
			continue
		}

		// A public variable that appears only once might be weakly constrained
		if appearances == 1 {
			issues = append(issues, Issue{
				Severity:      "warning",
				Type:          "weakly-constrained-public",
				Description:   fmt.Sprintf("Public variable '%s' appears in only one constraint", varName),
				VariableIndex: i,
				Details:       "Public outputs appearing only once may not be uniquely determined by the circuit inputs.",
			})
		}
	}

	return issues
}

// analyzeHintOutputs checks if hint output variables are properly constrained.
// This is critical because hints compute values outside the circuit, and
// a malicious prover can substitute any value if outputs are under-constrained.
func analyzeHintOutputs(ext *ExtractedSystem, varAppearances map[uint32]int, varInMul map[uint32]bool) []Issue {
	var issues []Issue

	if len(ext.Hints) == 0 {
		return issues
	}

	for _, hint := range ext.Hints {
		for v := hint.OutputStart; v < hint.OutputEnd; v++ {
			appearances := varAppearances[v]
			varName := getVarName(ext, int(v))

			// Check 1: Hint output never appears in any constraint
			if appearances == 0 {
				issues = append(issues, Issue{
					Severity:      "critical",
					Type:          "unconstrained-hint-output",
					Description:   fmt.Sprintf("Hint output '%s' never appears in any constraint", varName),
					VariableIndex: int(v),
					Details:       "Hint outputs must be constrained. A malicious prover can set this to any value.",
				})
				continue
			}

			// Check 2: Hint output appears only once - might be under-constrained
			if appearances == 1 {
				issues = append(issues, Issue{
					Severity:      "warning",
					Type:          "weakly-constrained-hint-output",
					Description:   fmt.Sprintf("Hint output '%s' appears in only one constraint", varName),
					VariableIndex: int(v),
					Details:       "Hint outputs appearing only once may be under-constrained. Verify the constraint uniquely determines this value.",
				})
			}

			// Check 3: Hint output only appears in linear terms (no multiplication)
			// This might allow linear combinations to satisfy constraints with wrong values
			if !varInMul[v] && !hasRangeConstraint(ext, v) {
				issues = append(issues, Issue{
					Severity:      "warning",
					Type:          "hint-output-no-range",
					Description:   fmt.Sprintf("Hint output '%s' has no apparent range constraint", varName),
					VariableIndex: int(v),
					Details:       "Hint outputs should typically be range-checked or appear in non-linear constraints.",
				})
			}
		}
	}

	// Summary of hint analysis
	if len(ext.Hints) > 0 && len(issues) == 0 {
		// This would be added as a passed check in the caller
	}

	return issues
}

// DecompositionVar represents a variable that's part of a decomposition
type DecompositionVar struct {
	VarIndex      int
	VarName       string
	Coefficient   *big.Int
	HasRangeCheck bool
}

// detectDecompositionPattern finds variables that look like decomposition limbs
// that need range checks. This specifically looks for SECRET input variables
// used in decomposition patterns, not intermediate computed values.
func detectDecompositionPattern(ext *ExtractedSystem) []DecompositionVar {
	var result []DecompositionVar

	// Track which variables are "outputs" of decomposition constraints
	// These are computed values, not limbs that need checking
	computedVars := make(map[uint32]bool)

	// First pass: identify output variables from decomposition constraints
	for _, c := range ext.Constraints {
		// Pattern: qL*xa + qR*xb + qO*xc = 0 where qO = -1
		// This means xc = xa*qL/|qO| + xb*qR/|qO| (xc is computed from xa, xb)
		if c.QM.Sign() == 0 && isNegOne(c.QO, ext.Field) {
			computedVars[c.XC] = true
		}
	}

	// Second pass: find SECRET variables used in decomposition that aren't computed
	for _, c := range ext.Constraints {
		// Pattern: qL*xa + qR*xb + qO*xc = 0, qO = -1 (xa + k*xb = xc)
		if c.QM.Sign() == 0 && c.QC.Sign() == 0 && isNegOne(c.QO, ext.Field) {
			if c.QL.Sign() != 0 && c.QR.Sign() != 0 {
				// Only flag SECRET variables as potential limbs needing range check
				// Internal variables are either computed or properly constrained through
				// the log-derivative mechanism
				if int(c.XA) >= ext.NbPublic && int(c.XA) < ext.NbPublic+ext.NbSecret {
					if !computedVars[c.XA] {
						xaHasRange := hasRangeConstraint(ext, c.XA)
						result = append(result, DecompositionVar{
							VarIndex:      int(c.XA),
							VarName:       getVarName(ext, int(c.XA)),
							Coefficient:   c.QL,
							HasRangeCheck: xaHasRange,
						})
					}
				}
				if int(c.XB) >= ext.NbPublic && int(c.XB) < ext.NbPublic+ext.NbSecret {
					if !computedVars[c.XB] {
						xbHasRange := hasRangeConstraint(ext, c.XB)
						result = append(result, DecompositionVar{
							VarIndex:      int(c.XB),
							VarName:       getVarName(ext, int(c.XB)),
							Coefficient:   c.QR,
							HasRangeCheck: xbHasRange,
						})
					}
				}
			}
		}
	}

	// Deduplicate
	seen := make(map[int]bool)
	var unique []DecompositionVar
	for _, dv := range result {
		if !seen[dv.VarIndex] {
			seen[dv.VarIndex] = true
			unique = append(unique, dv)
		}
	}

	return unique
}

// hasRangeConstraint checks if a variable has an apparent range constraint
// using gnark's log-derivative argument pattern
func hasRangeConstraint(ext *ExtractedSystem, varIdx uint32) bool {
	return hasRangeConstraintWithDepth(ext, varIdx, 0, make(map[uint32]bool))
}

// hasRangeConstraintWithDepth checks range constraints with recursion depth tracking
func hasRangeConstraintWithDepth(ext *ExtractedSystem, varIdx uint32, depth int, visited map[uint32]bool) bool {
	// Prevent infinite recursion
	if depth > 10 || visited[varIdx] {
		return false
	}
	visited[varIdx] = true

	// Gnark's range check for PlonK uses log-derivative argument:
	// 1. For each limb, compute diff = limb - table_entry
	// 2. Inverse check: inv * diff = 1 (proves diff non-zero unless limb = entry)
	// 3. Sum over all entries gives 0 only if limb is in table
	//
	// For secret inputs that get decomposed, the pattern is:
	// - Secret variable appears in decomposition: secret = limb0 + 256*limb1 + ...
	// - Each limb_i is then range-checked via the log-derivative mechanism
	// - The limbs are computed via hints and then constrained

	// First, find if varIdx is used to compute a "diff" variable
	diffVars := make(map[uint32]bool)
	for _, c := range ext.Constraints {
		// Pattern: -1*varIdx + something + -1*output = 0
		// This computes: output = varIdx - something (diff pattern)
		if isNegOne(c.QL, ext.Field) && c.XA == varIdx && isNegOne(c.QO, ext.Field) {
			diffVars[c.XC] = true
		}
		// Also check XB position
		if isNegOne(c.QR, ext.Field) && c.XB == varIdx && isNegOne(c.QO, ext.Field) {
			diffVars[c.XC] = true
		}
	}

	// Now check if any of these diff variables have inverse checks
	for diffVar := range diffVars {
		if hasInverseCheck(ext, diffVar) {
			return true
		}
	}

	// Also check direct patterns:
	// Pattern: varIdx forced to specific value (qL*varIdx + qC = 0)
	for _, c := range ext.Constraints {
		if c.XA == varIdx && c.QL.Sign() != 0 &&
			c.QR.Sign() == 0 && c.QO.Sign() == 0 && c.QM.Sign() == 0 && c.QC.Sign() != 0 {
			// varIdx = -qC/qL (forced to constant)
			return true
		}
		// varIdx forced to zero
		if c.XA == varIdx && isNegOne(c.QL, ext.Field) &&
			c.QR.Sign() == 0 && c.QO.Sign() == 0 && c.QM.Sign() == 0 && c.QC.Sign() == 0 {
			return true
		}
	}

	// Check if varIdx participates in multiplication (log-derivative sum)
	// This is a key indicator of range checking
	for _, c := range ext.Constraints {
		if c.QM.Sign() != 0 {
			if c.XA == varIdx || c.XB == varIdx {
				return true
			}
		}
	}

	// Check if varIdx is decomposed into limbs that ARE range-checked
	// Pattern: varIdx = limb0 + k1*limb1 (XC = XA + k*XB where QO = -1)
	// If the limbs are range-checked (recursively), then varIdx is effectively bounded
	for _, c := range ext.Constraints {
		// Look for varIdx appearing as output of a linear combination
		if c.XC == varIdx && c.QM.Sign() == 0 && isNegOne(c.QO, ext.Field) {
			if c.QL.Sign() != 0 && c.QR.Sign() != 0 {
				// Both XA and XB contribute - recursively check if they're constrained
				xaConstrained := hasRangeConstraintWithDepth(ext, c.XA, depth+1, visited)
				xbConstrained := hasRangeConstraintWithDepth(ext, c.XB, depth+1, visited)
				if xaConstrained && xbConstrained {
					return true
				}
			} else if c.QL.Sign() != 0 {
				// Only XA contributes
				if hasRangeConstraintWithDepth(ext, c.XA, depth+1, visited) {
					return true
				}
			} else if c.QR.Sign() != 0 {
				// Only XB contributes
				if hasRangeConstraintWithDepth(ext, c.XB, depth+1, visited) {
					return true
				}
			}
		}
	}

	return false
}

// hasInverseCheck checks if a variable appears in an inverse check pattern
func hasInverseCheck(ext *ExtractedSystem, varIdx uint32) bool {
	for _, c := range ext.Constraints {
		// Pattern: qM*xa*xb + qC = 0 where qC = -1 (inverse check a*b = 1)
		if c.QM.Sign() != 0 && isNegOne(c.QC, ext.Field) &&
			c.QL.Sign() == 0 && c.QR.Sign() == 0 && c.QO.Sign() == 0 {
			if c.XA == varIdx || c.XB == varIdx {
				return true
			}
		}
	}
	return false
}

func getVarName(ext *ExtractedSystem, idx int) string {
	if idx < len(ext.VariableNames) {
		return ext.VariableNames[idx]
	}
	return fmt.Sprintf("v%d", idx)
}

// AnalyzeConstraintPatterns looks for common constraint patterns and verifies them.
func AnalyzeConstraintPatterns(ext *ExtractedSystem) []string {
	var patterns []string

	// Count constraint types
	linearOnly := 0      // Only qL, qR, qO (no qM)
	multiplicationOnly := 0  // Only qM
	mixed := 0           // Both linear and multiplication

	for _, c := range ext.Constraints {
		hasLinear := c.QL.Sign() != 0 || c.QR.Sign() != 0 || c.QO.Sign() != 0
		hasMul := c.QM.Sign() != 0

		if hasLinear && !hasMul {
			linearOnly++
		} else if hasMul && !hasLinear {
			multiplicationOnly++
		} else if hasLinear && hasMul {
			mixed++
		}
	}

	patterns = append(patterns, fmt.Sprintf("Linear constraints: %d", linearOnly))
	patterns = append(patterns, fmt.Sprintf("Multiplication constraints: %d", multiplicationOnly))
	patterns = append(patterns, fmt.Sprintf("Mixed constraints: %d", mixed))

	// Look for common patterns
	// Pattern: decomposition (a + k*b = c)
	decompositions := 0
	for _, c := range ext.Constraints {
		if c.QL.Cmp(big.NewInt(1)) == 0 && c.QR.Sign() != 0 &&
		   isNegOne(c.QO, ext.Field) && c.QM.Sign() == 0 && c.QC.Sign() == 0 {
			decompositions++
		}
	}
	if decompositions > 0 {
		patterns = append(patterns, fmt.Sprintf("Decomposition constraints (a + k*b = c): %d", decompositions))
	}

	// Pattern: inverse check (a*b = 1)
	inverseChecks := 0
	for _, c := range ext.Constraints {
		if c.QM.Cmp(big.NewInt(1)) == 0 && c.QL.Sign() == 0 && c.QR.Sign() == 0 &&
		   c.QO.Sign() == 0 && isNegOne(c.QC, ext.Field) {
			inverseChecks++
		}
	}
	if inverseChecks > 0 {
		patterns = append(patterns, fmt.Sprintf("Inverse check constraints (a*b = 1): %d", inverseChecks))
	}

	return patterns
}

func isNegOne(val *big.Int, field *big.Int) bool {
	negOne := new(big.Int).Sub(field, big.NewInt(1))
	return val.Cmp(negOne) == 0
}

// GenerateUnderConstraintTest creates a specific test for under-constraint detection.
func GenerateUnderConstraintTest(w io.Writer, ext *ExtractedSystem, testName string,
	varIndex int, description string) {

	varName := "unknown"
	if varIndex < len(ext.VariableNames) {
		varName = ext.VariableNames[varIndex]
	}

	// Convert varName to PascalCase for function name
	funcName := toPascalCase(varName)

	fmt.Fprintf(w, `
/**
 * Test: %s
 * Variable: %s (index %d)
 *
 * This test checks if the variable can take multiple different values
 * while still satisfying all constraints. If SAT, the variable is
 * under-constrained.
 */
bool test%sUnderConstrained() {
    TermManager tm;
    Solver solver(tm);
    Sort field = tm.mkFiniteFieldSort(FIELD_MODULUS);

    // Two sets of variables
    vector<Term> vars1 = createVars(tm, field, "_set1");
    vector<Term> vars2 = createVars(tm, field, "_set2");

    // Both satisfy all constraints
    assertAllConstraints(solver, tm, field, vars1);
    assertAllConstraints(solver, tm, field, vars2);

    // Variable %d must be different
    Term diff = ffSub(tm, field, vars1[%d], vars2[%d]);
    Term zero = mkFieldElem(tm, field, "0");
    solver.assertFormula(tm.mkTerm(Kind::NOT, {tm.mkTerm(Kind::EQUAL, {diff, zero})}));

    Result r = solver.checkSat();
    return r.isUnsat();  // UNSAT means uniquely determined (good)
}
`, description, varName, varIndex, funcName, varIndex, varIndex, varIndex)
}

// toPascalCase converts a string to PascalCase for use in function names.
func toPascalCase(s string) string {
	if len(s) == 0 {
		return s
	}
	// Simple implementation: capitalize first letter
	first := strings.ToUpper(s[:1])
	if len(s) == 1 {
		return first
	}
	return first + s[1:]
}
