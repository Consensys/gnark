// gnark_constraint_verifier.hpp
// Header-only library for verifying gnark PlonK constraints with cvc5
//
// This provides utilities for:
// - Loading constraints exported from gnark
// - Building cvc5 terms from constraint data
// - Running under/over-constraint analysis
//
// Usage:
//   1. Export your gnark circuit using the smt package
//   2. Include this header and the exported constraint data
//   3. Use the verification functions to analyze constraints
//
// Compile with: g++ -std=c++17 -I/path/to/cvc5/include -L/path/to/cvc5/lib -lcvc5

#ifndef GNARK_CONSTRAINT_VERIFIER_HPP
#define GNARK_CONSTRAINT_VERIFIER_HPP

#include <cvc5/cvc5.h>
#include <string>
#include <vector>
#include <iostream>
#include <functional>

namespace gnark {

using namespace cvc5;

// PlonkConstraint represents a single constraint: qL*xa + qR*xb + qO*xc + qM*(xa*xb) + qC = 0
struct PlonkConstraint {
    int xa, xb, xc;
    std::string qL, qR, qO, qM, qC;
    std::string description;
};

// ConstraintSystem holds all data for a gnark circuit
struct ConstraintSystem {
    std::string fieldModulus;
    int nbPublic;
    int nbSecret;
    int nbInternal;
    std::vector<std::string> variableNames;
    std::vector<PlonkConstraint> constraints;

    int totalVariables() const {
        return nbPublic + nbSecret + nbInternal;
    }
};

// Helper to create field element
inline Term mkFieldElem(TermManager& tm, Sort& field, const std::string& value) {
    return tm.mkFiniteFieldElem(value, field);
}

inline Term mkFieldElem(TermManager& tm, Sort& field, int64_t value) {
    return tm.mkFiniteFieldElem(std::to_string(value), field);
}

// Finite field arithmetic
inline Term ffAdd(TermManager& tm, Term a, Term b) {
    return tm.mkTerm(Kind::FINITE_FIELD_ADD, {a, b});
}

inline Term ffMul(TermManager& tm, Term a, Term b) {
    return tm.mkTerm(Kind::FINITE_FIELD_MULT, {a, b});
}

inline Term ffSub(TermManager& tm, Sort& field, Term a, Term b) {
    Term negOne = mkFieldElem(tm, field, "-1");
    return ffAdd(tm, a, ffMul(tm, negOne, b));
}

inline Term ffEqual(TermManager& tm, Sort& field, Term a, Term b) {
    Term zero = mkFieldElem(tm, field, 0);
    return tm.mkTerm(Kind::EQUAL, {ffSub(tm, field, a, b), zero});
}

// Build a constraint term from PlonkConstraint
inline Term buildConstraintTerm(TermManager& tm, Sort& field,
                                const std::vector<Term>& vars,
                                const PlonkConstraint& c) {
    Term zero = mkFieldElem(tm, field, "0");
    Term result = zero;

    if (c.qL != "0") {
        result = ffAdd(tm, result, ffMul(tm, mkFieldElem(tm, field, c.qL), vars[c.xa]));
    }
    if (c.qR != "0") {
        result = ffAdd(tm, result, ffMul(tm, mkFieldElem(tm, field, c.qR), vars[c.xb]));
    }
    if (c.qO != "0") {
        result = ffAdd(tm, result, ffMul(tm, mkFieldElem(tm, field, c.qO), vars[c.xc]));
    }
    if (c.qM != "0") {
        result = ffAdd(tm, result,
                      ffMul(tm, mkFieldElem(tm, field, c.qM),
                            ffMul(tm, vars[c.xa], vars[c.xb])));
    }
    if (c.qC != "0") {
        result = ffAdd(tm, result, mkFieldElem(tm, field, c.qC));
    }

    return result;
}

// Verifier class for running analysis
class Verifier {
public:
    Verifier(const ConstraintSystem& cs) : cs_(cs), tm_(), solver_(tm_) {
        field_ = tm_.mkFiniteFieldSort(cs_.fieldModulus);
        createVariables();
    }

    // Create all wire variables
    void createVariables() {
        vars_.clear();
        for (int i = 0; i < cs_.totalVariables(); i++) {
            std::string name = (i < static_cast<int>(cs_.variableNames.size()))
                              ? cs_.variableNames[i]
                              : "v" + std::to_string(i);
            vars_.push_back(tm_.mkConst(field_, name));
        }
    }

    // Assert a specific constraint
    void assertConstraint(int idx) {
        if (idx < 0 || idx >= static_cast<int>(cs_.constraints.size())) return;

        const auto& c = cs_.constraints[idx];
        Term constraintTerm = buildConstraintTerm(tm_, field_, vars_, c);
        Term zero = mkFieldElem(tm_, field_, "0");
        solver_.assertFormula(tm_.mkTerm(Kind::EQUAL, {constraintTerm, zero}));
    }

    // Assert all constraints
    void assertAllConstraints() {
        for (size_t i = 0; i < cs_.constraints.size(); i++) {
            assertConstraint(i);
        }
    }

    // Assert all constraints EXCEPT the given one
    void assertAllConstraintsExcept(int excludeIdx) {
        for (size_t i = 0; i < cs_.constraints.size(); i++) {
            if (static_cast<int>(i) != excludeIdx) {
                assertConstraint(i);
            }
        }
    }

    // Assert that two variables are different
    void assertDifferent(int varIdx1, int varIdx2) {
        Term notEqual = tm_.mkTerm(Kind::NOT, {ffEqual(tm_, field_, vars_[varIdx1], vars_[varIdx2])});
        solver_.assertFormula(notEqual);
    }

    // Assert a variable equals a specific value
    void assertVariableValue(int varIdx, const std::string& value) {
        solver_.assertFormula(ffEqual(tm_, field_, vars_[varIdx], mkFieldElem(tm_, field_, value)));
    }

    // Set variable to one of a set of values (range constraint)
    void assertVariableInRange(int varIdx, int min, int max) {
        std::vector<Term> options;
        for (int v = min; v <= max; v++) {
            options.push_back(tm_.mkTerm(Kind::EQUAL, {vars_[varIdx], mkFieldElem(tm_, field_, v)}));
        }
        if (!options.empty()) {
            solver_.assertFormula(tm_.mkTerm(Kind::OR, options));
        }
    }

    // Check satisfiability
    bool checkSat() {
        Result r = solver_.checkSat();
        return r.isSat();
    }

    // Check unsatisfiability
    bool checkUnsat() {
        Result r = solver_.checkSat();
        return r.isUnsat();
    }

    // Reset solver state
    void reset() {
        solver_.resetAssertions();
    }

    // Get the zero constant
    Term zero() {
        return mkFieldElem(tm_, field_, "0");
    }

    // Access term manager and solver for custom queries
    TermManager& termManager() { return tm_; }
    Solver& solver() { return solver_; }
    Sort& field() { return field_; }
    const std::vector<Term>& variables() const { return vars_; }

private:
    const ConstraintSystem& cs_;
    TermManager tm_;
    Solver solver_;
    Sort field_;
    std::vector<Term> vars_;
};

// Test result structure
struct TestResult {
    std::string name;
    bool passed;
    std::string message;
};

// Test runner for running multiple verification tests
class TestRunner {
public:
    using TestFunc = std::function<TestResult(Verifier&)>;

    TestRunner(const ConstraintSystem& cs) : cs_(cs) {}

    void addTest(const std::string& name, TestFunc func) {
        tests_.push_back({name, func});
    }

    void run() {
        std::cout << "========================================" << std::endl;
        std::cout << "Gnark Constraint Verification" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Field: " << cs_.fieldModulus.substr(0, 20) << "..." << std::endl;
        std::cout << "Variables: " << cs_.nbPublic << " public, "
                  << cs_.nbSecret << " secret, " << cs_.nbInternal << " internal" << std::endl;
        std::cout << "Constraints: " << cs_.constraints.size() << std::endl;
        std::cout << std::endl;

        int passed = 0, failed = 0;

        for (const auto& test : tests_) {
            Verifier verifier(cs_);
            TestResult result = test.second(verifier);

            if (result.passed) {
                std::cout << "PASS: " << result.name;
                passed++;
            } else {
                std::cout << "FAIL: " << result.name;
                failed++;
            }
            if (!result.message.empty()) {
                std::cout << " - " << result.message;
            }
            std::cout << std::endl;
        }

        std::cout << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Summary: " << passed << " passed, " << failed << " failed" << std::endl;
        std::cout << "========================================" << std::endl;
    }

private:
    const ConstraintSystem& cs_;
    std::vector<std::pair<std::string, TestFunc>> tests_;
};

// Common test: verify constraints are satisfiable
inline TestResult testSatisfiable(Verifier& v) {
    v.assertAllConstraints();
    bool sat = v.checkSat();
    return {"Constraints satisfiable", sat, sat ? "System has valid solutions" : "No solutions exist"};
}

// Test that removing a constraint makes the system more permissive
// (i.e., the constraint is necessary)
inline TestResult testConstraintNecessary(Verifier& v, int constraintIdx,
                                          std::function<void(Verifier&)> setupAdversarial) {
    v.assertAllConstraintsExcept(constraintIdx);
    setupAdversarial(v);
    bool sat = v.checkSat();
    std::string msg = sat ? "Constraint is necessary (attack possible without it)"
                          : "Constraint may be redundant";
    return {"Constraint " + std::to_string(constraintIdx) + " necessary", sat, msg};
}

} // namespace gnark

#endif // GNARK_CONSTRAINT_VERIFIER_HPP
