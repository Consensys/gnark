// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package issue555

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

const nbEqualities = 16
const nbBenchmarkEqualities = 1024

type internalEqualityCircuit struct {
	WithEqualities bool `gnark:"-"`
	A, B           [nbEqualities]frontend.Variable
	C, D           [nbEqualities]frontend.Variable
}

func (c *internalEqualityCircuit) Define(api frontend.API) error {
	for i := 0; i < nbEqualities; i++ {
		left := api.Mul(c.A[i], c.B[i])
		right := api.Mul(c.C[i], c.D[i])
		if c.WithEqualities {
			api.AssertIsEqual(left, right)
		}
	}
	return nil
}

func TestInternalEqualitiesAreCanonicalized(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			base := compile(t, tc.builder, &internalEqualityCircuit{})
			withEqualities := compile(t, tc.builder, &internalEqualityCircuit{WithEqualities: true})

			baseConstraints := base.GetNbConstraints()
			withConstraints := withEqualities.GetNbConstraints()
			if baseConstraints != 32 {
				t.Fatalf("expected base circuit to have 32 constraints, got %d", baseConstraints)
			}
			if withConstraints != baseConstraints {
				t.Fatalf("expected internal equalities to be canonicalized, got base=%d withEqualities=%d", baseConstraints, withConstraints)
			}

			validWitness, err := frontend.NewWitness(internalEqualityAssignment(false), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := withEqualities.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve rewritten constraints: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(internalEqualityAssignment(true), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := withEqualities.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail after rewriting stale pre-merge constraints")
			}
		})
	}
}

type internalEqualityBenchmarkCircuit struct {
	WithEqualities bool `gnark:"-"`
	A, B           [nbBenchmarkEqualities]frontend.Variable
	C, D           [nbBenchmarkEqualities]frontend.Variable
}

func (c *internalEqualityBenchmarkCircuit) Define(api frontend.API) error {
	for i := 0; i < nbBenchmarkEqualities; i++ {
		left := api.Mul(c.A[i], c.B[i])
		right := api.Mul(c.C[i], c.D[i])
		if c.WithEqualities {
			api.AssertIsEqual(left, right)
		}
	}
	return nil
}

func BenchmarkInternalEqualityCanonicalizationCompile(b *testing.B) {
	for _, tc := range builderCases {
		b.Run(tc.name, func(b *testing.B) {
			for _, withEqualities := range []bool{false, true} {
				name := "base"
				if withEqualities {
					name = "with_equalities"
				}

				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()

					var nbConstraints, nbInternalVariables, nbInstructions int
					for i := 0; i < b.N; i++ {
						ccs, err := frontend.Compile(ecc.BN254.ScalarField(), tc.builder, &internalEqualityBenchmarkCircuit{
							WithEqualities: withEqualities,
						})
						if err != nil {
							b.Fatal(err)
						}
						nbConstraints = ccs.GetNbConstraints()
						nbInternalVariables = ccs.GetNbInternalVariables()
						nbInstructions = ccs.GetNbInstructions()
					}

					want := 2 * nbBenchmarkEqualities
					if nbConstraints != want {
						b.Fatalf("expected %s/%s to have %d constraints, got %d", tc.name, name, want, nbConstraints)
					}
					if nbInternalVariables != want {
						b.Fatalf("expected %s/%s to have %d internal variables, got %d", tc.name, name, want, nbInternalVariables)
					}

					b.ReportMetric(float64(nbConstraints), "constraints/op")
					b.ReportMetric(float64(nbInternalVariables), "internal_variables/op")
					b.ReportMetric(float64(nbInstructions), "instructions/op")
				})
			}
		})
	}
}

type secretEqualityCircuit struct {
	A, B frontend.Variable
}

func (c *secretEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.A, c.B)
	return nil
}

func TestWitnessEqualityRemainsConstrained(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc.builder, &secretEqualityCircuit{})
			if got := ccs.GetNbConstraints(); got != 1 {
				t.Fatalf("expected witness equality to emit one constraint, got %d", got)
			}

			validWitness, err := frontend.NewWitness(&secretEqualityCircuit{A: 5, B: 5}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve witness equality: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(&secretEqualityCircuit{A: 5, B: 6}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail because witness equality remains constrained")
			}
		})
	}
}

type internalToSecretInputEqualityCircuit struct {
	A, B, C frontend.Variable
}

func (c *internalToSecretInputEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.C)
	return nil
}

type internalToPublicInputEqualityCircuit struct {
	A, B frontend.Variable
	C    frontend.Variable `gnark:",public"`
}

func (c *internalToPublicInputEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.C)
	return nil
}

func TestInternalToInputEqualityRemainsConstrained(t *testing.T) {
	inputCases := []struct {
		name    string
		circuit frontend.Circuit
		valid   frontend.Circuit
		invalid frontend.Circuit
	}{
		{
			name:    "secret",
			circuit: &internalToSecretInputEqualityCircuit{},
			valid:   &internalToSecretInputEqualityCircuit{A: 2, B: 3, C: 6},
			invalid: &internalToSecretInputEqualityCircuit{A: 2, B: 3, C: 7},
		},
		{
			name:    "public",
			circuit: &internalToPublicInputEqualityCircuit{},
			valid:   &internalToPublicInputEqualityCircuit{A: 2, B: 3, C: 6},
			invalid: &internalToPublicInputEqualityCircuit{A: 2, B: 3, C: 7},
		},
	}

	for _, tc := range builderCases {
		for _, input := range inputCases {
			t.Run(tc.name+"/"+input.name, func(t *testing.T) {
				ccs := compile(t, tc.builder, input.circuit)
				if got := ccs.GetNbConstraints(); got != 2 {
					t.Fatalf("expected internal-to-input equality to remain constrained, got %d constraints", got)
				}

				validWitness, err := frontend.NewWitness(input.valid, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := ccs.IsSolved(validWitness); err != nil {
					t.Fatalf("valid witness should solve internal-to-input equality: %v", err)
				}

				invalidWitness, err := frontend.NewWitness(input.invalid, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := ccs.IsSolved(invalidWitness); err == nil {
					t.Fatal("invalid witness should fail because the equality remains constrained")
				}
			})
		}
	}
}

type chainEqualityCircuit struct {
	A, B, C, D, E, F frontend.Variable
}

func (c *chainEqualityCircuit) Define(api frontend.API) error {
	x := api.Mul(c.A, c.B)
	y := api.Mul(c.C, c.D)
	z := api.Mul(c.E, c.F)
	api.AssertIsEqual(x, y)
	api.AssertIsEqual(y, z)
	return nil
}

func TestChainedInternalEqualitiesAreCanonicalized(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc.builder, &chainEqualityCircuit{})
			if got := ccs.GetNbConstraints(); got != 3 {
				t.Fatalf("expected chained internal equalities to add no constraints, got %d", got)
			}

			validWitness, err := frontend.NewWitness(&chainEqualityCircuit{
				A: 2, B: 3,
				C: 1, D: 6,
				E: 6, F: 1,
			}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid chain witness should solve: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(&chainEqualityCircuit{
				A: 2, B: 3,
				C: 1, D: 6,
				E: 7, F: 1,
			}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid chain witness should fail")
			}
		})
	}
}

type hintedInternalEqualityCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *hintedInternalEqualityCircuit) Define(api frontend.API) error {
	left := api.Mul(c.A, c.B)
	right := api.Mul(c.C, c.D)
	hintOut, err := api.Compiler().NewHint(identityHint, 1, right)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hintOut[0], right)
	api.AssertIsEqual(left, right)
	return nil
}

func TestHintInputEscapePreventsAlias(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc.builder, &hintedInternalEqualityCircuit{})
			if got := ccs.GetNbConstraints(); got != 4 {
				t.Fatalf("expected hint input escape to keep equality constrained, got %d constraints", got)
			}

			witness, err := frontend.NewWitness(&hintedInternalEqualityCircuit{
				A: 2,
				B: 3,
				C: 1,
				D: 6,
			}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(witness, solver.WithHints(identityHint)); err != nil {
				t.Fatalf("valid witness should solve hint escape circuit: %v", err)
			}
		})
	}
}

type lateHintInputCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *lateHintInputCircuit) Define(api frontend.API) error {
	left := api.Mul(c.A, c.B)
	right := api.Mul(c.C, c.D)
	api.AssertIsEqual(left, right)

	hintOut, err := api.Compiler().NewHint(identityHint, 1, right)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hintOut[0], right)
	return nil
}

func TestLateHintInputUsesCanonicalAlias(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc.builder, &lateHintInputCircuit{})
			if got := ccs.GetNbConstraints(); got != 3 {
				t.Fatalf("expected late hint input to use canonical alias, got %d constraints", got)
			}

			validWitness, err := frontend.NewWitness(&lateHintInputCircuit{
				A: 2,
				B: 3,
				C: 1,
				D: 6,
			}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness, solver.WithHints(identityHint)); err != nil {
				t.Fatalf("valid witness should solve late hint circuit: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(&lateHintInputCircuit{
				A: 2,
				B: 3,
				C: 1,
				D: 7,
			}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness, solver.WithHints(identityHint)); err == nil {
				t.Fatal("invalid witness should fail because the aliased producer is still constrained")
			}
		})
	}
}

type addOutputEqualityCircuit struct {
	A, B, C, D, E, F, G, H frontend.Variable
}

func (c *addOutputEqualityCircuit) Define(api frontend.API) error {
	left := api.Add(api.Mul(c.A, c.B), api.Mul(c.C, c.D))
	right := api.Add(api.Mul(c.E, c.F), api.Mul(c.G, c.H))
	api.AssertIsEqual(left, right)
	return nil
}

func TestAddOutputEqualityIsCanonicalized(t *testing.T) {
	base := compile(t, scs.NewBuilder[constraint.U64], &addOutputEqualityCircuitBase{})
	ccs := compile(t, scs.NewBuilder[constraint.U64], &addOutputEqualityCircuit{})
	if got, want := ccs.GetNbConstraints(), base.GetNbConstraints(); got != want {
		t.Fatalf("expected SCS add-output equality to add no constraints, got %d want %d", got, want)
	}

	witness, err := frontend.NewWitness(&addOutputEqualityCircuit{
		A: 2, B: 3,
		C: 1, D: 4,
		E: 5, F: 1,
		G: 5, H: 1,
	}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(witness); err != nil {
		t.Fatalf("valid add-output witness should solve: %v", err)
	}
}

type addOutputEqualityCircuitBase addOutputEqualityCircuit

func (c *addOutputEqualityCircuitBase) Define(api frontend.API) error {
	_ = api.Add(api.Mul(c.A, c.B), api.Mul(c.C, c.D))
	_ = api.Add(api.Mul(c.E, c.F), api.Mul(c.G, c.H))
	return nil
}

type batchInvertAfterAliasCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *batchInvertAfterAliasCircuit) Define(api frontend.API) error {
	left := api.Mul(c.A, c.B)
	right := api.Mul(c.C, c.D)
	api.AssertIsEqual(left, right)
	inverted := api.(frontend.BatchInverter).BatchInvert([]frontend.Variable{right})
	api.AssertIsEqual(api.Mul(left, inverted[0]), 1)
	return nil
}

func TestBatchInvertUsesCanonicalAlias(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc.builder, &batchInvertAfterAliasCircuit{})
			witness, err := frontend.NewWitness(&batchInvertAfterAliasCircuit{
				A: 2,
				B: 3,
				C: 1,
				D: 6,
			}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(witness); err != nil {
				t.Fatalf("valid batch inversion witness should solve: %v", err)
			}
		})
	}
}

type canonicalVariableEqualityCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *canonicalVariableEqualityCircuit) Define(api frontend.API) error {
	left := api.Mul(c.A, c.B)
	right := api.Mul(c.C, c.D)
	_ = api.Compiler().ToCanonicalVariable(right)
	api.AssertIsEqual(left, right)
	return nil
}

func TestCanonicalVariableEscapePreventsAlias(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc.builder, &canonicalVariableEqualityCircuit{})
			if got := ccs.GetNbConstraints(); got != 3 {
				t.Fatalf("expected canonical variable escape to keep equality constrained, got %d constraints", got)
			}
		})
	}
}

type customInstructionOutputCircuit struct {
	A, B frontend.Variable
}

func (c *customInstructionOutputCircuit) Define(api frontend.API) error {
	blueprintID := api.Compiler().AddBlueprint(&constantOutputBlueprint{})
	outputWires := api.Compiler().AddInstruction(blueprintID, nil)
	output := api.Compiler().InternalVariable(outputWires[0])

	api.AssertIsEqual(api.Mul(c.A, c.B), output)
	return nil
}

func TestCustomInstructionOutputEscapePreventsAlias(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc.builder, &customInstructionOutputCircuit{})
			if got := ccs.GetNbConstraints(); got != 2 {
				t.Fatalf("expected custom instruction output escape to keep equality constrained, got %d constraints", got)
			}

			validWitness, err := frontend.NewWitness(&customInstructionOutputCircuit{A: 2, B: 3}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve custom instruction circuit: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(&customInstructionOutputCircuit{A: 2, B: 4}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail because custom instruction output equality remains constrained")
			}
		})
	}
}

type constantOutputBlueprint struct{}

func (b *constantOutputBlueprint) CalldataSize() int {
	return 0
}

func (b *constantOutputBlueprint) NbConstraints() int {
	return 0
}

func (b *constantOutputBlueprint) NbOutputs(constraint.Instruction) int {
	return 1
}

func (b *constantOutputBlueprint) UpdateInstructionTree(inst constraint.Instruction, tree constraint.InstructionTree) constraint.Level {
	tree.InsertWire(inst.WireOffset, 0)
	return 0
}

func (b *constantOutputBlueprint) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	s.SetValue(inst.WireOffset, s.FromInterface(6))
	return nil
}

var _ constraint.BlueprintSolvable[constraint.U64] = (*constantOutputBlueprint)(nil)

var builderCases = []struct {
	name    string
	builder frontend.NewBuilder
}{
	{name: "r1cs", builder: r1cs.NewBuilder[constraint.U64]},
	{name: "scs", builder: scs.NewBuilder[constraint.U64]},
}

func compile(t testing.TB, builder frontend.NewBuilder, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	return ccs
}

func internalEqualityAssignment(invalid bool) *internalEqualityCircuit {
	assignment := &internalEqualityCircuit{WithEqualities: true}
	for i := 0; i < nbEqualities; i++ {
		assignment.A[i] = 2
		assignment.B[i] = 3
		assignment.C[i] = 1
		assignment.D[i] = 6
	}
	if invalid {
		assignment.D[0] = 7
	}
	return assignment
}

func identityHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}
