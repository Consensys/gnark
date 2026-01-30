//go:build !windows

package profile_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
)

// EmulatedCircuit performs emulated arithmetic which uses deferred constraints
type EmulatedCircuit struct {
	A, B emulated.Element[emulated.Secp256k1Fp]
}

func (c *EmulatedCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		return err
	}

	// These operations use deferred constraint creation
	// Without virtual constraints, profiling wouldn't show where Mul was called
	res := f.Mul(&c.A, &c.B)
	res = f.Mul(res, &c.A)
	f.AssertIsEqual(res, &c.B)

	return nil
}

func TestVirtualConstraints(t *testing.T) {
	p := profile.Start(profile.WithNoOutput())
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &EmulatedCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	p.Stop()

	// Check that we recorded both constraint and virtual samples
	nbConstraints := p.NbConstraints()
	nbVirtual := p.NbVirtualOperations()

	if nbConstraints == 0 {
		t.Error("expected some constraints to be recorded")
	}

	if nbVirtual == 0 {
		t.Error("expected some virtual operations to be recorded")
	}

	// We did 2 Mul operations and 1 AssertIsEqual (which calls checkZero)
	// So we expect at least 3 virtual operations
	// (there might be more due to internal operations like Reduce)
	if nbVirtual < 3 {
		t.Errorf("expected at least 3 virtual operations (2 Mul + 1 AssertIsEqual), got %d", nbVirtual)
	}

	t.Logf("Constraints: %d, Virtual operations: %d", nbConstraints, nbVirtual)
	t.Logf("\n--- Constraints (sample_index=0) ---\n%s", p.Top())
	t.Logf("\n--- Virtual Operations (sample_index=1) ---\n%s", p.TopVirtual())
}

func TestVirtualConstraintsDirectAPI(t *testing.T) {
	// Test the RecordVirtual API directly
	p := profile.Start(profile.WithNoOutput())

	// Record some virtual operations manually (each records count=1)
	profile.RecordVirtual("test.op1", 1)
	profile.RecordVirtual("test.op2", 1)
	profile.RecordVirtual("test.op2", 1) // record op2 twice

	// Also record regular constraints (simulate with RecordConstraint)
	profile.RecordConstraint()
	profile.RecordConstraint()

	p.Stop()

	nbConstraints := p.NbConstraints()
	nbVirtual := p.NbVirtualOperations()

	if nbConstraints != 2 {
		t.Errorf("expected 2 constraints, got %d", nbConstraints)
	}

	if nbVirtual != 3 {
		t.Errorf("expected 3 virtual operations (1+2), got %d", nbVirtual)
	}

	t.Logf("Direct API test - Constraints: %d, Virtual: %d", nbConstraints, nbVirtual)
}

func TestVirtualConstraintsNoSession(t *testing.T) {
	// When no profiling session is active, RecordVirtual should be a no-op
	// This tests that it doesn't panic and doesn't affect anything

	// No profile.Start() - just call RecordVirtual
	profile.RecordVirtual("test.noop", 1)
	profile.RecordConstraint()

	// Start a new session to verify nothing was recorded
	p := profile.Start(profile.WithNoOutput())
	p.Stop()

	// Should have 0 since we started the session after the calls
	if p.NbConstraints() != 0 {
		t.Errorf("expected 0 constraints when session started after recording")
	}
	if p.NbVirtualOperations() != 0 {
		t.Errorf("expected 0 virtual ops when session started after recording")
	}
}

func TestVirtualWeights(t *testing.T) {
	// Test that WithVirtualWeights multiplies counts correctly
	weights := map[string]int{
		"expensive.op": 10,
		"medium.op":    5,
		// "cheap.op" is not in the map, should use count=1
	}
	p := profile.Start(profile.WithNoOutput(), profile.WithVirtualWeights(weights))

	// Record virtual operations
	profile.RecordVirtual("expensive.op", 1) // should count as 10
	profile.RecordVirtual("medium.op", 1)    // should count as 5
	profile.RecordVirtual("medium.op", 1)    // should count as 5
	profile.RecordVirtual("cheap.op", 1)     // should count as 1 (no weight)

	p.Stop()

	nbVirtual := p.NbVirtualOperations()
	// Expected: 10 + 5 + 5 + 1 = 21
	if nbVirtual != 21 {
		t.Errorf("expected 21 virtual operations with weights (10+5+5+1), got %d", nbVirtual)
	}

	t.Logf("WithVirtualWeights test - Virtual: %d (expected 21)", nbVirtual)
}

func TestVirtualWeightsMultipleSessions(t *testing.T) {
	// Test that different sessions can have different weights
	weights1 := map[string]int{"op": 10}
	weights2 := map[string]int{"op": 2}

	p1 := profile.Start(profile.WithNoOutput(), profile.WithVirtualWeights(weights1))
	p2 := profile.Start(profile.WithNoOutput(), profile.WithVirtualWeights(weights2))

	// Record a virtual operation - each session should apply its own weight
	profile.RecordVirtual("op", 1)

	p2.Stop()
	p1.Stop()

	if p1.NbVirtualOperations() != 10 {
		t.Errorf("session 1: expected 10 virtual operations, got %d", p1.NbVirtualOperations())
	}
	if p2.NbVirtualOperations() != 2 {
		t.Errorf("session 2: expected 2 virtual operations, got %d", p2.NbVirtualOperations())
	}

	t.Logf("Multiple sessions - p1: %d (expected 10), p2: %d (expected 2)",
		p1.NbVirtualOperations(), p2.NbVirtualOperations())
}

// ECMulCircuit wraps the ECMul precompile for profiling
type ECMulCircuit struct {
	P sw_emulated.AffinePoint[emulated.BN254Fp]
	U emulated.Element[emulated.BN254Fr]
}

func (c *ECMulCircuit) Define(api frontend.API) error {
	// This is a complex operation that involves many emulated field operations
	// and range checks - perfect for demonstrating virtual constraint profiling
	_ = evmprecompiles.ECMul(api, &c.P, &c.U)
	return nil
}

func TestVirtualConstraintsECMul(t *testing.T) {
	// Test with a more complex circuit - ECMul precompile
	p := profile.Start(profile.WithNoOutput())
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &ECMulCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	p.Stop()

	nbConstraints := p.NbConstraints()
	nbVirtual := p.NbVirtualOperations()

	t.Logf("ECMul Circuit - Constraints: %d, Virtual operations: %d", nbConstraints, nbVirtual)

	// ECMul involves many multiplications and range checks
	// We expect a significant number of virtual operations
	if nbVirtual < 100 {
		t.Errorf("expected at least 100 virtual operations for ECMul, got %d", nbVirtual)
	}

	// Print virtual operations tree to show the breakdown
	t.Logf("\n--- Virtual Operations Breakdown ---\n%s", p.TopVirtual())
}

// Example_virtualConstraints demonstrates how to use virtual constraint profiling
// with emulated arithmetic.
func Example_virtualConstraints() {
	// Start profiling - virtual operations will be tracked at call sites
	p := profile.Start(profile.WithNoOutput())

	// Compile a circuit using emulated arithmetic
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &EmulatedCircuit{})

	p.Stop()

	// View actual constraints (default)
	// go tool pprof -sample_index=0 gnark.pprof

	// View virtual operations (shows where Mul/AssertIsEqual were called)
	// go tool pprof -sample_index=1 gnark.pprof

	// Or programmatically:
	// p.Top() - shows constraint tree
	// p.TopVirtual() - shows virtual operation tree
}

func TestWithoutVirtual(t *testing.T) {
	// Test that WithoutVirtual excludes virtual samples from the profile
	p := profile.Start(profile.WithNoOutput(), profile.WithoutVirtual())

	// Record both constraint and virtual samples
	profile.RecordConstraint()
	profile.RecordConstraint()
	profile.RecordVirtual("test.op", 1)
	profile.RecordVirtual("test.op", 1)

	p.Stop()

	// After Stop(), filtering is applied
	// NbConstraints should still work (returns 2)
	nbConstraints := p.NbConstraints()
	if nbConstraints != 2 {
		t.Errorf("expected 2 constraints, got %d", nbConstraints)
	}

	// Virtual operations count should be 0 after filtering
	nbVirtual := p.NbVirtualOperations()
	if nbVirtual != 0 {
		t.Errorf("expected 0 virtual operations with WithoutVirtual, got %d", nbVirtual)
	}

	t.Logf("WithoutVirtual - Constraints: %d, Virtual: %d", nbConstraints, nbVirtual)
}

func TestWithoutConstraints(t *testing.T) {
	// Test that WithoutConstraints excludes constraint samples from the profile
	p := profile.Start(profile.WithNoOutput(), profile.WithoutConstraints())

	// Record both constraint and virtual samples
	profile.RecordConstraint()
	profile.RecordConstraint()
	profile.RecordVirtual("test.op", 1)
	profile.RecordVirtual("test.op", 1)

	p.Stop()

	// NbConstraints returns 0 when WithoutConstraints is used
	nbConstraints := p.NbConstraints()
	if nbConstraints != 0 {
		t.Errorf("expected 0 constraints with WithoutConstraints, got %d", nbConstraints)
	}

	// NbVirtualOperations should still work correctly
	nbVirtual := p.NbVirtualOperations()
	if nbVirtual != 2 {
		t.Errorf("expected 2 virtual operations, got %d", nbVirtual)
	}

	// Top() should return empty string when constraints are excluded
	if p.Top() != "" {
		t.Errorf("expected empty Top() with WithoutConstraints")
	}

	// TopVirtual() should still work
	if p.TopVirtual() == "" {
		t.Errorf("expected non-empty TopVirtual() with WithoutConstraints")
	}

	t.Logf("WithoutConstraints - Constraints: %d, Virtual: %d", nbConstraints, nbVirtual)
}

func TestWithoutBoth(t *testing.T) {
	// Test that using both WithoutConstraints and WithoutVirtual panics
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when using both WithoutConstraints and WithoutVirtual")
		}
	}()

	_ = profile.Start(profile.WithNoOutput(), profile.WithoutConstraints(), profile.WithoutVirtual())
}
