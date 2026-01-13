package gkrtypes

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

// TestCompiledGateWithConstants tests that gates can use constant values
func TestCompiledGateWithConstants(t *testing.T) {
	// Create a gate that adds a constant: f(x) = x + 5
	addConstantGate := func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		five := big.NewInt(5)
		return api.Add(in[0], five)
	}

	const nbIn = 1
	// Compile the gate
	compiled := CompileGateFunction(addConstantGate, nbIn)

	// Verify the gate has constants
	if len(compiled.Constants) == 0 {
		t.Fatal("Expected compiled gate to have constants")
	}

	// Verify the constant value
	if compiled.Constants[0].Cmp(big.NewInt(5)) != 0 {
		t.Errorf("Expected constant to be 5, got %s", compiled.Constants[0].String())
	}

	// Verify instructions reference the constant
	if len(compiled.Instructions) == 0 {
		t.Fatal("Expected compiled gate to have instructions")
	}

	inst := compiled.Instructions[0]
	if inst.Op != OpAdd {
		t.Errorf("Expected OpAdd, got %v", inst.Op)
	}

	// Verify index layout: constants at [0, nbConsts), inputs at [nbConsts, nbConsts+nbInputs)
	nbConsts := len(compiled.Constants)
	hasConstant := false
	hasInput := false
	for _, idx := range inst.Inputs {
		if idx < uint16(nbConsts) {
			hasConstant = true
			if idx != 0 {
				t.Errorf("Expected constant index 0, got %d", idx)
			}
		} else if idx >= uint16(nbConsts) && idx < uint16(nbConsts+nbIn) {
			hasInput = true
			inputIdx := idx - uint16(nbConsts)
			if inputIdx != 0 {
				t.Errorf("Expected input index 0 (remapped to %d), got %d", nbConsts, idx)
			}
		}
	}

	if !hasConstant {
		t.Error("Expected instruction to reference a constant")
	}
	if !hasInput {
		t.Error("Expected instruction to reference an input")
	}
}

// TestCompiledGateWithMultipleConstants tests gates with multiple different constants
func TestCompiledGateWithMultipleConstants(t *testing.T) {
	// Create a gate: f(x) = (x + 3) * 7
	complexGate := func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		three := big.NewInt(3)
		seven := big.NewInt(7)
		sum := api.Add(in[0], three)
		return api.Mul(sum, seven)
	}

	// Compile the gate
	const nbIn = 1
	compiled := CompileGateFunction(complexGate, nbIn)

	// Verify we have two constants
	if len(compiled.Constants) != 2 {
		t.Errorf("Expected 2 constants, got %d", len(compiled.Constants))
	}

	// Verify the constants are 3 and 7
	constantValues := make(map[int64]bool)
	for _, c := range compiled.Constants {
		constantValues[c.Int64()] = true
	}

	if !constantValues[3] || !constantValues[7] {
		t.Error("Expected constants to be 3 and 7")
	}

	t.Logf("Successfully compiled gate with %d constants: %v",
		len(compiled.Constants), compiled.Constants)
}

// TestConstantDeduplication tests that identical constants are deduplicated
func TestConstantDeduplication(t *testing.T) {
	// Create a gate that uses the same constant multiple times: f(x, y) = (x + 5) + (y + 5)
	gateWithDuplicates := func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		five1 := big.NewInt(5)
		five2 := big.NewInt(5) // Same value, should be deduplicated
		sum1 := api.Add(in[0], five1)
		sum2 := api.Add(in[1], five2)
		return api.Add(sum1, sum2)
	}

	const nbIn = 2
	// Compile the gate
	compiled := CompileGateFunction(gateWithDuplicates, nbIn)

	// Verify only one constant is stored (deduplication)
	if len(compiled.Constants) != 1 {
		t.Errorf("Expected 1 deduplicated constant, got %d", len(compiled.Constants))
	}

	if compiled.Constants[0].Cmp(big.NewInt(5)) != 0 {
		t.Errorf("Expected constant to be 5, got %s", compiled.Constants[0].String())
	}

	t.Logf("Successfully deduplicated constants: %d unique constant(s)",
		len(compiled.Constants))
}
