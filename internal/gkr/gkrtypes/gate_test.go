package gkrtypes

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	compiled, err := CompileGateFunction(addConstantGate, nbIn)
	require.NoError(t, err)

	// Verify the gate has constants
	assert.NotEmpty(t, compiled.Constants, "Expected compiled gate to have constants")

	// Verify the constant value
	assert.Equal(t, 0, compiled.Constants[0].Cmp(big.NewInt(5)), "Expected constant to be 5, got %s", compiled.Constants[0].String())

	// Verify instructions reference the constant
	assert.NotEmpty(t, compiled.Instructions, "Expected compiled gate to have instructions")

	inst := compiled.Instructions[0]
	assert.Equal(t, OpAdd, inst.Op, "Expected OpAdd, got %v", inst.Op)

	// Verify index layout: constants at [0, nbConsts), inputs at [nbConsts, nbConsts+nbInputs)
	nbConsts := len(compiled.Constants)
	hasConstant := false
	hasInput := false
	for _, idx := range inst.Inputs {
		if idx < uint16(nbConsts) {
			hasConstant = true
			assert.Equal(t, uint16(0), idx, "Expected constant index 0, got %d", idx)
		} else if idx >= uint16(nbConsts) && idx < uint16(nbConsts+nbIn) {
			hasInput = true
			inputIdx := idx - uint16(nbConsts)
			assert.Equal(t, uint16(0), inputIdx, "Expected input index 0 (remapped to %d), got %d", nbConsts, idx)
		}
	}

	assert.True(t, hasConstant, "Expected instruction to reference a constant")
	assert.True(t, hasInput, "Expected instruction to reference an input")
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
	compiled, err := CompileGateFunction(complexGate, nbIn)
	require.NoError(t, err)

	// Verify we have two constants
	assert.Equal(t, 2, len(compiled.Constants), "Expected 2 constants, got %d", len(compiled.Constants))

	// Verify the constants are 3 and 7
	constantValues := make(map[int64]bool)
	for _, c := range compiled.Constants {
		constantValues[c.Int64()] = true
	}

	assert.True(t, constantValues[3] && constantValues[7], "Expected constants to be 3 and 7")

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
	compiled, err := CompileGateFunction(gateWithDuplicates, nbIn)
	require.NoError(t, err)

	// Verify only one constant is stored (deduplication)
	assert.Equal(t, 1, len(compiled.Constants), "Expected 1 deduplicated constant, got %d", len(compiled.Constants))

	assert.Equal(t, 0, compiled.Constants[0].Cmp(big.NewInt(5)), "Expected constant to be 5, got %s", compiled.Constants[0].String())

	t.Logf("Successfully deduplicated constants: %d unique constant(s)",
		len(compiled.Constants))
}

func testFitPoly(t *testing.T, name string, f gkr.GateFunction, nbIn, degree, maxDegree int) {
	t.Run(name, func(t *testing.T) {
		tester := gateTester{mod: ecc.BN254.ScalarField()}
		g, err := CompileGateFunction(f, nbIn)
		require.NoError(t, err)
		tester.setGate(g, nbIn)
		require.Equal(t, degree, len(tester.fitPoly(maxDegree))-1)
	})
}

func TestFitPoly(t *testing.T) {
	testFitPoly(t, "identity", Identity, 1, 1, 3)
	testFitPoly(t, "add", Add2, 2, 1, 2)
	testFitPoly(t, "sub", Sub2, 2, 1, 4)
	testFitPoly(t, "mul", Mul2, 2, 2, 2)

	// x * y * z has degree 3
	mul3 := func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Mul(api.Mul(in[0], in[1]), in[2])
	}
	testFitPoly(t, "mul3", mul3, 3, 3, 4)

	// x + y + z has degree 1
	add3 := func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Add(api.Add(in[0], in[1]), in[2])
	}
	testFitPoly(t, "add3", add3, 3, 1, 4)

	// (x + y) * z has degree 2
	addMul := func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Mul(api.Add(in[0], in[1]), in[2])
	}
	testFitPoly(t, "addMul", addMul, 3, 2, 4)
}

func testIsAdditive(t *testing.T, name string, f gkr.GateFunction, isAdditive ...bool) {
	t.Run(name, func(t *testing.T) {
		tester := gateTester{mod: ecc.BN254.ScalarField()}
		g, err := CompileGateFunction(f, len(isAdditive))
		require.NoError(t, err)
		tester.setGate(g, len(isAdditive))
		for i := range isAdditive {
			assert.Equal(t, isAdditive[i], tester.isAdditive(i))
		}
	})
}

func TestIsAdditive(t *testing.T) {
	testIsAdditive(t, "x+y", Add2, true, true)
	testIsAdditive(t, "x-y", Sub2, true, true)
	testIsAdditive(t, "x*y", Mul2, false, false) // neither additive (degree 2 monomial)

	// x additive, y and z not
	testIsAdditive(t, "x+y*z",
		func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			return api.Add(in[0], api.Mul(in[1], in[2]))
		},
		true, false, false)

	// x not additive (degree 2), y additive
	testIsAdditive(t, "x²+y",
		func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			return api.Add(api.Mul(in[0], in[0]), in[1])
		},
		false, true)

	// y appears in both degree-1 and degree-2 terms, so not additive
	testIsAdditive(t, "x*y+y",
		func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			return api.Add(api.Mul(in[0], in[1]), in[1])
		},
		false, false)
}
