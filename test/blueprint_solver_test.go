package test

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"
)

func testBigIntoToElement[E constraint.Element](t *testing.T, modulus *big.Int) {
	// sample a random big.Int, convert it to an element, and back
	// to a big.Int, and check that it's the same
	s := blueprintSolver[E]{q: modulus}
	b := big.NewInt(0)
	for i := 0; i < 50; i++ {
		b.Rand(rand.New(rand.NewSource(time.Now().Unix())), s.q) //#nosec G404 -- This is a false positive
		e := s.toElement(b)
		b2 := s.ToBigInt(e)
		if b.Cmp(b2) != 0 {
			t.Fatal("b != b2")
		}
	}
}

func TestBigIntToElement(t *testing.T) {
	// t.Parallel()
	testBigIntoToElement[constraint.U64](t, ecc.BW6_761.ScalarField())
	testBigIntoToElement[constraint.U64](t, ecc.BN254.ScalarField())
	testBigIntoToElement[constraint.U32](t, babybear.Modulus())
}

func testBigIntToUint32Slice[E constraint.Element](t *testing.T, modulus *big.Int) {
	// sample a random big.Int, write it to a uint32 slice, and back
	// to a big.Int, and check that it's the same
	s := blueprintSolver[E]{q: modulus}
	var elementLen int // number of uint32 words in the element
	var e E
	switch any(e).(type) {
	case constraint.U32:
		elementLen = 1 // 2 * 1 uint32
	case constraint.U64:
		elementLen = 12 // 6 * 2 ([6]uint64) = 12 uint32
	}

	b1 := big.NewInt(0)
	b2 := big.NewInt(0)

	randSource := rand.New(rand.NewSource(time.Now().Unix())) //#nosec G404 -- This is a false positive

	for i := 0; i < 50; i++ {
		b1.Rand(randSource, s.q)
		b2.Rand(randSource, s.q)
		wb1 := wrappedBigInt{Int: b1, modulus: modulus}
		wb2 := wrappedBigInt{Int: b2, modulus: modulus}
		var to []uint32
		wb1.Compress(&to)
		wb2.Compress(&to)

		if len(to) != elementLen*2 {
			t.Fatal("wrong length: expected 2*len of constraint.Element (uint32 words)")
		}

		e1, n := s.Read(to)
		if n != elementLen {
			t.Fatal("wrong length: expected 1 len of constraint.Element (uint32 words)")
		}
		e2, n := s.Read(to[n:])
		if n != elementLen {
			t.Fatal("wrong length: expected 1 len of constraint.Element (uint32 words)")
		}
		rb1, rb2 := s.ToBigInt(e1), s.ToBigInt(e2)
		if rb1.Cmp(b1) != 0 || rb2.Cmp(b2) != 0 {
			t.Fatal("rb1 != b1 || rb2 != b2")
		}
	}
}

func TestBigIntToUint32Slice(t *testing.T) {
	t.Parallel()
	testBigIntToUint32Slice[constraint.U64](t, ecc.BW6_761.ScalarField())
	testBigIntToUint32Slice[constraint.U64](t, ecc.BN254.ScalarField())
	testBigIntToUint32Slice[constraint.U32](t, babybear.Modulus())
}

// BlueprintCheckReadConsistency verifies that s.Read returns the same Montgomery form
// in both the test engine and real solvers.
//
// Expected behavior: s.Read should return field elements in Montgomery form (internal
// fr.Element representation) consistently across all solvers, allowing custom blueprints
// to work correctly in both test and production environments.
type BlueprintCheckReadConsistency struct {
	expectedMontgomery constraint.U64
}

func (b *BlueprintCheckReadConsistency) CalldataSize() int {
	return 3 // format: [1, coeffID, varID] for a single-term linear expression
}

func (b *BlueprintCheckReadConsistency) NbConstraints() int {
	return 0
}

func (b *BlueprintCheckReadConsistency) NbOutputs(inst constraint.Instruction) int {
	return 1 // Return the value we read
}

func (b *BlueprintCheckReadConsistency) UpdateInstructionTree(inst constraint.Instruction, tree constraint.InstructionTree) constraint.Level {
	// Find max level of referenced wires
	maxLevel := constraint.Level(0)
	n := int(inst.Calldata[0])
	j := 1
	for range n {
		wireID := inst.Calldata[j+1]
		j += 2
		if tree.HasWire(wireID) {
			if level := tree.GetWireLevel(wireID); level >= maxLevel {
				maxLevel = level + 1 // Our instruction depends on this, so we're one level after
			}
		}
	}

	// Insert output wire at this level
	tree.InsertWire(inst.WireOffset, maxLevel)

	return maxLevel
}

func (b *BlueprintCheckReadConsistency) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	// Read using s.Read - should return Montgomery form in both test engine and real solver
	readValue, _ := s.Read(inst.Calldata)

	// Verify we get Montgomery form consistently
	if readValue != b.expectedMontgomery {
		return fmt.Errorf("s.Read consistency violation: got %v, expected Montgomery %v", readValue, b.expectedMontgomery)
	}

	// Set the output wire to the value we read (echo it back)
	s.SetValue(inst.WireOffset, readValue)

	return nil
}

var _ constraint.BlueprintSolvable[constraint.U64] = (*BlueprintCheckReadConsistency)(nil)

// readConsistencyCircuit tests that s.Read returns Montgomery form consistently
type readConsistencyCircuit struct {
	X                  frontend.Variable
	expectedMontgomery constraint.U64
}

func (c *readConsistencyCircuit) Define(api frontend.API) error {
	// First, ensure X is used in a constraint so it gets a wire assignment
	api.AssertIsEqual(c.X, c.X)

	// Create custom blueprint that checks s.Read returns Montgomery form
	blueprint := &BlueprintCheckReadConsistency{
		expectedMontgomery: c.expectedMontgomery,
	}
	blueprintID := api.Compiler().AddBlueprint(blueprint)

	// Convert the frontend Variable to canonical form and compress to calldata
	canonicalVar := api.Compiler().ToCanonicalVariable(c.X)

	var calldata []uint32
	canonicalVar.(constraint.Compressible).Compress(&calldata)

	// Add instruction that will call blueprint.Solve and return the read value
	outputWires := api.Compiler().AddInstruction(blueprintID, calldata)

	// Assert that the output (the value read by blueprint) equals the input X
	output := api.Compiler().InternalVariable(outputWires[0])
	api.AssertIsEqual(output, c.X)

	return nil
}

// TestReadConsistency verifies that s.Read returns Montgomery form consistently
// in both the test engine and real solver.
//
// Expected behavior: BOTH should pass by returning Montgomery form.
// Current status: Real solver passes (returns Montgomery), test engine FAILS (returns canonical).
// Goal: Make test engine also return Montgomery form so both pass.
func TestReadConsistency(t *testing.T) {
	testValue := big.NewInt(12345)
	field := ecc.BLS12_381.ScalarField()

	// Compute expected Montgomery form
	var frElement bls12381fr.Element
	frElement.SetBigInt(testValue)
	var expectedMontgomery constraint.U64
	copy(expectedMontgomery[:], frElement[:])

	circuit := &readConsistencyCircuit{expectedMontgomery: expectedMontgomery}
	assignment := &readConsistencyCircuit{X: testValue, expectedMontgomery: expectedMontgomery}

	// Test with a real solver
	ccs, err := frontend.Compile(field, scs.NewBuilder, circuit)
	require.NoError(t, err)

	w, err := frontend.NewWitness(assignment, field)
	require.NoError(t, err)

	_, err = ccs.Solve(w)
	require.NoError(t, err)

	// Test with engine
	require.NoError(t, IsSolved(circuit, assignment, field))
}
