package sw_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

// Benchmark circuits for comparing classical vs torus Miller loop

type ClassicalPairCircuit struct {
	P G1Affine
	Q G2Affine
}

func (c *ClassicalPairCircuit) Define(api frontend.API) error {
	pairing, err := Pair(api, []G1Affine{c.P}, []G2Affine{c.Q})
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	pairing.AssertIsEqual(api, one)
	return nil
}

type TorusPairCircuit struct {
	P G1Affine
	Q G2Affine
}

func (c *TorusPairCircuit) Define(api frontend.API) error {
	pairing, err := PairTorus(api, []G1Affine{c.P}, []G2Affine{c.Q})
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	pairing.AssertIsEqual(api, one)
	return nil
}

// Multi-pairing circuits
type ClassicalPair2Circuit struct {
	P [2]G1Affine
	Q [2]G2Affine
}

func (c *ClassicalPair2Circuit) Define(api frontend.API) error {
	pairing, err := Pair(api, c.P[:], c.Q[:])
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	pairing.AssertIsEqual(api, one)
	return nil
}

type TorusPair2Circuit struct {
	P [2]G1Affine
	Q [2]G2Affine
}

func (c *TorusPair2Circuit) Define(api frontend.API) error {
	pairing, err := PairTorus(api, c.P[:], c.Q[:])
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	pairing.AssertIsEqual(api, one)
	return nil
}

// PairingCheck circuit for comparison (optimized classical version)
type PairingCheckCircuit struct {
	P [2]G1Affine
	Q [2]G2Affine
}

func (c *PairingCheckCircuit) Define(api frontend.API) error {
	return PairingCheck(api, c.P[:], c.Q[:])
}

// PairingCheckTorus circuit
type PairingCheckTorusCircuit struct {
	P [2]G1Affine
	Q [2]G2Affine
}

func (c *PairingCheckTorusCircuit) Define(api frontend.API) error {
	return PairingCheckTorus(api, c.P[:], c.Q[:])
}

func TestTorusMillerLoopConstraintComparison(t *testing.T) {
	// Compile classical Pair circuit
	c1 := &ClassicalPairCircuit{}
	ccs1, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c1)
	if err != nil {
		t.Fatal(err)
	}

	// Compile torus Pair circuit
	c2 := &TorusPairCircuit{}
	ccs2, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c2)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("=== Single Pairing (n=1) ===")
	fmt.Printf("Classical Pair: %d constraints\n", ccs1.GetNbConstraints())
	fmt.Printf("Torus Pair:     %d constraints\n", ccs2.GetNbConstraints())
	fmt.Printf("Difference:     %d constraints\n", ccs1.GetNbConstraints()-ccs2.GetNbConstraints())
	fmt.Println()

	// Compile 2-pairing circuits
	c3 := &ClassicalPair2Circuit{}
	ccs3, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c3)
	if err != nil {
		t.Fatal(err)
	}

	c4 := &TorusPair2Circuit{}
	ccs4, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c4)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("=== Double Pairing (n=2) ===")
	fmt.Printf("Classical Pair2: %d constraints\n", ccs3.GetNbConstraints())
	fmt.Printf("Torus Pair2:     %d constraints\n", ccs4.GetNbConstraints())
	fmt.Printf("Difference:      %d constraints\n", ccs3.GetNbConstraints()-ccs4.GetNbConstraints())
	fmt.Println()

	// Compile PairingCheck (optimized classical)
	c5 := &PairingCheckCircuit{}
	ccs5, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c5)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("=== Comparison with PairingCheck (n=2) ===")
	fmt.Printf("PairingCheck:  %d constraints\n", ccs5.GetNbConstraints())
	fmt.Printf("Torus Pair2:   %d constraints\n", ccs4.GetNbConstraints())
	fmt.Printf("Difference:    %d constraints\n", ccs5.GetNbConstraints()-ccs4.GetNbConstraints())
	fmt.Println()

	// Compile PairingCheckTorus
	c6 := &PairingCheckTorusCircuit{}
	ccs6, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c6)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("=== PairingCheck vs PairingCheckTorus (n=2) ===")
	fmt.Printf("PairingCheck:      %d constraints\n", ccs5.GetNbConstraints())
	fmt.Printf("PairingCheckTorus: %d constraints\n", ccs6.GetNbConstraints())
	fmt.Printf("Difference:        %d constraints\n", ccs5.GetNbConstraints()-ccs6.GetNbConstraints())
}

// Test that torus pairing produces correct results
// e(P, Q) * e(-P, Q) = 1
type TorusPairCheckCircuit struct {
	P1, P2 G1Affine
	Q1, Q2 G2Affine
}

func (c *TorusPairCheckCircuit) Define(api frontend.API) error {
	pairing, err := PairTorus(api, []G1Affine{c.P1, c.P2}, []G2Affine{c.Q1, c.Q2})
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	pairing.AssertIsEqual(api, one)
	return nil
}

func TestTorusPairCorrectness(t *testing.T) {
	assert := test.NewAssert(t)

	// Get test points
	_, _, p1, q1 := bls12377.Generators()
	var p2 bls12377.G1Affine
	p2.Neg(&p1)

	circuit := &TorusPairCheckCircuit{}
	witness := &TorusPairCheckCircuit{
		P1: NewG1Affine(p1),
		P2: NewG1Affine(p2),
		Q1: NewG2Affine(q1),
		Q2: NewG2Affine(q1),
	}

	err := test.IsSolved(circuit, witness, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

func TestTorusPair2Correctness(t *testing.T) {
	assert := test.NewAssert(t)

	// Get test points
	_, _, p1, q1 := bls12377.Generators()
	var p2 bls12377.G1Affine
	var q2 bls12377.G2Affine
	p2.Neg(&p1)
	q2.Set(&q1)

	circuit := &TorusPair2Circuit{}
	witness := &TorusPair2Circuit{
		P: [2]G1Affine{NewG1Affine(p1), NewG1Affine(p2)},
		Q: [2]G2Affine{NewG2Affine(q1), NewG2Affine(q2)},
	}

	err := test.IsSolved(circuit, witness, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

// Miller loop only circuits for comparison
type MillerLoopOnlyCircuit struct {
	P [2]G1Affine
	Q [2]G2Affine
}

func (c *MillerLoopOnlyCircuit) Define(api frontend.API) error {
	ml, err := MillerLoop(api, c.P[:], c.Q[:])
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	// Just constrain it somehow to avoid optimization
	ml.AssertIsEqual(api, one)
	return nil
}

type MillerLoopTorusOnlyCircuit struct {
	P [2]G1Affine
	Q [2]G2Affine
}

func (c *MillerLoopTorusOnlyCircuit) Define(api frontend.API) error {
	ml, err := MillerLoopTorus(api, c.P[:], c.Q[:])
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	ml.AssertIsEqual(api, one)
	return nil
}

func TestMillerLoopConstraintComparison(t *testing.T) {
	// Classical Miller loop
	c1 := &MillerLoopOnlyCircuit{}
	ccs1, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c1)
	if err != nil {
		t.Fatal(err)
	}

	// Torus Miller loop
	c2 := &MillerLoopTorusOnlyCircuit{}
	ccs2, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c2)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("=== Miller Loop Only (n=2) ===")
	fmt.Printf("Classical Miller Loop: %d constraints\n", ccs1.GetNbConstraints())
	fmt.Printf("Torus Miller Loop:     %d constraints\n", ccs2.GetNbConstraints())
	fmt.Printf("Savings:               %d constraints (%.1f%%)\n",
		ccs1.GetNbConstraints()-ccs2.GetNbConstraints(),
		float64(ccs1.GetNbConstraints()-ccs2.GetNbConstraints())/float64(ccs1.GetNbConstraints())*100)
}

func TestPairingCheckTorusCorrectness(t *testing.T) {
	assert := test.NewAssert(t)

	// Get test points: e(P, Q) * e(-P, Q) = 1
	_, _, p1, q1 := bls12377.Generators()
	var p2 bls12377.G1Affine
	p2.Neg(&p1)

	circuit := &PairingCheckTorusCircuit{}
	witness := &PairingCheckTorusCircuit{
		P: [2]G1Affine{NewG1Affine(p1), NewG1Affine(p2)},
		Q: [2]G2Affine{NewG2Affine(q1), NewG2Affine(q1)},
	}

	err := test.IsSolved(circuit, witness, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}
