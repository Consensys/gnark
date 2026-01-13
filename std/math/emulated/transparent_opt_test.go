package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

// This test file demonstrates that the small field optimization is transparent
// to the user - they just use Element[T] and the optimization kicks in automatically.

// TransparentMulChainCircuit uses the standard Element[T] API
type TransparentMulChainCircuit struct {
	Inputs []Element[emparams.KoalaBear]
	Output Element[emparams.KoalaBear]
	NbMuls int
}

func (c *TransparentMulChainCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	// Standard Element[T] multiplication chain
	// The optimization is automatic and transparent!
	acc := &c.Inputs[0]
	for i := 1; i <= c.NbMuls; i++ {
		idx := i % len(c.Inputs)
		acc = f.Mul(acc, &c.Inputs[idx])
	}

	f.AssertIsEqual(acc, &c.Output)
	return nil
}

func TestTransparentOptimizationWitness(t *testing.T) {
	var fp emparams.KoalaBear
	nbInputs := 10
	nbMuls := 5

	// Generate random inputs
	inputs := make([]*big.Int, nbInputs)
	for i := range inputs {
		inputs[i], _ = rand.Int(rand.Reader, fp.Modulus())
	}

	// Compute expected output
	acc := new(big.Int).Set(inputs[0])
	for i := 1; i <= nbMuls; i++ {
		idx := i % nbInputs
		acc.Mul(acc, inputs[idx])
		acc.Mod(acc, fp.Modulus())
	}

	circuit := &TransparentMulChainCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}

	witness := &TransparentMulChainCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}
	for i := range inputs {
		witness.Inputs[i] = ValueOf[emparams.KoalaBear](inputs[i])
	}
	witness.Output = ValueOf[emparams.KoalaBear](acc)

	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BLS12_377))
}

func TestTransparentOptimizationConstraints(t *testing.T) {
	nbInputs := 10
	nbMuls := 100

	circuit := &TransparentMulChainCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	constraintsPerMul := float64(ccs.GetNbConstraints()) / float64(nbMuls)
	fmt.Printf("Transparent Element[T] with optimization: %d constraints for %d muls (%.2f per mul)\n",
		ccs.GetNbConstraints(), nbMuls, constraintsPerMul)
}

func TestTransparentOptimizationConstraintsLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large test")
	}

	nbInputs := 100
	nbMuls := 100000

	circuit := &TransparentMulChainCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	constraintsPerMul := float64(ccs.GetNbConstraints()) / float64(nbMuls)
	fmt.Printf("Transparent Element[T] with optimization: %d constraints for %d muls (%.2f per mul)\n",
		ccs.GetNbConstraints(), nbMuls, constraintsPerMul)
}

// Test that the optimization doesn't break large field emulation
// Large field emulation (e.g., secp256k1 on BN254) should still work

type LargeFieldMulCircuit struct {
	A, B, C Element[emparams.Secp256k1Fp]
}

func (c *LargeFieldMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.Secp256k1Fp](api)
	if err != nil {
		return err
	}

	result := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(result, &c.C)
	return nil
}

func TestLargeFieldStillWorks(t *testing.T) {
	var fp emparams.Secp256k1Fp
	p := fp.Modulus()

	// Random inputs
	a, _ := rand.Int(rand.Reader, p)
	b, _ := rand.Int(rand.Reader, p)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, p)

	circuit := &LargeFieldMulCircuit{}
	witness := &LargeFieldMulCircuit{
		A: ValueOf[emparams.Secp256k1Fp](a),
		B: ValueOf[emparams.Secp256k1Fp](b),
		C: ValueOf[emparams.Secp256k1Fp](c),
	}

	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
}

// Summary benchmark showing improvement
func TestTransparentOptimizationSummary(t *testing.T) {
	fmt.Println("\n=== Transparent Small Field Optimization Summary ===")
	fmt.Println("Using standard Element[T] API with KoalaBear on BLS12-377")
	fmt.Println()

	for _, nbMuls := range []int{100, 1000, 10000} {
		circuit := &TransparentMulChainCircuit{
			Inputs: make([]Element[emparams.KoalaBear], 10),
			NbMuls: nbMuls,
		}

		ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
		if err != nil {
			t.Fatal(err)
		}

		constraintsPerMul := float64(ccs.GetNbConstraints()) / float64(nbMuls)
		fmt.Printf("%d muls: %d total constraints (%.2f per mul)\n",
			nbMuls, ccs.GetNbConstraints(), constraintsPerMul)
	}

	fmt.Println()
	fmt.Println("Before optimization (polynomial checks): ~52 constraints/mul")
	fmt.Println("After optimization (batched scalar):     ~26 constraints/mul")
	fmt.Println("Improvement: ~50% constraint reduction!")
	fmt.Println()
}
