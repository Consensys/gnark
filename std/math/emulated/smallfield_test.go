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

// SmallFieldMulChainCircuitNative tests a chain of multiplications using native variables
type SmallFieldMulChainCircuitNative struct {
	Inputs []frontend.Variable
	Output frontend.Variable
	NbMuls int
}

func (c *SmallFieldMulChainCircuitNative) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	modBits := uint(f.fParams.Modulus().BitLen())

	// Convert inputs to small field elements
	sfInputs := make([]*SmallFieldElement[emparams.KoalaBear], len(c.Inputs))
	for i := range c.Inputs {
		sfInputs[i] = &SmallFieldElement[emparams.KoalaBear]{
			Val:        c.Inputs[i],
			upperBound: modBits,
			isReduced:  false,
		}
	}

	acc := sfInputs[0]
	for i := 1; i <= c.NbMuls; i++ {
		idx := i % len(c.Inputs)
		acc = f.SmallFieldMulMod(acc, sfInputs[idx])
	}

	expected := &SmallFieldElement[emparams.KoalaBear]{
		Val:        c.Output,
		upperBound: modBits,
		isReduced:  false,
	}
	f.SmallFieldAssertIsEqual(acc, expected)
	return nil
}

func TestSmallFieldMulChainConstraints(t *testing.T) {
	// Test constraint count for small field mul chain
	nbInputs := 10
	nbMuls := 100

	circuit := &SmallFieldMulChainCircuitNative{
		Inputs: make([]frontend.Variable, nbInputs),
		NbMuls: nbMuls,
	}

	// Compile for BLS12-377 (PLONK/SCS)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	constraintsPerMul := float64(ccs.GetNbConstraints()) / float64(nbMuls)
	fmt.Printf("SmallField KoalaBear on BLS12-377 (PLONK): %d constraints for %d muls (%.2f per mul)\n",
		ccs.GetNbConstraints(), nbMuls, constraintsPerMul)
}

func TestSmallFieldMulChainConstraintsLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large constraint count test in short mode")
	}

	// Test constraint count for small field mul chain
	nbInputs := 100
	nbMuls := 100000

	circuit := &SmallFieldMulChainCircuitNative{
		Inputs: make([]frontend.Variable, nbInputs),
		NbMuls: nbMuls,
	}

	// Compile for BLS12-377 (PLONK/SCS)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	constraintsPerMul := float64(ccs.GetNbConstraints()) / float64(nbMuls)
	fmt.Printf("SmallField KoalaBear on BLS12-377 (PLONK): %d constraints for %d muls (%.2f per mul)\n",
		ccs.GetNbConstraints(), nbMuls, constraintsPerMul)
}

func TestSmallFieldMulChainWitness(t *testing.T) {
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

	circuit := &SmallFieldMulChainCircuitNative{
		Inputs: make([]frontend.Variable, nbInputs),
		NbMuls: nbMuls,
	}

	witness := &SmallFieldMulChainCircuitNative{
		Inputs: make([]frontend.Variable, nbInputs),
		NbMuls: nbMuls,
	}
	for i := range inputs {
		witness.Inputs[i] = inputs[i]
	}
	witness.Output = acc

	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BLS12_377))
}

// Compare old vs new implementation constraint counts
func TestCompareConstraintCounts(t *testing.T) {
	nbInputs := 10
	nbMuls := 100

	// Old implementation
	oldCircuit := &SmallFieldMulOnlyCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}
	oldCcs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, oldCircuit)
	if err != nil {
		t.Fatal(err)
	}

	// New implementation
	newCircuit := &SmallFieldMulChainCircuitNative{
		Inputs: make([]frontend.Variable, nbInputs),
		NbMuls: nbMuls,
	}
	newCcs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, newCircuit)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Comparison for %d muls:\n", nbMuls)
	fmt.Printf("  Old (emulated.Element): %d constraints (%.2f per mul)\n",
		oldCcs.GetNbConstraints(), float64(oldCcs.GetNbConstraints())/float64(nbMuls))
	fmt.Printf("  New (SmallFieldElement): %d constraints (%.2f per mul)\n",
		newCcs.GetNbConstraints(), float64(newCcs.GetNbConstraints())/float64(nbMuls))
	fmt.Printf("  Reduction: %.1f%%\n",
		100*(1-float64(newCcs.GetNbConstraints())/float64(oldCcs.GetNbConstraints())))
}

func TestCompareConstraintCountsLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large constraint count test in short mode")
	}

	nbInputs := 100
	nbMuls := 100000

	// Old implementation
	oldCircuit := &SmallFieldMulOnlyCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}
	oldCcs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, oldCircuit)
	if err != nil {
		t.Fatal(err)
	}

	// New implementation
	newCircuit := &SmallFieldMulChainCircuitNative{
		Inputs: make([]frontend.Variable, nbInputs),
		NbMuls: nbMuls,
	}
	newCcs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, newCircuit)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Comparison for %d muls:\n", nbMuls)
	fmt.Printf("  Old (emulated.Element): %d constraints (%.2f per mul)\n",
		oldCcs.GetNbConstraints(), float64(oldCcs.GetNbConstraints())/float64(nbMuls))
	fmt.Printf("  New (SmallFieldElement): %d constraints (%.2f per mul)\n",
		newCcs.GetNbConstraints(), float64(newCcs.GetNbConstraints())/float64(nbMuls))
	fmt.Printf("  Reduction: %.1f%%\n",
		100*(1-float64(newCcs.GetNbConstraints())/float64(oldCcs.GetNbConstraints())))
}
