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

// SmallFieldBenchCircuit benchmarks koalabear emulation on BLS12-377
type SmallFieldBenchCircuit struct {
	Inputs  []Element[emparams.KoalaBear]
	Outputs []Element[emparams.KoalaBear]
	NbMuls  int
}

func (c *SmallFieldBenchCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	// Chain of multiplications and additions
	// Each iteration: acc = acc * input[i % len] + input[(i+1) % len]
	acc := &c.Inputs[0]
	for i := 0; i < c.NbMuls; i++ {
		idx := i % len(c.Inputs)
		nextIdx := (i + 1) % len(c.Inputs)
		mul := f.Mul(acc, &c.Inputs[idx])
		acc = f.Add(mul, &c.Inputs[nextIdx])
	}

	// Final assertion
	f.AssertIsEqual(acc, &c.Outputs[0])
	return nil
}

// SmallFieldMulOnlyCircuit benchmarks pure multiplications
type SmallFieldMulOnlyCircuit struct {
	Inputs []Element[emparams.KoalaBear]
	Output Element[emparams.KoalaBear]
	NbMuls int
}

func (c *SmallFieldMulOnlyCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	// Pure multiplication chain
	acc := &c.Inputs[0]
	for i := 1; i <= c.NbMuls; i++ {
		idx := i % len(c.Inputs)
		acc = f.Mul(acc, &c.Inputs[idx])
	}

	f.AssertIsEqual(acc, &c.Output)
	return nil
}

func TestSmallFieldConstraintCount(t *testing.T) {
	// Test with small number first to understand constraint counts
	nbInputs := 10
	nbMuls := 100

	circuit := &SmallFieldMulOnlyCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}

	// Compile for BLS12-377 (PLONK/SCS)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	constraintsPerMul := float64(ccs.GetNbConstraints()) / float64(nbMuls)
	fmt.Printf("KoalaBear on BLS12-377 (PLONK): %d constraints for %d muls (%.2f per mul)\n",
		ccs.GetNbConstraints(), nbMuls, constraintsPerMul)
}

func TestSmallFieldConstraintCountLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large constraint count test in short mode")
	}

	// Target: ~50-100M constraints
	// Based on small test, estimate nbMuls needed
	nbInputs := 100
	nbMuls := 100000 // Start with 100k, adjust based on constraint count

	circuit := &SmallFieldMulOnlyCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}

	// Compile for BLS12-377 (PLONK/SCS)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	constraintsPerMul := float64(ccs.GetNbConstraints()) / float64(nbMuls)
	fmt.Printf("KoalaBear on BLS12-377 (PLONK): %d constraints for %d muls (%.2f per mul)\n",
		ccs.GetNbConstraints(), nbMuls, constraintsPerMul)
}

func TestSmallFieldWitness(t *testing.T) {
	// Test the circuit actually works
	nbInputs := 10
	nbMuls := 5

	var fp emparams.KoalaBear

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

	// Create witness
	circuit := &SmallFieldMulOnlyCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}

	witness := &SmallFieldMulOnlyCircuit{
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

// BenchmarkSmallFieldCompile measures compilation time and constraint count
func BenchmarkSmallFieldCompile(b *testing.B) {
	nbInputs := 100
	nbMuls := 1000

	circuit := &SmallFieldMulOnlyCircuit{
		Inputs: make([]Element[emparams.KoalaBear], nbInputs),
		NbMuls: nbMuls,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
		if err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
			b.ReportMetric(float64(ccs.GetNbConstraints())/float64(nbMuls), "constraints/mul")
		}
	}
}
