package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	gkr "github.com/consensys/gnark/internal/gkr/small_rational"
	"github.com/consensys/gnark/std/gkrapi"
	stdgkr "github.com/consensys/gnark/std/gkrapi/gkr"
	_ "github.com/consensys/gnark/std/hash/mimc" // register MIMC hash
	"github.com/consensys/gnark/std/permutation/poseidon2"
	gkr_poseidon2 "github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2"
)

func main() {
	tasks := []func() error{
		gkr.GenerateSumcheckVectors,
		gkr.GenerateVectors,
		generateSerializationTestData,
		generatePoseidon2IntegrationTestData,
	}

	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for _, f := range tasks {
		go func() {
			assertNoError(f())
			wg.Done()
		}()
	}
	wg.Wait()
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}

// doubleCircuit is a simple GKR circuit for serialization testing
type doubleCircuit struct {
	X []frontend.Variable
}

func (c *doubleCircuit) Define(api frontend.API) error {
	gkrApi, err := gkrapi.New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	z := gkrApi.Add(x, x)

	gkrCircuit, err := gkrApi.Compile("MIMC")
	if err != nil {
		return err
	}

	instanceIn := make(map[stdgkr.Variable]frontend.Variable)
	for i := range c.X {
		instanceIn[x] = c.X[i]
		instanceOut, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return err
		}
		api.AssertIsEqual(instanceOut[z], api.Mul(2, c.X[i]))
	}
	return nil
}

func generateSerializationTestData() error {
	fmt.Println("generating GKR serialization test data")

	circuit := &doubleCircuit{
		X: make([]frontend.Variable, 2),
	}

	// Compile for BN254
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Create testdata directory if needed
	testDataDir := filepath.Join("../../gkr/test_vectors/testdata")
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create testdata directory: %w", err)
	}

	// Write serialized constraint system
	outPath := filepath.Join(testDataDir, "gkr_circuit_bn254.scs")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := ccs.WriteTo(f); err != nil {
		return fmt.Errorf("failed to write constraint system: %w", err)
	}

	fmt.Printf("\twrote %s\n", outPath)
	return nil
}

// gkrPoseidon2Circuit performs n Poseidon2 compressions twice — once through the
// GKR-backed compressor and once through the in-circuit Poseidon2 — and asserts
// they agree. Compiling this produces a schedule with all three level variants
// (GkrSkipLevel, GkrSumcheckLevel, GkrSingleSourceZeroCheckLevel), which is what
// the integration test in std/gkrapi needs to exercise after deserialization.
type gkrPoseidon2Circuit struct {
	Ins [][2]frontend.Variable
}

func (c *gkrPoseidon2Circuit) Define(api frontend.API) error {
	gkrComp, err := gkr_poseidon2.NewCompressor(api)
	if err != nil {
		return err
	}
	pos2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	for i := range c.Ins {
		api.AssertIsEqual(pos2.Compress(c.Ins[i][0], c.Ins[i][1]), gkrComp.Compress(c.Ins[i][0], c.Ins[i][1]))
	}
	return nil
}

// generatePoseidon2IntegrationTestData compiles a small GKR-Poseidon2 circuit
// for BLS12-377 and writes both the constraint system and a matching witness
// to testdata/. std/gkrapi reads them back in a separate test process and calls
// Solve on the deserialized constraint system; this exercises the CBOR
// round-trip of GkrProvingSchedule end-to-end through the prover path.
func generatePoseidon2IntegrationTestData() error {
	fmt.Println("generating GKR-Poseidon2 integration test data")

	const nbInstances = 2
	assignment := &gkrPoseidon2Circuit{Ins: make([][2]frontend.Variable, nbInstances)}
	for i := range assignment.Ins {
		assignment.Ins[i] = [2]frontend.Variable{2 * i, 2*i + 1}
	}
	circuit := &gkrPoseidon2Circuit{Ins: make([][2]frontend.Variable, nbInstances)}

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}

	w, err := frontend.NewWitness(assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to build witness: %w", err)
	}

	testDataDir := filepath.Join("../../gkr/test_vectors/testdata")
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create testdata directory: %w", err)
	}

	scsPath := filepath.Join(testDataDir, "gkr_poseidon2_bls12377.scs")
	scsFile, err := os.Create(scsPath)
	if err != nil {
		return fmt.Errorf("failed to create scs file: %w", err)
	}
	defer scsFile.Close()
	if _, err := ccs.WriteTo(scsFile); err != nil {
		return fmt.Errorf("failed to write constraint system: %w", err)
	}
	fmt.Printf("\twrote %s\n", scsPath)

	wtnsPath := filepath.Join(testDataDir, "gkr_poseidon2_bls12377.wtns")
	wtnsFile, err := os.Create(wtnsPath)
	if err != nil {
		return fmt.Errorf("failed to create witness file: %w", err)
	}
	defer wtnsFile.Close()
	if _, err := w.WriteTo(wtnsFile); err != nil {
		return fmt.Errorf("failed to write witness: %w", err)
	}
	fmt.Printf("\twrote %s\n", wtnsPath)

	return nil
}
