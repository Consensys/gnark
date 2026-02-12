package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	gkr "github.com/consensys/gnark/internal/gkr/small_rational"
	"github.com/consensys/gnark/std/gkrapi"
	stdgkr "github.com/consensys/gnark/std/gkrapi/gkr"
	_ "github.com/consensys/gnark/std/hash/mimc" // register MIMC hash
)

func main() {
	assertNoError(gkr.GenerateSumcheckVectors())
	assertNoError(gkr.GenerateVectors())
	assertNoError(generateSerializationTestData())
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
	testDataDir := filepath.Join("testdata")
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
