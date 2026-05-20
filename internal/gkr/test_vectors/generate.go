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
	_ "github.com/consensys/gnark/std/hash/mimc" // register MIMC hash
	"github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2/gkrposeidon2testing"
)

func main() {
	tasks := []func() error{
		gkr.GenerateSumcheckVectors,
		gkr.GenerateVectors,
		generateGkrSolveTestdata,
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

// generateGkrSolveTestdata compiles a small GKR-Poseidon2 validator circuit for
// BLS12-377 and writes its constraint system and a matching witness to the
// testdata directory consumed by internal/regression_tests/gkr_solve. That test
// reads them back in a process that does not import gkrapi and calls Solve,
// exercising the full CBOR round-trip of the GKR proving schedule end-to-end.
func generateGkrSolveTestdata() error {
	fmt.Println("generating GKR-Poseidon2 integration testdata")

	const nbInstances = 2
	assignment := &gkrposeidon2testing.Circuit{Ins: make([][2]frontend.Variable, nbInstances)}
	for i := range assignment.Ins {
		assignment.Ins[i] = [2]frontend.Variable{2 * i, 2*i + 1}
	}
	circuit := &gkrposeidon2testing.Circuit{Ins: make([][2]frontend.Variable, nbInstances)}

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}

	w, err := frontend.NewWitness(assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to build witness: %w", err)
	}

	testDataDir := filepath.Join("../../regression_tests/gkr_solve/testdata")
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create testdata directory: %w", err)
	}

	scsPath := filepath.Join(testDataDir, "gkr_poseidon2.scs")
	scsFile, err := os.Create(scsPath)
	if err != nil {
		return fmt.Errorf("failed to create scs file: %w", err)
	}
	defer scsFile.Close()
	if _, err := ccs.WriteTo(scsFile); err != nil {
		return fmt.Errorf("failed to write constraint system: %w", err)
	}
	fmt.Printf("\twrote %s\n", scsPath)

	wtnsPath := filepath.Join(testDataDir, "gkr_poseidon2.wtns")
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
