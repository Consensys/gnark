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
	gkr_poseidon2 "github.com/consensys/gnark/std/hash/poseidon2/gkr-poseidon2"
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

// gkrPoseidon2Circuit computes H(X,Y) using gkr-poseidon2.
type gkrPoseidon2Circuit struct {
	X, Y frontend.Variable
}

func (c *gkrPoseidon2Circuit) Define(api frontend.API) error {
	h, err := gkr_poseidon2.New(api)
	if err != nil {
		return err
	}
	h.Write(c.X, c.Y)
	api.AssertIsDifferent(h.Sum(), 0)
	return nil
}

// generateGkrSolveTestdata compiles a small GKR-Poseidon2 validator circuit for
// BLS12-377 and writes its constraint system and a matching witness to the
// integration_test/ directory. The test there reads them back in a process that
// does not import gkrapi and calls Solve, exercising the full CBOR round-trip
// of the GKR proving schedule end-to-end.
func generateGkrSolveTestdata() error {
	fmt.Println("generating GKR-Poseidon2 integration testdata")

	assignment := gkrPoseidon2Circuit{1, 2}
	var circuit gkrPoseidon2Circuit

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}

	w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to build witness: %w", err)
	}

	const testDataDir = "integration_test"
	if err = os.MkdirAll(testDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create testdata directory: %w", err)
	}

	scsPath := filepath.Join(testDataDir, "gkr_poseidon2.scs")
	scsFile, err := os.Create(scsPath)
	if err != nil {
		return fmt.Errorf("failed to create scs file: %w", err)
	}
	defer scsFile.Close()
	if _, err = ccs.WriteTo(scsFile); err != nil {
		return fmt.Errorf("failed to write constraint system: %w", err)
	}
	fmt.Printf("\twrote %s\n", scsPath)

	wtnsPath := filepath.Join(testDataDir, "gkr_poseidon2.wtns")
	wtnsFile, err := os.Create(wtnsPath)
	if err != nil {
		return fmt.Errorf("failed to create witness file: %w", err)
	}
	defer wtnsFile.Close()
	if _, err = w.WriteTo(wtnsFile); err != nil {
		return fmt.Errorf("failed to write witness: %w", err)
	}
	fmt.Printf("\twrote %s\n", wtnsPath)

	return nil
}
