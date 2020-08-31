// Package benchmark internal benchmarks
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

const benchCount = 4

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
func PrintMemUsage(header string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Println("________________________________________________________________________________________________________________")
	fmt.Println(header)
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tmallocs = %v ", m.Mallocs)
	fmt.Printf("\tfrees = %v ", m.Frees)
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

// /!\ internal use /!\
// running it with "trace" will output trace.out file
// const n = 1000000

// else will output average proving times, in csv format
func main() {
	n, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Printf("processing with %d constraints as input, %d cpus\n", n, runtime.NumCPU())
	pk, r1cs, input := generateCircuit(n)
	_r1cs := r1cs.(*backend_bn256.R1CS)
	fmt.Println("r1cs nb wires", _r1cs.NbWires)
	fmt.Println("r1cs nb constraints", _r1cs.NbConstraints)
	fmt.Println("r1cs different coeffs", len(_r1cs.Coefficients))
	fmt.Println()
	PrintMemUsage("after r1cs compile + dummy setup")
	fmt.Println()
	start := time.Now()
	_, _ = groth16.Prove(r1cs, pk, input)
	took := time.Since(start)
	PrintMemUsage("after prove")
	fmt.Println()
	fmt.Println("took", took.Milliseconds())
	fmt.Println("____________________________")
}

type benchCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *benchCircuit) Define(ctx *frontend.Context, cs *frontend.CS) error {
	nbConstraints, _ := ctx.Value(nbConstraintKey)
	for i := 0; i < nbConstraints.(int); i++ {
		circuit.X = cs.MUL(circuit.X, circuit.X)
	}
	cs.MUSTBE_EQ(circuit.X, circuit.Y)
	return nil
}

func (circuit *benchCircuit) PostInit(ctx *frontend.Context) error {
	return nil
}

type _nbConstraintKey int

var nbConstraintKey _nbConstraintKey

func generateCircuit(nbConstraints int) (groth16.ProvingKey, r1cs.R1CS, map[string]interface{}) {
	var circuit benchCircuit
	ctx := frontend.NewContext(gurvy.BN256)
	ctx.Set(nbConstraintKey, nbConstraints)

	r1cs, err := frontend.Compile(ctx, &circuit)
	if err != nil {
		panic(err)
	}

	// compute expected Y
	var expectedY fr.Element
	expectedY.SetInterface(2)
	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}
	solution := make(map[string]interface{})
	solution["X"] = 2
	solution["Y"] = expectedY

	// ---------------------------------------------------------------------------------------------
	//  setup
	pk := groth16.DummySetup(r1cs)
	return pk, r1cs, solution
}
