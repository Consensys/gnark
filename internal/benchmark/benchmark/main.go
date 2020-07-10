// Package benchmark internal benchmarks
package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
	"github.com/pkg/profile"
)

const benchCount = 1

var nbConstraints = []int{1000, 10000, 40000} //, 100000, 1000000, 10000000}

// /!\ internal use /!\
// running it with "trace" will output trace.out file
// else will output average proving times, in csv format
func main() {
	mode := "time"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	for _, i := range nbConstraints {
		pk, r1cs, r1csInput := generateCircuit(i)
		runtime.GC()
		if mode != "trace" {
			start := time.Now()
			for i := uint(0); i < benchCount; i++ {
				_, _ = groth16.Prove(r1cs, pk, r1csInput)
			}
			duration := time.Since(start)
			duration = time.Duration(int64(duration) / int64(benchCount))
			fmt.Printf("%d,%d\n", r1cs.GetNbConstraints(), duration.Milliseconds())
		} else {
			p := profile.Start(profile.TraceProfile, profile.ProfilePath("."))
			for i := uint(0); i < benchCount; i++ {
				_, _ = groth16.Prove(r1cs, pk, r1csInput)
			}
			p.Stop()
		}

	}
	// TODO revisit with new backend R1CS stuff and new frontend.Compile
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
	expectedY := fr.FromInterface(2)
	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}
	solution := make(map[string]interface{})
	solution["X"] = 2
	solution["Y"] = expectedY

	// ---------------------------------------------------------------------------------------------
	//  setup
	pk, _ := groth16.Setup(r1cs)

	return pk, r1cs, solution
}
