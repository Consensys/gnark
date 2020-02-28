// Package benchmark internal benchmarks
package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/groth16"
	"github.com/pkg/profile"
)

const benchCount = 1

var nbConstraints = []int{20000} //1000, 10000, 40000} //, 100000, 1000000, 10000000}

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
				_, _ = groth16.Prove(&r1cs, &pk, r1csInput)
			}
			duration := time.Since(start)
			duration = time.Duration(int64(duration) / int64(benchCount))
			fmt.Printf("%s,%d,%d\n", cs.CurveID.String(), r1cs.NbConstraints(), duration.Milliseconds())
		} else {
			p := profile.Start(profile.TraceProfile, profile.ProfilePath("."))
			for i := uint(0); i < benchCount; i++ {
				_, _ = groth16.Prove(&r1cs, &pk, r1csInput)
			}
			p.Stop()
		}

	}
}

func generateCircuit(nbConstraints int) (groth16.ProvingKey, cs.R1CS, cs.Assignments) {
	// ---------------------------------------------------------------------------------------------
	// circuit definition
	circuit := cs.New()

	// declare inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	for i := 0; i < nbConstraints; i++ {
		x = circuit.MUL(x, x)
	}
	circuit.MUSTBE_EQ(x, y)
	// ---------------------------------------------------------------------------------------------
	// expected solution

	// compute expected Y
	expectedY := cs.Element(2)
	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}
	solution := cs.NewAssignment()
	solution.Assign(cs.Secret, "x", 2)
	solution.Assign(cs.Public, "y", expectedY)

	// ---------------------------------------------------------------------------------------------
	//  setup
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	r1cs := cs.NewR1CS(&circuit)
	groth16.Setup(r1cs, &pk, &vk)

	return pk, *r1cs, solution
}
