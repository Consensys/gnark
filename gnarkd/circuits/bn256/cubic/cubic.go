package main

import (
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *Circuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	x3 := cs.Mul(circuit.X, circuit.X, circuit.X)
	cs.AssertIsEqual(circuit.Y, cs.Add(x3, circuit.X, 5))
	return nil
}

//go:generate go run cubic.go
func main() {
	var circuit Circuit
	r1cs, _ := frontend.Compile(gurvy.BN256, &circuit)

	{
		f, _ := os.Create("cubic.r1cs")
		r1cs.WriteTo(f)
		f.Close()
	}

	pk, vk, _ := groth16.Setup(r1cs)
	{
		f, _ := os.Create("cubic.pk")
		pk.WriteTo(f)
		f.Close()
	}
	{
		f, _ := os.Create("cubic.vk")
		vk.WriteTo(f)
		f.Close()
	}
}
