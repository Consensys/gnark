package examples

import (
	"github.com/consensys/gnark/frontend"
)

// PrintfCircuit demonstrates the usage of Printf for debugging circuit variables
type PrintfCircuit struct {
	X, Y frontend.Variable `gnark:"x,public"`
	Z    frontend.Variable `gnark:"z,secret"`
}

// Define implements the circuit logic using Printf for debugging
func (circuit *PrintfCircuit) Define(api frontend.API) error {
	// Basic arithmetic with debug output
	sum := api.Add(circuit.X, circuit.Y)
	api.Printf("Sum of %d and %d is %d", circuit.X, circuit.Y, sum)

	// Show different number formats
	api.Printf("X in different formats: dec=%d hex=%x bin=%b", circuit.X, circuit.X, circuit.X)

	// Debug intermediate calculations
	product := api.Mul(sum, circuit.Z)
	api.Printf("Product of sum(%d) and secret Z is %d", sum, product)

	// Verify constraints with debug output
	isLessOrEqual := api.IsZero(api.Sub(api.Mul(circuit.X, circuit.Y), product))
	api.Printf("Is X*Y <= sum*Z? %d", isLessOrEqual)

	return nil
}
