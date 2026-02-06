package fields_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// E12 Square (dense)
type E12SquareCircuit struct{ A E12 }

func (c *E12SquareCircuit) Define(api frontend.API) error {
	c.A.Square(api, c.A)
	return nil
}

// E12 CyclotomicSquare
type E12CyclotomicSquareCircuit struct{ A E12 }

func (c *E12CyclotomicSquareCircuit) Define(api frontend.API) error {
	c.A.CyclotomicSquare(api, c.A)
	return nil
}

// E12 Mul
type E12MulCircuit struct{ A, B E12 }

func (c *E12MulCircuit) Define(api frontend.API) error {
	c.A.Mul(api, c.A, c.B)
	return nil
}

// E12 MulBy034
type E12MulBy034Circuit struct {
	A      E12
	C3, C4 E2
}

func (c *E12MulBy034Circuit) Define(api frontend.API) error {
	c.A.MulBy034(api, c.C3, c.C4)
	return nil
}

// E6 Square (for torus comparison)
type E6SquareCircuit struct{ A E6 }

func (c *E6SquareCircuit) Define(api frontend.API) error {
	c.A.Square(api, c.A)
	return nil
}

// E6 Mul
type E6MulCircuit struct{ A, B E6 }

func (c *E6MulCircuit) Define(api frontend.API) error {
	c.A.Mul(api, c.A, c.B)
	return nil
}

func TestCompareOperationCosts(t *testing.T) {
	circuits := []struct {
		name    string
		circuit frontend.Circuit
	}{
		{"E12.Square (dense)", &E12SquareCircuit{}},
		{"E12.CyclotomicSquare", &E12CyclotomicSquareCircuit{}},
		{"E12.Mul", &E12MulCircuit{}},
		{"E12.MulBy034", &E12MulBy034Circuit{}},
		{"E6.Square", &E6SquareCircuit{}},
		{"E6.Mul", &E6MulCircuit{}},
	}

	fmt.Println("=== Native BLS12-377 Operation Costs (SCS) ===")
	for _, c := range circuits {
		ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c.circuit)
		fmt.Printf("%-25s: %d constraints\n", c.name, ccs.GetNbConstraints())
	}
}
