package fields_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// Torus multiplication: compress(x*y) = (y_x + y_y) / (1 + y_x * y_y * v)
type TorusMulCircuit struct {
	Yx, Yy E6
	Result E6
}

func (c *TorusMulCircuit) Define(api frontend.API) error {
	var num E6
	num.Add(api, c.Yx, c.Yy)

	var prod E6
	prod.Mul(api, c.Yx, c.Yy)

	var denom E6
	denom.MulByNonResidue(api, prod)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	var check E6
	check.Mul(api, c.Result, denom)
	check.AssertIsEqual(api, num)

	return nil
}

// Torus squaring: compress(x^2) = 2*y / (1 + y^2 * v)
type TorusSquareCircuit struct {
	Y      E6
	Result E6
}

func (c *TorusSquareCircuit) Define(api frontend.API) error {
	var num E6
	num.Double(api, c.Y)

	var ySq E6
	ySq.Square(api, c.Y)

	var denom E6
	denom.MulByNonResidue(api, ySq)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	var check E6
	check.Mul(api, c.Result, denom)
	check.AssertIsEqual(api, num)

	return nil
}

func TestTorusOperationCosts(t *testing.T) {
	c1 := &TorusMulCircuit{}
	ccs1, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c1)

	c3 := &TorusSquareCircuit{}
	ccs3, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c3)

	fmt.Println("=== Torus Operation Costs (E6) ===")
	fmt.Printf("Torus Mul (dense×dense):  %d constraints\n", ccs1.GetNbConstraints())
	fmt.Printf("Torus Square:             %d constraints\n", ccs3.GetNbConstraints())
	fmt.Println()
	fmt.Println("=== For comparison (E12) ===")
	fmt.Printf("E12.Square (dense):       180 constraints\n")
	fmt.Printf("E12.CyclotomicSquare:     93 constraints\n")
	fmt.Printf("E12.MulBy034:             131 constraints\n")
	fmt.Printf("E6.Square:                44 constraints\n")
	fmt.Printf("E6.Mul:                   78 constraints\n")
}
