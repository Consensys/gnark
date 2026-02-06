package fields_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// Torus mul by sparse (y0, y1, 0): compress(x*y) = (y_x + y_sparse) / (1 + y_x * y_sparse * v)
// y_sparse = (y0, y1, 0) so y_x * y_sparse uses MulBy01
type TorusMulBy01Circuit struct {
	Yx     E6 // dense accumulator in torus
	Y0, Y1 E2 // sparse line: (y0, y1, 0)
	Result E6 // hinted result
}

func (c *TorusMulBy01Circuit) Define(api frontend.API) error {
	// y_sparse = (y0, y1, 0)
	var ySparse E6
	ySparse.B0 = c.Y0
	ySparse.B1 = c.Y1
	ySparse.B2 = E2{A0: 0, A1: 0}

	// Numerator: y_x + y_sparse
	var num E6
	num.Add(api, c.Yx, ySparse)

	// y_x * y_sparse using MulBy01 (sparse multiplication)
	var prod E6
	prod = c.Yx
	prod.MulBy01(api, c.Y0, c.Y1)

	// Denominator: 1 + prod * v
	var denom E6
	denom.MulByNonResidue(api, prod)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	// Verify: Result * denom = num
	var check E6
	check.Mul(api, c.Result, denom)
	check.AssertIsEqual(api, num)

	return nil
}

// What if we batch: multiply by multiple sparse lines, single verification
// acc_new = acc * prod(lines) where lines are in torus form
type TorusBatchMulBy01Circuit struct {
	Yx     E6
	Lines  [4][2]E2 // 4 sparse lines, each (y0, y1)
	Result E6
}

func (c *TorusBatchMulBy01Circuit) Define(api frontend.API) error {
	acc := c.Yx

	for i := 0; i < 4; i++ {
		// y_sparse = (y0, y1, 0)
		var ySparse E6
		ySparse.B0 = c.Lines[i][0]
		ySparse.B1 = c.Lines[i][1]

		// Compute numerator and prod for this line
		var num E6
		num.Add(api, acc, ySparse)

		var prod E6
		prod = acc
		prod.MulBy01(api, c.Lines[i][0], c.Lines[i][1])

		var denom E6
		denom.MulByNonResidue(api, prod)
		denom.B0.A0 = api.Add(denom.B0.A0, 1)

		// Hint intermediate result
		// For now, just chain through (would need hints per step)
		// This is just to measure the "minimum" cost
		acc = num // simplified - in practice needs division verification
	}

	// Single final verification
	c.Result.AssertIsEqual(api, acc)

	return nil
}

func TestTorusSparseOperationCosts(t *testing.T) {
	c1 := &TorusMulBy01Circuit{}
	ccs1, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c1)

	fmt.Println("=== Torus Sparse Multiplication ===")
	fmt.Printf("Torus MulBy01 (dense×sparse): %d constraints\n", ccs1.GetNbConstraints())
	fmt.Println()
	fmt.Println("=== Comparison ===")
	fmt.Printf("Torus Mul (dense×dense):      169 constraints\n")
	fmt.Printf("E12.MulBy034:                 131 constraints\n")
	fmt.Printf("E6.MulBy01:                   ~50 constraints\n")
}
