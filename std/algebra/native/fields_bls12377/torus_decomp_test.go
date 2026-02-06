package fields_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// Torus decompression using E12 multiplication with sparse element
type TorusDecompressCircuit struct {
	Y      E6  // torus representation
	Result E12 // decompressed E12 element (hinted)
}

func (c *TorusDecompressCircuit) Define(api frontend.API) error {
	// Verify: Result * (1 - y*w) = (1 + y*w) in E12
	// where w generates E12 over E6

	// For E12 = E6 + E6*w:
	// (a + b*w) * (1 - y*w) = a - b*y*v + (b - a*y)*w
	// Should equal 1 + y*w
	// So: a - b*y*v = 1 and b - a*y = y

	// Compute Result.C0 - Result.C1*Y*v (where v is non-residue)
	var tmp E6
	tmp.Mul(api, c.Result.C1, c.Y)
	tmp.MulByNonResidue(api, tmp)

	var lhs0 E6
	lhs0.Sub(api, c.Result.C0, tmp)

	// Compute Result.C1 - Result.C0*Y
	var tmp2 E6
	tmp2.Mul(api, c.Result.C0, c.Y)

	var lhs1 E6
	lhs1.Sub(api, c.Result.C1, tmp2)

	// Check lhs0 = 1
	var one E6
	one.SetOne()
	lhs0.AssertIsEqual(api, one)

	// Check lhs1 = Y
	lhs1.AssertIsEqual(api, c.Y)

	return nil
}

func TestTorusDecompressionCost(t *testing.T) {
	c1 := &TorusDecompressCircuit{}
	ccs1, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c1)

	fmt.Println("=== Torus Decompression ===")
	fmt.Printf("Torus Decompress (E6→E12): %d constraints\n", ccs1.GetNbConstraints())
}
