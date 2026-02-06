package fields_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// Division by sparse element using hint
type DivBy034Circuit struct {
	Acc    E12 // dense accumulator
	C3, C4 E2  // sparse line coefficients
	Result E12 // hinted result (will be verified)
}

func (c *DivBy034Circuit) Define(api frontend.API) error {
	// Verify: Result × l = Acc where l = (1, 0, 0, c3, c4, 0)
	// This checks Result = Acc / l
	var check E12
	check = c.Result
	check.MulBy034(api, c.C3, c.C4)
	check.AssertIsEqual(api, c.Acc)
	return nil
}

// Full cyclotomic line multiplication: acc × conj(l) / l
type CyclotomicLineMulCircuit struct {
	Acc    E12
	C3, C4 E2  // line coefficients
	AccNew E12 // hinted result
}

func (c *CyclotomicLineMulCircuit) Define(api frontend.API) error {
	// conj(l) has coefficients (-c3, -c4) in the C1 part
	var conjC3, conjC4 E2
	conjC3.Neg(api, c.C3)
	conjC4.Neg(api, c.C4)

	// t = acc × conj(l)
	var t E12
	t = c.Acc
	t.MulBy034(api, conjC3, conjC4)

	// Verify: accNew × l = t (i.e., accNew = t / l = acc × conj(l) / l)
	var check E12
	check = c.AccNew
	check.MulBy034(api, c.C3, c.C4)
	check.AssertIsEqual(api, t)

	return nil
}

func TestCyclotomicLineCost(t *testing.T) {
	// Just division verification
	c1 := &DivBy034Circuit{}
	ccs1, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c1)

	// Full cyclotomic line mul
	c2 := &CyclotomicLineMulCircuit{}
	ccs2, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, c2)

	fmt.Println("=== Cyclotomic Line Multiplication Costs ===")
	fmt.Printf("DivBy034 verification:    %d constraints\n", ccs1.GetNbConstraints())
	fmt.Printf("Full cyclotomic line mul: %d constraints\n", ccs2.GetNbConstraints())
	fmt.Printf("Current MulBy034:         131 constraints\n")
	fmt.Printf("Overhead per line:        %d constraints\n", ccs2.GetNbConstraints()-131)
}
