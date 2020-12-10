package frontend

import (
	"fmt"
	"testing"
)

func TestReduce(t *testing.T) {

	cs := newConstraintSystem()
	x := cs.newInternalVariable()
	y := cs.newInternalVariable()
	z := cs.newInternalVariable()

	a := cs.Mul(x, 3)
	b := cs.Mul(x, 5)
	c := cs.Mul(y, 10)
	d := cs.Mul(y, 11)
	e := cs.Mul(z, 2)
	f := cs.Mul(z, 2)

	toTest := cs.Add(a, b, c, d, e, f)

	// check sizes
	if len(toTest.linExp) != 3 {
		t.Fatal("Error reduce, duplicate variables not collapsed")
	}

	// check coefficients
	for _, t := range toTest.linExp {
		fmt.Println(cs.coeffs[t.CoeffID()])
	}
}
