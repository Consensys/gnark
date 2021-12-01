package circuits

import (
	"github.com/consensys/gnark/frontend"
)

// circuit designed to test if plonk compiler recognizes
// correctly constraints of the form a*b=c where a is
// marked as boolean constraint, but the constraint doesn't exist
// (it's the case for the result of a XOR, OR, AND for instance)
type orXoAndMulCircuit struct {
	A, B frontend.Variable
}

func (circuit *orXoAndMulCircuit) Define(cs frontend.API) error {

	a := cs.Xor(circuit.A, circuit.B)
	b := cs.Mul(a, circuit.A)

	c := cs.Or(circuit.A, circuit.B)
	d := cs.Mul(c, circuit.A)

	e := cs.Or(circuit.A, circuit.B)
	f := cs.Mul(e, circuit.A)

	cs.AssertIsBoolean(b)
	cs.AssertIsBoolean(d)
	cs.AssertIsBoolean(f)

	return nil
}

func init() {

	good := []frontend.Circuit{
		&orXoAndMulCircuit{
			A: (1),
			B: (1),
		},
		&orXoAndMulCircuit{
			A: (1),
			B: (0),
		},
		&orXoAndMulCircuit{
			A: (0),
			B: (1),
		},
	}

	bad := []frontend.Circuit{
		&orXoAndMulCircuit{
			A: (0),
			B: (2),
		},
		&orXoAndMulCircuit{
			A: (2),
			B: (0),
		},
		&orXoAndMulCircuit{
			A: (1),
			B: (2),
		},
	}

	addNewEntry("orXoAndMulCircuit", &orXoAndMulCircuit{}, good, bad)
}
