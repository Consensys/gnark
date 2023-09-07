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

func (circuit *orXoAndMulCircuit) Define(api frontend.API) error {

	a := api.Xor(circuit.A, circuit.B)
	b := api.Mul(a, circuit.A)

	c := api.Or(circuit.A, circuit.B)
	d := api.Mul(c, circuit.A)

	e := api.Or(circuit.A, circuit.B)
	f := api.Mul(e, circuit.A)

	api.AssertIsBoolean(b)
	api.AssertIsBoolean(d)
	api.AssertIsBoolean(f)

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

	addNewEntry("orXoAndMulCircuit", &orXoAndMulCircuit{}, good, bad, nil)
}
