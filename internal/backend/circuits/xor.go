package circuits

import (
	"github.com/consensys/gnark/frontend"
)

// one input is constant
type xorCircuitVarCst struct {
	Op      frontend.Variable
	XorOne  frontend.Variable `gnark:",public"`
	XorZero frontend.Variable `gnark:",public"`
}

func (circuit *xorCircuitVarCst) Define(api frontend.API) error {
	a := api.Xor(circuit.Op, 1)
	b := api.Xor(circuit.Op, 0)
	c := api.Xor(1, circuit.Op)
	d := api.Xor(0, circuit.Op)
	api.AssertIsEqual(a, circuit.XorOne)
	api.AssertIsEqual(b, circuit.XorZero)
	api.AssertIsEqual(c, circuit.XorOne)
	api.AssertIsEqual(d, circuit.XorZero)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&xorCircuitVarCst{
			Op:      1,
			XorOne:  0,
			XorZero: 1,
		},
		&xorCircuitVarCst{
			Op:      (0),
			XorOne:  (1),
			XorZero: (0),
		},
	}

	bad := []frontend.Circuit{
		&xorCircuitVarCst{
			Op:      0,
			XorOne:  0,
			XorZero: 1,
		},
		&xorCircuitVarCst{
			Op:      (1),
			XorOne:  (1),
			XorZero: (0),
		},
	}

	addNewEntry("xorCstVar", &xorCircuitVarCst{}, good, bad, nil)

}

// both inputs are variable
type xorCircuit struct {
	Op1, Op2, Res frontend.Variable
}

func (circuit *xorCircuit) Define(api frontend.API) error {
	d := api.Xor(circuit.Op1, circuit.Op2)

	api.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&xorCircuit{
			Op1: 1,
			Op2: 1,
			Res: 0,
		},
		&xorCircuit{
			Op1: 1,
			Op2: 0,
			Res: 1,
		},
		&xorCircuit{
			Op1: 0,
			Op2: 1,
			Res: 1,
		},
		&xorCircuit{
			Op1: 0,
			Op2: 0,
			Res: 0,
		},
	}

	bad := []frontend.Circuit{
		&xorCircuit{
			Op1: 1,
			Op2: 1,
			Res: 1,
		},
		&xorCircuit{
			Op1: 1,
			Op2: 0,
			Res: 0,
		},
		&xorCircuit{
			Op1: 0,
			Op2: 1,
			Res: 0,
		},
		&xorCircuit{
			Op1: 0,
			Op2: 0,
			Res: 1,
		},
		&xorCircuit{
			Op1: (42),
			Op2: 1,
			Res: 1,
		},
		&xorCircuit{
			Op1: 1,
			Op2: 1,
			Res: (42),
		},
	}

	addNewEntry("xor", &xorCircuit{}, good, bad, nil)
}
