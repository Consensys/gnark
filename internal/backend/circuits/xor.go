package circuits

import (
	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// one input is constant
type XorCircuitVarCst struct {
	Op      frontend.Variable
	XorOne  frontend.Variable `gnark:",public"`
	XorZero frontend.Variable `gnark:",public"`
}

func (circuit *XorCircuitVarCst) Define(api frontend.API) error {
	a := api.Xor(circuit.Op, 1)
	b := api.Xor(circuit.Op, 0)
	api.AssertIsEqual(a, circuit.XorOne)
	api.AssertIsEqual(b, circuit.XorZero)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&XorCircuitVarCst{
			Op:      (1),
			XorOne:  (0),
			XorZero: (1),
		},
		&XorCircuitVarCst{
			Op:      (0),
			XorOne:  (1),
			XorZero: (1),
		},
	}

	bad := []frontend.Circuit{
		&XorCircuitVarCst{
			Op:      (0),
			XorOne:  (0),
			XorZero: (1),
		},
		&XorCircuitVarCst{
			Op:      (1),
			XorOne:  (1),
			XorZero: (1),
		},
	}

	addNewEntry("xorCstVar", &xorCircuit{}, good, bad, []ecc.ID{ecc.BN254})

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
			Op1: (1),
			Op2: (1),
			Res: (0),
		},
		&xorCircuit{
			Op1: (1),
			Op2: (0),
			Res: (1),
		},
		&xorCircuit{
			Op1: (0),
			Op2: (1),
			Res: (1),
		},
		&xorCircuit{
			Op1: (0),
			Op2: (0),
			Res: (0),
		},
	}

	bad := []frontend.Circuit{
		&xorCircuit{
			Op1: (1),
			Op2: (1),
			Res: (1),
		},
		&xorCircuit{
			Op1: (1),
			Op2: (0),
			Res: (0),
		},
		&xorCircuit{
			Op1: (0),
			Op2: (1),
			Res: (0),
		},
		&xorCircuit{
			Op1: (0),
			Op2: (0),
			Res: (1),
		},
		&xorCircuit{
			Op1: (42),
			Op2: (1),
			Res: (1),
		},
		&xorCircuit{
			Op1: (1),
			Op2: (1),
			Res: (42),
		},
	}

	addNewEntry("xor", &xorCircuit{}, good, bad, gnark.Curves())
}
