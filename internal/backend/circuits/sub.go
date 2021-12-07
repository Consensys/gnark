package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type subCircuit struct {
	Op1, Op2, Res cs.Variable
}

func (circuit *subCircuit) Define(api frontend.API) error {
	d := api.Sub(circuit.Op1, circuit.Op2, circuit.Op2)

	api.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&subCircuit{
			Op1: (7),
			Op2: (3),
			Res: (1),
		},
		&subCircuit{
			Op1: (6),
			Op2: (3),
			Res: (0),
		},
	}

	bad := []frontend.Circuit{
		&subCircuit{
			Op1: (2),
			Op2: (3),
			Res: (5),
		},
	}

	addNewEntry("sub", &subCircuit{}, good, bad)
}
