package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type addCircuit struct {
	Op1, Op2, Res cs.Variable
}

func (circuit *addCircuit) Define(api frontend.API) error {
	d := api.Add(circuit.Op1, circuit.Op2, circuit.Op1)

	api.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&addCircuit{
			Op1: (2),
			Op2: (3),
			Res: (7),
		},
	}

	bad := []frontend.Circuit{
		&addCircuit{
			Op1: (2),
			Op2: (3),
			Res: (5),
		},
	}

	addNewEntry("add", &addCircuit{}, good, bad)
}
