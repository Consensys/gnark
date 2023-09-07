package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type orCircuit struct {
	Op1, Op2, Res frontend.Variable
}

func (circuit *orCircuit) Define(api frontend.API) error {
	d := api.Or(circuit.Op1, circuit.Op2)

	api.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&orCircuit{
			Op1: (1),
			Op2: (1),
			Res: (1),
		},
		&orCircuit{
			Op1: (1),
			Op2: (0),
			Res: (1),
		},
		&orCircuit{
			Op1: (0),
			Op2: (1),
			Res: (1),
		},
		&orCircuit{
			Op1: (0),
			Op2: (0),
			Res: (0),
		},
	}

	bad := []frontend.Circuit{
		&orCircuit{
			Op1: (1),
			Op2: (1),
			Res: (0),
		},
		&orCircuit{
			Op1: (1),
			Op2: (0),
			Res: (0),
		},
		&orCircuit{
			Op1: (0),
			Op2: (1),
			Res: (0),
		},
		&orCircuit{
			Op1: (0),
			Op2: (0),
			Res: (1),
		},
		&orCircuit{
			Op1: (42),
			Op2: (1),
			Res: (1),
		},
		&orCircuit{
			Op1: (1),
			Op2: (1),
			Res: (42),
		},
	}

	addNewEntry("or", &orCircuit{}, good, bad, nil)
}
