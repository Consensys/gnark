package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type andCircuit struct {
	Op1, Op2, Res frontend.Variable
}

func (circuit *andCircuit) Define(api frontend.API) error {
	d := api.And(circuit.Op1, circuit.Op2)

	api.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&andCircuit{
			Op1: (1),
			Op2: (1),
			Res: (1),
		},
		&andCircuit{
			Op1: (1),
			Op2: (0),
			Res: (0),
		},
		&andCircuit{
			Op1: (0),
			Op2: (1),
			Res: (0),
		},
		&andCircuit{
			Op1: (0),
			Op2: (0),
			Res: (0),
		},
	}

	bad := []frontend.Circuit{
		&andCircuit{
			Op1: (1),
			Op2: (1),
			Res: (0),
		},
		&andCircuit{
			Op1: (1),
			Op2: (0),
			Res: (1),
		},
		&andCircuit{
			Op1: (0),
			Op2: (1),
			Res: (1),
		},
		&andCircuit{
			Op1: (0),
			Op2: (0),
			Res: (1),
		},
		&andCircuit{
			Op1: (42),
			Op2: (1),
			Res: (1),
		},
		&andCircuit{
			Op1: (1),
			Op2: (1),
			Res: (42),
		},
	}

	addNewEntry("and", &andCircuit{}, good, bad, nil)
}
