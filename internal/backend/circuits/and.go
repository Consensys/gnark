package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type andCircuit struct {
	Op1, Op2, Res frontend.Variable
}

func (circuit *andCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	d := cs.And(circuit.Op1, circuit.Op2)

	cs.AssertIsEqual(d, circuit.Res)
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

	addNewEntry("and", &andCircuit{}, good, bad)
}
