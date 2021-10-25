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
			Op1: frontend.Value(1),
			Op2: frontend.Value(1),
			Res: frontend.Value(1),
		},
		&andCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(0),
			Res: frontend.Value(0),
		},
		&andCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(1),
			Res: frontend.Value(0),
		},
		&andCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(0),
			Res: frontend.Value(0),
		},
	}

	bad := []frontend.Circuit{
		&andCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(1),
			Res: frontend.Value(0),
		},
		&andCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(0),
			Res: frontend.Value(1),
		},
		&andCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(1),
			Res: frontend.Value(1),
		},
		&andCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(0),
			Res: frontend.Value(1),
		},
		&andCircuit{
			Op1: frontend.Value(42),
			Op2: frontend.Value(1),
			Res: frontend.Value(1),
		},
		&andCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(1),
			Res: frontend.Value(42),
		},
	}

	addNewEntry("and", &andCircuit{}, good, bad)
}
