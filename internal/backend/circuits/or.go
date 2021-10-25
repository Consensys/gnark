package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type orCircuit struct {
	Op1, Op2, Res frontend.Variable
}

func (circuit *orCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	d := cs.Or(circuit.Op1, circuit.Op2)

	cs.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&orCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(1),
			Res: frontend.Value(1),
		},
		&orCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(0),
			Res: frontend.Value(1),
		},
		&orCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(1),
			Res: frontend.Value(1),
		},
		&orCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(0),
			Res: frontend.Value(0),
		},
	}

	bad := []frontend.Circuit{
		&orCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(1),
			Res: frontend.Value(0),
		},
		&orCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(0),
			Res: frontend.Value(0),
		},
		&orCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(1),
			Res: frontend.Value(0),
		},
		&orCircuit{
			Op1: frontend.Value(0),
			Op2: frontend.Value(0),
			Res: frontend.Value(1),
		},
		&orCircuit{
			Op1: frontend.Value(42),
			Op2: frontend.Value(1),
			Res: frontend.Value(1),
		},
		&orCircuit{
			Op1: frontend.Value(1),
			Op2: frontend.Value(1),
			Res: frontend.Value(42),
		},
	}

	addNewEntry("or", &orCircuit{}, good, bad)
}
