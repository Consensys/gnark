package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type addCircuit struct {
	Op1, Op2, Res frontend.Variable
}

func (circuit *addCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	d := cs.Add(circuit.Op1, circuit.Op2, circuit.Op1)

	cs.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&addCircuit{
			Op1: frontend.Value(2),
			Op2: frontend.Value(3),
			Res: frontend.Value(7),
		},
	}

	bad := []frontend.Circuit{
		&addCircuit{
			Op1: frontend.Value(2),
			Op2: frontend.Value(3),
			Res: frontend.Value(5),
		},
	}

	addNewEntry("add", &addCircuit{}, good, bad)
}
