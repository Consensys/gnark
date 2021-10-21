package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type subCircuit struct {
	Op1, Op2, Res frontend.Variable
}

func (circuit *subCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	d := cs.Sub(circuit.Op1, circuit.Op2, circuit.Op2)

	cs.AssertIsEqual(d, circuit.Res)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&subCircuit{
			Op1: frontend.Value(7),
			Op2: frontend.Value(3),
			Res: frontend.Value(1),
		},
		&subCircuit{
			Op1: frontend.Value(6),
			Op2: frontend.Value(3),
			Res: frontend.Value(0),
		},
	}

	bad := []frontend.Circuit{
		&subCircuit{
			Op1: frontend.Value(2),
			Op2: frontend.Value(3),
			Res: frontend.Value(5),
		},
	}

	addNewEntry("sub", &subCircuit{}, good, bad)
}
