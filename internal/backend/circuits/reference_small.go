package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

const nbConstraintsRefSmall = 5

type referenceSmallCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *referenceSmallCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	for i := 0; i < nbConstraintsRefSmall; i++ {
		circuit.X = cs.Mul(circuit.X, circuit.X)
	}
	cs.MustBeEqual(circuit.X, circuit.Y)
	return nil
}

func init() {
	var circuit, good, bad referenceSmallCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.X.Assign(2)

	// compute expected Y
	var expectedY big.Int
	expectedY.SetUint64(2)

	for i := 0; i < nbConstraintsRefSmall; i++ {
		expectedY.Mul(&expectedY, &expectedY)
	}

	good.Y.Assign(expectedY)

	bad.X.Assign(2)
	bad.Y.Assign(0)

	addEntry("reference_small", r1cs, &good, &bad)
}
