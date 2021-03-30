package exponentiate

import (
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/ecc"
)

func TestExponentiate(t *testing.T) {

	assert := groth16.NewAssert(t)

	var expCircuit Circuit
	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &expCircuit)
	if err != nil {
		t.Fatal(err)
	}

	{
		var witness Circuit
		witness.X.Assign(2)
		witness.E.Assign(12)
		witness.Y.Assign(4095)
		assert.ProverFailed(r1cs, &witness) // y != x**e
	}

	{
		var witness Circuit
		witness.X.Assign(2)
		witness.E.Assign(12)
		witness.Y.Assign(4096)
		assert.ProverSucceeded(r1cs, &witness)
	}

}
