package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type invCircuit struct {
	A frontend.Variable
	C frontend.Variable `gnark:",public"`
}

func (circuit *invCircuit) Define(api frontend.API) error {
	d := api.Inverse(circuit.A)
	e := api.Inverse(2387287246)
	api.AssertIsEqual(d, circuit.C)
	api.AssertIsEqual(e, circuit.C)
	return nil
}

func init() {

	var good, bad invCircuit

	a := big.NewInt(2387287246)
	m := ecc.BN254.ScalarField()
	var c big.Int
	c.ModInverse(a, m)

	good.A = a
	good.C = c

	bad.A = a
	bad.C = 1

	addEntry("inv", &invCircuit{}, &good, &bad, []ecc.ID{ecc.BN254})
}
