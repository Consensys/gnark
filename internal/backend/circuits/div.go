package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type divCircuit struct {
	A, B frontend.Variable
	C    frontend.Variable `gnark:",public"`
}

func (circuit *divCircuit) Define(api frontend.API) error {
	c := api.DivUnchecked(circuit.A, circuit.B)
	d := api.DivUnchecked(2387287246, circuit.B)
	e := api.DivUnchecked(circuit.A, 987342642)
	api.AssertIsEqual(c, circuit.C)
	api.AssertIsEqual(d, circuit.C)
	api.AssertIsEqual(e, circuit.C)
	return nil
}

func init() {

	var good, bad divCircuit

	a := big.NewInt(2387287246)
	b := big.NewInt(987342642)
	m := ecc.BN254.ScalarField()
	var c big.Int
	c.ModInverse(b, m).Mul(&c, a)
	c.Mod(&c, m)

	// good.A = a
	good.A = a
	good.B = b
	good.C = c

	// bad.A = a
	bad.A = a
	bad.B = b
	bad.C = 1

	addEntry("div", &divCircuit{}, &good, &bad, []ecc.ID{ecc.BN254})
}
