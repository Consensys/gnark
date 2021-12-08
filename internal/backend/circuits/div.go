package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type divCircuit struct {
	A, B cs.Variable
	C    cs.Variable `gnark:",public"`
}

func (circuit *divCircuit) Define(api frontend.API) error {
	c := api.Div(circuit.A, circuit.B)
	d := api.Div(2387287246, circuit.B)
	e := api.Div(circuit.A, 987342642)
	api.AssertIsEqual(c, circuit.C)
	api.AssertIsEqual(d, circuit.C)
	api.AssertIsEqual(e, circuit.C)
	return nil
}

func init() {

	var good, bad divCircuit

	a := big.NewInt(2387287246)
	b := big.NewInt(987342642)
	m := ecc.BLS12_377.Info().Fp.Modulus()
	var c big.Int
	c.ModInverse(b, m).Mul(&c, a)

	good.A = a
	good.B = b
	good.C = c

	bad.A = a
	bad.B = b
	bad.C = 1

	addEntry("div", &divCircuit{}, &good, &bad, []ecc.ID{ecc.BW6_761})
}
