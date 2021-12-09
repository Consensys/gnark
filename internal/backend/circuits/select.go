package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type selectCircuit struct {
	A1, A2, B, C cs.Variable
}

func (circuit *selectCircuit) Define(api frontend.API) error {
	a := api.Select(circuit.A1, circuit.B, circuit.C)
	b := api.Select(circuit.A2, circuit.B, circuit.C)
	c := api.Select(circuit.A1, circuit.B, 3)
	d := api.Select(circuit.A2, circuit.B, 3)
	e := api.Select(circuit.A1, 4, circuit.C)
	f := api.Select(circuit.A2, 4, circuit.C)
	api.AssertIsEqual(a, circuit.B)
	api.AssertIsEqual(b, circuit.C)
	api.AssertIsEqual(c, circuit.B)
	api.AssertIsEqual(d, 3)
	api.AssertIsEqual(e, 4)
	api.AssertIsEqual(f, circuit.C)
	return nil
}

func init() {

	var good, bad selectCircuit

	a := big.NewInt(2387287246)
	b := big.NewInt(987342642)
	m := ecc.BLS12_377.Info().Fp.Modulus()
	var c big.Int
	c.ModInverse(b, m).Mul(&c, a)

	good.A1 = 1
	good.A2 = 0
	good.B = 12323
	good.C = 83723

	bad.A1 = 0
	bad.A2 = 1
	bad.B = 12323
	bad.C = 83723

	addEntry("select", &selectCircuit{}, &good, &bad, []ecc.ID{ecc.BW6_761})
}
