package sw_bls24315

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type MuxCircuitTest struct {
	Selector frontend.Variable
	Inputs   [8]G1Affine
	Expected G1Affine
}

func (c *MuxCircuitTest) Define(api frontend.API) error {
	cr, err := NewCurve(api)
	if err != nil {
		return err
	}
	els := make([]*G1Affine, len(c.Inputs))
	for i := range c.Inputs {
		els[i] = &c.Inputs[i]
	}
	res := cr.Mux(c.Selector, els...)
	cr.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMux(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MuxCircuitTest{}
	r := make([]fr_bls24315.Element, len(circuit.Inputs))
	for i := range r {
		r[i].SetRandom()
	}
	selector, _ := rand.Int(rand.Reader, big.NewInt(int64(len(r))))
	expectedR := r[selector.Int64()]
	expected := new(bls24315.G1Affine).ScalarMultiplicationBase(expectedR.BigInt(new(big.Int)))
	witness := MuxCircuitTest{
		Selector: selector,
		Expected: NewG1Affine(*expected),
	}
	for i := range r {
		eli := new(bls24315.G1Affine).ScalarMultiplicationBase(r[i].BigInt(new(big.Int)))
		witness.Inputs[i] = NewG1Affine(*eli)
	}
	err := test.IsSolved(&circuit, &witness, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}
