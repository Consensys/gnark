package arith

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type divmodCircuit struct {
	Div                   uint
	In, Quotient, Modulus frontend.Variable
}

func (c *divmodCircuit) Define(api frontend.API) error {
	quotient, modulus := DivMod(api, c.In, c.Div)
	api.AssertIsEqual(quotient, c.Quotient)
	api.AssertIsEqual(modulus, c.Modulus)
	return nil
}

func TestDivMod(t *testing.T) {
	assert := test.NewAssert(t)
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &divmodCircuit{Div: 0})
	assert.Error(err)

	assert.ProverSucceeded(&divmodCircuit{Div: 1}, &divmodCircuit{In: 0, Quotient: 0, Modulus: 0})
	assert.ProverSucceeded(&divmodCircuit{Div: 2}, &divmodCircuit{In: 1, Quotient: 0, Modulus: 1})
	assert.ProverSucceeded(&divmodCircuit{Div: 3}, &divmodCircuit{In: 5, Quotient: 1, Modulus: 2})

	assert.ProverSucceeded(&divmodCircuit{Div: 4}, &divmodCircuit{In: 8, Quotient: 2, Modulus: 0})
	assert.ProverFailed(&divmodCircuit{Div: 4}, &divmodCircuit{In: 8, Quotient: 1, Modulus: 4})
}
