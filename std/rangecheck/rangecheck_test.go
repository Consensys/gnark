package rangecheck

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type CheckCircuit struct {
	Vals []frontend.Variable
	bits int
	base int
}

func (c *CheckCircuit) Define(api frontend.API) error {
	r := newCommitRangechecker(api)
	for i := range c.Vals {
		r.Check(c.Vals[i], c.bits)
	}
	return nil
}

func TestCheck(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	bits := 64
	base := 11
	nbVals := 100000
	bound := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	vals := make([]frontend.Variable, nbVals)
	for i := range vals {
		vals[i], err = rand.Int(rand.Reader, bound)
		if err != nil {
			t.Fatal(err)
		}
	}
	witness := CheckCircuit{Vals: vals, bits: bits, base: base}
	circuit := CheckCircuit{Vals: make([]frontend.Variable, len(vals)), bits: bits, base: base}
	err = test.IsSolved(&circuit, &witness, goldilocks.Modulus())
	assert.NoError(err)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log(ccs.GetNbConstraints())
}
