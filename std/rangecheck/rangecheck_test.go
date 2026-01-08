package rangecheck

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type CheckCircuit struct {
	Vals []frontend.Variable
	bits int
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
	nbVals := 100
	bound := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	vals := make([]frontend.Variable, nbVals)
	for i := range vals {
		vals[i], err = rand.Int(rand.Reader, bound)
		assert.NoError(err)
	}
	invalidVals := make([]frontend.Variable, nbVals)
	for i := range invalidVals {
		invalidVals[i], err = rand.Int(rand.Reader, bound)
		assert.NoError(err)
		invalidVals[i] = new(big.Int).Add(invalidVals[i].(*big.Int), bound)
	}
	witness := CheckCircuit{Vals: vals}
	invalidWitness := CheckCircuit{Vals: invalidVals}
	circuit := CheckCircuit{Vals: make([]frontend.Variable, len(vals)), bits: bits}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithInvalidAssignment(&invalidWitness), test.WithSkipSmallfieldCheck())
}

func TestCheckSmallField(t *testing.T) {
	assert := test.NewAssert(t)

	var err error
	bits := 20
	nbVals := 100
	bound := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	vals := make([]frontend.Variable, nbVals)
	for i := range vals {
		vals[i], err = rand.Int(rand.Reader, bound)
		assert.NoError(err)
	}
	invalidVals := make([]frontend.Variable, nbVals)
	for i := range invalidVals {
		invalidVals[i], err = rand.Int(rand.Reader, bound)
		assert.NoError(err)
		invalidVals[i] = new(big.Int).Add(invalidVals[i].(*big.Int), bound)
	}
	witness := CheckCircuit{Vals: vals}
	invalidWitness := CheckCircuit{Vals: invalidVals}
	circuit := CheckCircuit{Vals: make([]frontend.Variable, len(vals)), bits: bits}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithInvalidAssignment(&invalidWitness), test.WithNoCurves(), test.WithSmallfieldCheck())
}
