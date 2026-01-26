package rangecheck

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithInvalidAssignment(&invalidWitness), test.WithoutSmallfieldCheck())
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithInvalidAssignment(&invalidWitness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func BenchmarkRangecheckConstraints(b *testing.B) {
	bits := 64
	nbVals := 100

	circuit := CheckCircuit{Vals: make([]frontend.Variable, nbVals), bits: bits}

	// Compile for R1CS
	r1csCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}

	// Compile for PLONK (SCS)
	scsCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportMetric(float64(r1csCS.GetNbConstraints()), "R1CS_constraints")
	b.ReportMetric(float64(scsCS.GetNbConstraints()), "PLONK_constraints")
	b.ReportMetric(float64(r1csCS.GetNbConstraints())/float64(nbVals), "R1CS_constraints/val")
	b.ReportMetric(float64(scsCS.GetNbConstraints())/float64(nbVals), "PLONK_constraints/val")
}
