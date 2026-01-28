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

// Test circuits for baseLength option

type baseLengthNoOptionCircuit struct {
	Val frontend.Variable
}

func (c *baseLengthNoOptionCircuit) Define(api frontend.API) error {
	rc := newCommitRangechecker(api)
	rc.Check(c.Val, 64)
	if rc.cfg.baseLength != 0 {
		panic("expected baseLength to be 0 when no option is set")
	}
	return nil
}

type baseLengthNoOptionThenOptionCircuit struct {
	Val frontend.Variable
}

func (c *baseLengthNoOptionThenOptionCircuit) Define(api frontend.API) error {
	rc1 := newCommitRangechecker(api)
	rc1.Check(c.Val, 64)
	rc2 := newCommitRangechecker(api, WithBaseLength(10))
	rc2.Check(c.Val, 64)
	// after second call with option, baseLength should be updated to 10
	if rc1.cfg.baseLength != 10 {
		panic("expected first checker baseLength to be 10 after second call with option")
	}
	if rc2.cfg.baseLength != 10 {
		panic("expected second checker baseLength to be 10")
	}
	return nil
}

type baseLengthOptionThenNoOptionCircuit struct {
	Val frontend.Variable
}

func (c *baseLengthOptionThenNoOptionCircuit) Define(api frontend.API) error {
	rc1 := newCommitRangechecker(api, WithBaseLength(8))
	rc1.Check(c.Val, 64)
	rc2 := newCommitRangechecker(api)
	rc2.Check(c.Val, 64)
	// second call without option should not override the first option
	if rc1.cfg.baseLength != 8 {
		panic("expected first checker baseLength to remain 8")
	}
	if rc2.cfg.baseLength != 8 {
		panic("expected second checker baseLength to be 8")
	}
	return nil
}

type baseLengthOptionThenOptionCircuit struct {
	Val frontend.Variable
}

func (c *baseLengthOptionThenOptionCircuit) Define(api frontend.API) error {
	rc1 := newCommitRangechecker(api, WithBaseLength(6))
	rc1.Check(c.Val, 64)
	rc2 := newCommitRangechecker(api, WithBaseLength(12))
	rc2.Check(c.Val, 64)
	// second option should override the first
	if rc1.cfg.baseLength != 12 {
		panic("expected first checker baseLength to be 12 after second call with option")
	}
	if rc2.cfg.baseLength != 12 {
		panic("expected second checker baseLength to be 12")
	}
	return nil
}

func TestBaseLengthOption(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		circuit := &baseLengthNoOptionCircuit{Val: 0}
		witness := &baseLengthNoOptionCircuit{Val: 42}
		_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		assert.NoError(err)
		// also check with witness to make sure circuit compiles correctly
		assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
	}, "firstOption=none", "secondOption=none")

	assert.Run(func(assert *test.Assert) {
		circuit := &baseLengthNoOptionThenOptionCircuit{Val: 0}
		witness := &baseLengthNoOptionThenOptionCircuit{Val: 42}
		_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		assert.NoError(err)
		assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
	}, "firstOption=none", "secondOption=10")

	assert.Run(func(assert *test.Assert) {
		circuit := &baseLengthOptionThenNoOptionCircuit{Val: 0}
		witness := &baseLengthOptionThenNoOptionCircuit{Val: 42}
		_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		assert.NoError(err)
		assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
	}, "firstOption=8", "secondOption=none")

	assert.Run(func(assert *test.Assert) {
		circuit := &baseLengthOptionThenOptionCircuit{Val: 0}
		witness := &baseLengthOptionThenOptionCircuit{Val: 42}
		_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		assert.NoError(err)
		assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
	}, "firstOption=6", "secondOption=12")
}
