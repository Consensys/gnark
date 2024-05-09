package gnark_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------------------------------------------
// test println (non regression)
type printlnCircuit struct {
	A, B frontend.Variable
}

func (circuit *printlnCircuit) Define(api frontend.API) error {
	c := api.Add(circuit.A, circuit.B)
	api.Println(c, "is the addition")
	d := api.Mul(circuit.A, c)
	api.Println(d, new(big.Int).SetInt64(42))
	bs := api.ToBinary(circuit.B, 10)
	api.Println("bits", bs[3])
	api.Println("circuit", circuit)
	nb := api.Mul(bs[1], 2)
	api.AssertIsBoolean(nb) // this will fail
	m := api.Mul(circuit.A, circuit.B)
	api.Println("m", m) // this should not be resolved
	return nil
}

func TestPrintln(t *testing.T) {
	assert := require.New(t)

	var circuit, witness printlnCircuit
	witness.A = 2
	witness.B = 11

	var expected bytes.Buffer
	expected.WriteString("debug_test.go:30 > 13 is the addition\n")
	expected.WriteString("debug_test.go:32 > 26 42\n")
	expected.WriteString("debug_test.go:34 > bits 1\n")
	expected.WriteString("debug_test.go:35 > circuit {A: 2, B: 11}\n")
	expected.WriteString("debug_test.go:39 > m .*\n")

	{
		trace, _ := getGroth16Trace(&circuit, &witness)
		assert.Regexp(expected.String(), trace)
	}

	{
		trace, _ := getPlonkTrace(&circuit, &witness)
		assert.Regexp(expected.String(), trace)
	}
}

// -------------------------------------------------------------------------------------------------
// Div by 0
type divBy0Trace struct {
	A, B, C frontend.Variable
}

func (circuit *divBy0Trace) Define(api frontend.API) error {
	d := api.Add(circuit.B, circuit.C)
	api.Div(circuit.A, d)
	return nil
}

func TestTraceDivBy0(t *testing.T) {
	assert := require.New(t)

	var circuit, witness divBy0Trace
	witness.A = 2
	witness.B = -2
	witness.C = 2

	{
		_, err := getGroth16Trace(&circuit, &witness)
		assert.Error(err)
		assert.Contains(err.Error(), "constraint #0 is not satisfied: [div] 2/0 == <unsolved>")
		assert.Contains(err.Error(), "(*divBy0Trace).Define")
		assert.Contains(err.Error(), "debug_test.go:")
	}

	{
		_, err := getPlonkTrace(&circuit, &witness)
		assert.Error(err)
		if debug.Debug {
			assert.Contains(err.Error(), "constraint #1 is not satisfied: [inverse] 1/0 < ∞")
			assert.Contains(err.Error(), "(*divBy0Trace).Define")
			assert.Contains(err.Error(), "debug_test.go:")
		} else {
			assert.Contains(err.Error(), "constraint #1 is not satisfied: division by 0")
		}

	}
}

// -------------------------------------------------------------------------------------------------
// Not Equal
type notEqualTrace struct {
	A, B, C frontend.Variable
}

func (circuit *notEqualTrace) Define(api frontend.API) error {
	d := api.Add(circuit.B, circuit.C)
	api.AssertIsEqual(circuit.A, d)
	return nil
}

func TestTraceNotEqual(t *testing.T) {
	assert := require.New(t)

	var circuit, witness notEqualTrace
	witness.A = 1
	witness.B = 24
	witness.C = 42

	{
		_, err := getGroth16Trace(&circuit, &witness)
		assert.Error(err)
		if debug.Debug {
			assert.Contains(err.Error(), "constraint #0 is not satisfied: [assertIsEqual] 1 == 66")
			assert.Contains(err.Error(), "(*notEqualTrace).Define")
			assert.Contains(err.Error(), "debug_test.go:")
		} else {
			assert.Contains(err.Error(), "constraint #0 is not satisfied: 1 ⋅ 1 != 66")
		}
	}

	{
		_, err := getPlonkTrace(&circuit, &witness)
		assert.Error(err)
		if debug.Debug {
			assert.Contains(err.Error(), "constraint #1 is not satisfied: [assertIsEqual] 1 == 66")
			assert.Contains(err.Error(), "(*notEqualTrace).Define")
			assert.Contains(err.Error(), "debug_test.go:")
		} else {
			assert.Contains(err.Error(), "constraint #1 is not satisfied: qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → 1 + -66 + 0 + 0 + 0 != 0")
		}

	}
}

func getPlonkTrace(circuit, w frontend.Circuit) (string, error) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return "", err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		return "", err
	}

	pk, _, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	sw, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return "", err
	}
	log := zerolog.New(&zerolog.ConsoleWriter{Out: &buf, NoColor: true, PartsExclude: []string{zerolog.LevelFieldName, zerolog.TimestampFieldName}})
	_, err = plonk.Prove(ccs, pk, sw, backend.WithSolverOptions(solver.WithLogger(log)))
	return buf.String(), err
}

func getGroth16Trace(circuit, w frontend.Circuit) (string, error) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return "", err
	}

	pk, err := groth16.DummySetup(ccs)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	sw, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return "", err
	}
	log := zerolog.New(&zerolog.ConsoleWriter{Out: &buf, NoColor: true, PartsExclude: []string{zerolog.LevelFieldName, zerolog.TimestampFieldName}})
	_, err = groth16.Prove(ccs, pk, sw, backend.WithSolverOptions(solver.WithLogger(log)))
	return buf.String(), err
}
