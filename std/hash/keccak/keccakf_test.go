//circuit and test  for keccakF in gnark api

package keccak

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// Define declares the circuit's constraints
// StateOut = keccakf(StateIn)
type Circuit struct {
	StateIn  [25]frontend.Variable
	StateOut [25]frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// 1 in uint64

	var binaryStateIn [25][]frontend.Variable
	for i := range circuit.StateIn {
		binaryStateIn[i] = api.ToBinary(circuit.StateIn[i], 64)
	}
	//keccakf in gnark api= KeccakF
	binaryStateOut := KeccakF(api, binaryStateIn)
	var haveSliceStateOut []frontend.Variable
	var wantSliceStateOut []frontend.Variable
	for i := range binaryStateOut {
		haveSliceStateOut = append(haveSliceStateOut, binaryStateOut[i]...)
		wantSliceStateOut = append(wantSliceStateOut, api.ToBinary(circuit.StateOut[i], 64)...)
	}
	haveStateOut := api.FromBinary(haveSliceStateOut...)
	wantStateOut := api.FromBinary(wantSliceStateOut...)

	api.AssertIsEqual(haveStateOut, wantStateOut)

	return nil
}

func TestKeccakf(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit Circuit

	var b [25]uint64
	for i := range circuit.StateIn {
		circuit.StateIn[i] = 1
		b[i] = 1
	}

	assert.SolvingFailed(&circuit, &Circuit{

		StateIn:  circuit.StateIn,
		StateOut: circuit.StateIn,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

	// original keccakf = KeccakF1600 (from Go library)
	bb := KeccakF1600(b)

	for i := range circuit.StateOut {
		circuit.StateOut[i] = bb[i]
		circuit.StateIn[i] = 1
	}
	assert.SolvingSucceeded(&circuit, &Circuit{

		StateIn:  circuit.StateIn,
		StateOut: circuit.StateOut,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}
