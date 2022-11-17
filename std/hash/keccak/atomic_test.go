// testing atomic functions ; nXor, nAnd , LeftRotate, nNot
package keccak

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// _________________________________________________________________________
// /////////// Circuit Z == X nXor Y
type XorCircuit struct {
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`

	X frontend.Variable
}

func (circuit *XorCircuit) Define(api frontend.API) error {
	XX := api.ToBinary(circuit.X, 64)
	YY := api.ToBinary(circuit.Y, 64)
	var kapi Kapi
	kapi.api = api
	res := kapi.nXor(XX, YY)
	ZZ := api.FromBinary(res...)
	api.AssertIsEqual(ZZ, circuit.Z)
	return nil
}

/////////////////////////

func TestXor(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit XorCircuit

	assert.SolvingFailed(&circuit, &XorCircuit{
		Y: 1,
		Z: 1,
		X: 1,
	}, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &XorCircuit{
		Y: 7,
		Z: 0,
		X: 7,
	}, test.WithCurves(ecc.BN254))
}

////_______________________________________________________________________________________________________________
// Circuit Y == LeftRotate(X)

type RotateCircuit struct {
	Input  frontend.Variable
	Output frontend.Variable `gnark:",public"`
}

func (circuit RotateCircuit) Define(api frontend.API) error {
	var kapi Kapi
	kapi.api = api
	binaryInput := api.ToBinary(circuit.Input, 64)
	binaryOutput := kapi.LeftRotate(binaryInput, 2)
	output := api.FromBinary(binaryOutput...)
	api.AssertIsEqual(output, circuit.Output)
	return nil
}
func TestRotate(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit RotateCircuit

	assert.SolvingFailed(&circuit, &RotateCircuit{
		Input:  1,
		Output: 1,
	}, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &RotateCircuit{
		Input:  6,
		Output: 24,
	}, test.WithCurves(ecc.BN254))

}

// //_______________________________________________________________________________________________________________
// Circuit Y == nNot(X)
type NotCircuit struct {
	Input  frontend.Variable
	Output frontend.Variable `gnark:",public"`
}

func (circuit NotCircuit) Define(api frontend.API) error {
	var kapi Kapi
	kapi.api = api
	var one uint64 = 18446744073709551615

	kapi.one = one
	binaryInput := api.ToBinary(circuit.Input, 64)
	binaryOutput := kapi.nNot(binaryInput)
	output := api.FromBinary(binaryOutput...)

	api.AssertIsEqual(output, circuit.Output)
	return nil
}

// this test does not pass with PLONK (check the bottom of this file for the exact source of the problem)
func TestNot(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit NotCircuit
	var b uint64 = 18446744073709551613

	assert.SolvingFailed(&circuit, &NotCircuit{
		Input:  3,
		Output: 251,
	})

	assert.SolvingSucceeded(&circuit, &NotCircuit{
		Input:  2,
		Output: b,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}

// //_______________________________________________________________________________________________________________
// /////////// Circuit Z == X nAnd Y
type AndCircuit struct {
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`

	X frontend.Variable
}

func (circuit *AndCircuit) Define(api frontend.API) error {
	XX := api.ToBinary(circuit.X, 64)
	YY := api.ToBinary(circuit.Y, 64)
	var kapi Kapi
	kapi.api = api
	res := kapi.nAnd(XX, YY)
	ZZ := api.FromBinary(res...)
	api.AssertIsEqual(ZZ, circuit.Z)
	return nil
}

/////////////////////////

func TestAnd(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit AndCircuit

	assert.SolvingFailed(&circuit, &AndCircuit{
		Y: 1,
		Z: 1,
		X: 0,
	}, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &AndCircuit{
		Y: 7,
		Z: 7,
		X: 7,
	}, test.WithCurves(ecc.BN254))
}

// //_______________________________________________________________________________________________________________
// This is the test reflecting the problem in gnark-PLONK
// Circuit Y == Not(X)  Single-bit Not
type PSNotCircuit struct {
	Input  frontend.Variable
	Output frontend.Variable `gnark:",public"`
}

func (circuit PSNotCircuit) Define(api frontend.API) error {
	haveOutput := api.Xor(circuit.Input, 1)
	api.AssertIsEqual(haveOutput, circuit.Output)
	return nil
}

func TestPSNot(t *testing.T) {

	// Skipping this test because of a problem with Plonk
	//due to this, the test on KeccakF is done only on Groth16
	t.SkipNow()

	assert := test.NewAssert(t)
	var circuit PSNotCircuit
	assert.SolvingFailed(&circuit, &PSNotCircuit{
		Input:  1,
		Output: 1,
	}, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &PSNotCircuit{
		Input:  1,
		Output: 0,
	})

}

//________________________________________________________
