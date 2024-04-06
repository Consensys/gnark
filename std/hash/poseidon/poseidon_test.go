package poseidon

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type poseidonCircuit2 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [2]frontend.Variable
}

type poseidonCircuit4 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [4]frontend.Variable
}

type poseidonCircuit24 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [24]frontend.Variable
}

type poseidonCircuit30 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [30]frontend.Variable
}

type poseidonCircuit256 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [256]frontend.Variable
}

func (circuit *poseidonCircuit2) Define(api frontend.API) error {
	result := Poseidon(api, circuit.Data[:]...)
	api.AssertIsEqual(result, circuit.Hash)
	return nil
}

func (circuit *poseidonCircuit4) Define(api frontend.API) error {
	result := Poseidon(api, circuit.Data[:]...)
	api.AssertIsEqual(result, circuit.Hash)
	return nil
}

func (circuit *poseidonCircuit24) Define(api frontend.API) error {
	result := Poseidon(api, circuit.Data[:]...)
	api.AssertIsEqual(result, circuit.Hash)
	return nil
}

func (circuit *poseidonCircuit30) Define(api frontend.API) error {
	result := Poseidon(api, circuit.Data[:]...)
	api.AssertIsEqual(result, circuit.Hash)
	return nil
}

func (circuit *poseidonCircuit256) Define(api frontend.API) error {
	result := Poseidon(api, circuit.Data[:]...)
	api.AssertIsEqual(result, circuit.Hash)
	return nil
}

func TestPoseidon2(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness poseidonCircuit2
	hash, _ := new(big.Int).SetString("FCA49B798923AB0239DE1C9E7A4A9A2210312B6A2F616D18B5A87F9B628AE29", 16)

	// Test completeness
	size := 2
	for i := 0; i < size; i++ {
		witness.Data[i] = frontend.Variable(i + 1)
	}
	witness.Hash = hash
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestPoseidon4(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit4
	hash, _ := new(big.Int).SetString("1148AAEF609AA338B27DAFD89BB98862D8BB2B429ACEAC47D86206154FFE053D", 16)

	// Test completeness
	size := 4
	for i := 0; i < size; i++ {
		witness.Data[i] = frontend.Variable(i + 1)
	}
	witness.Hash = hash
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	// Test soundness
	for i := 0; i < size; i++ {
		wrongWitness.Data[i] = frontend.Variable(i + 2)
	}
	wrongWitness.Hash = hash
	assert.SolvingFailed(&circuit, &wrongWitness, test.WithCurves(ecc.BN254))

}

func TestPoseidon24(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit24
	hash, _ := new(big.Int).SetString("6C7676E83EF8CB9EF6C25746A5F6B2D39FBA4548B4C29B3D41490BBF3C1108D", 16)

	// Test completeness
	size := 24
	for i := 0; i < size; i++ {
		witness.Data[i] = frontend.Variable(i + 1)
	}
	witness.Hash = hash
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	// Test soundness
	for i := 0; i < size; i++ {
		wrongWitness.Data[i] = frontend.Variable(i + 2)
	}
	wrongWitness.Hash = hash
	assert.SolvingFailed(&circuit, &wrongWitness, test.WithCurves(ecc.BN254))

}

func TestPoseidon30(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit30
	hash, _ := new(big.Int).SetString("2FF47AB8E9E9F6134600A8DE8B8E99596E573620A7D8D39ED7B2C7CEF9F105F1", 16)

	// Test completeness
	size := 30
	for i := 0; i < size; i++ {
		witness.Data[i] = frontend.Variable(i + 1)
	}
	witness.Hash = hash
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	// Test soundness
	for i := 0; i < size; i++ {
		wrongWitness.Data[i] = frontend.Variable(i + 2)
	}
	wrongWitness.Hash = hash
	assert.SolvingFailed(&circuit, &wrongWitness, test.WithCurves(ecc.BN254))
}

func TestPoseidon256(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit256
	hash, _ := new(big.Int).SetString("182AF1C3FFD14FA66CDF5FE5D5199473678F221CA3BAB09B44758EF80641C1E0", 16)

	// Test completeness
	size := 256
	for i := 0; i < size; i++ {
		witness.Data[i] = frontend.Variable(i + 1)
	}
	witness.Hash = hash
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	// Test soundness
	for i := 0; i < size; i++ {
		wrongWitness.Data[i] = frontend.Variable(i + 2)
	}
	wrongWitness.Hash = hash
	assert.SolvingFailed(&circuit, &wrongWitness, test.WithCurves(ecc.BN254))
}
