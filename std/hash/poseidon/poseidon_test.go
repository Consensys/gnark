package poseidon

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type poseidonCircuit1 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [1]frontend.Variable
}

type poseidonCircuit2 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [2]frontend.Variable
}

type poseidonCircuit4 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [4]frontend.Variable
}

type poseidonCircuit13 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [13]frontend.Variable
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

func (circuit *poseidonCircuit1) Define(api frontend.API) error {
	result := Poseidon(api, circuit.Data[:]...)
	api.AssertIsEqual(result, circuit.Hash)
	return nil
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

func (circuit *poseidonCircuit13) Define(api frontend.API) error {
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

func TestPoseidon1(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit1
	hash, _ := new(big.Int).SetString("112A4F9241E384B0EDE4655E6D2BBF7EBD9595775DE9E7536DF87CD487852FC4", 16)

	// Test completeness
	size := 1
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

func TestPoseidon2(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit2
	hash, _ := new(big.Int).SetString("FCA49B798923AB0239DE1C9E7A4A9A2210312B6A2F616D18B5A87F9B628AE29", 16)

	// Test completeness
	size := 2
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

func TestPoseidon13(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit13
	hash, _ := new(big.Int).SetString("4EA9108A1551C780A7408570BDEAA3A0294B01F21198B72FF01545A60DA677F", 16)

	// Test completeness
	size := 13
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
	hash, _ := new(big.Int).SetString("15b218692488b5ce4c9f8571e7daef78bd39cc455d431572f5f5f2933e4f5ea2", 16)

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
