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
	hash, _ := new(big.Int).SetString("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a", 16)

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
	hash, _ := new(big.Int).SetString("299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465", 16)

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
	hash, _ := new(big.Int).SetString("612D378F91DC3422E6C60E54D24E3FA6D8000F0E47CDACE9BDB304506E3C9D3", 16)

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
	hash, _ := new(big.Int).SetString("140CEA90C05A04C7140337789BD4CDE38BA73EE1988D34533F3F8F7B6AAC5675", 16)

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
