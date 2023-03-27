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

type poseidonCircuit16 struct {
	Hash frontend.Variable `gnark:"data,public"`
	Data [16]frontend.Variable
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

func (circuit *poseidonCircuit16) Define(api frontend.API) error {
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
	hash, _ := new(big.Int).SetString("7764075183688725171230668857402392634761334547267776368103645048439717572548", 10)

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
	hash, _ := new(big.Int).SetString("7142104613055408817911962100316808866448378443474503659992478482890339429929", 10)

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
	hash, _ := new(big.Int).SetString("7817711165059374331357136443537800893307845083525445872661165200086166013245", 10)

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
	hash, _ := new(big.Int).SetString("1709610050961943784828399921362905178787999827108026634048665681910636069934", 10)

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

func TestPoseidon16(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness, wrongWitness poseidonCircuit16
	hash, _ := new(big.Int).SetString("8319791455060392555425392842391403897548969645190976863995973180967774875286", 10)

	// Test completeness
	size := 16
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
	hash, _ := new(big.Int).SetString("14281896993318141900551144554156181598834585543901557749703302979893059224887", 10)

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
	hash, _ := new(big.Int).SetString("3706864405066113783363062549980271879113588784557216652303342540436728346372", 10)

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
	hash, _ := new(big.Int).SetString("3889232958018785041730045800798978544000060048890444628344970190264245196615", 10)

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
