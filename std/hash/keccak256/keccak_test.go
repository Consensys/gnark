package keccak

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

type keccak256Circuit struct {
	ExpectedResult frontend.Variable
	Data           []frontend.Variable
}

type testcase struct {
	msg    []byte
	output []byte
}

const ShortVectorsNumber = 10

func (circuit keccak256Circuit) Define(api frontend.API) error {
	keccakHash := Keccak256Api(api, circuit.Data[:]...)
	api.AssertIsEqual(keccakHash, circuit.ExpectedResult)
	return nil
}

func TestKeccak256(t *testing.T) {
	var circuit, witness keccak256Circuit
	seed := "Hello, world!"
	output := crypto.Keccak256Hash([]byte(seed)).Bytes()

	circuit.Data = make([]frontend.Variable, len(seed))
	witness.Data = make([]frontend.Variable, len(seed))
	for j := range seed {
		witness.Data[j] = seed[j]
	}
	fmt.Println(common.Bytes2Hex(output))
	witness.ExpectedResult = output

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)
}

func TestConstraintsKeccak256(t *testing.T) {
	var circuit, witness keccak256Circuit
	seed := "Hello world!"
	h := sha256.New()
	h.Reset()
	h.Write([]byte(seed))
	output := h.Sum(nil)

	circuit.Data = make([]frontend.Variable, len(seed))
	witness.Data = make([]frontend.Variable, len(seed))
	for j := range seed {
		witness.Data[j] = seed[j]
	}
	fmt.Println(common.Bytes2Hex(output))
	witness.ExpectedResult = output

	oR1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &witness, frontend.IgnoreUnconstrainedInputs())
	fmt.Printf("Constraints num=%v\n", oR1cs.GetNbConstraints())
}
