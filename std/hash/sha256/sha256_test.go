package sha256

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"testing"
)

type sha256Circuit struct {
	ExpectedResult frontend.Variable
	Data           []frontend.Variable
}

func (circuit sha256Circuit) Define(api frontend.API) error {
	result := Sha256Api(api, circuit.Data[:]...)
	api.AssertIsEqual(result, circuit.ExpectedResult)
	return nil
}

func TestSha256(t *testing.T) {
	var circuit, witness sha256Circuit
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

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)
}

func TestConstraintsSha256(t *testing.T) {
	var circuit, witness sha256Circuit
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
