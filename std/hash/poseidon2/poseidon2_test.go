package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type Poseidon2Circuit struct {
	Input    []frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *Poseidon2Circuit) Define(api frontend.API) error {
	hsh, err := NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}
	hsh.Write(c.Input...)
	api.AssertIsEqual(hsh.Sum(), c.Expected)
	return nil
}

func TestPoseidon2Hash(t *testing.T) {
	assert := test.NewAssert(t)

	const nbInputs = 5
	// prepare expected output
	h := poseidon2.NewMerkleDamgardHasher()
	circInput := make([]frontend.Variable, nbInputs)
	for i := range nbInputs {
		_, err := h.Write([]byte{byte(i)})
		assert.NoError(err)
		circInput[i] = i
	}
	res := h.Sum(nil)
	assert.CheckCircuit(&Poseidon2Circuit{Input: make([]frontend.Variable, nbInputs)}, test.WithValidAssignment(&Poseidon2Circuit{Input: circInput, Expected: res}), test.WithCurves(ecc.BLS12_377)) // we have parametrized currently only for BLS12-377
}
