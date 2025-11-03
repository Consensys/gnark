package poseidon2

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	gcPoseidon2 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/test"
)

type Poseidon2Circuit struct {
	Input    []frontend.Variable
	Expected []frontend.Variable `gnark:",public"` // Expected[i] = H(Input[:i+1])
}

func (c *Poseidon2Circuit) Define(api frontend.API) error {
	if len(c.Input) != len(c.Expected) {
		return fmt.Errorf("length mismatch")
	}
	hsh, err := NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}

	compressor, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}

	for i := range c.Input {
		hsh.Write(c.Input[i])
		api.AssertIsEqual(c.Expected[i], hsh.Sum())
		api.AssertIsEqual(c.Expected[i], hash.SumMerkleDamgardDynamicLength(api, compressor, 0, i+1, c.Input))
	}

	return nil
}

func TestPoseidon2Hash(t *testing.T) {
	assert := test.NewAssert(t)

	var buf [fr.Bytes]byte
	const nbInputs = 5
	// prepare expected output
	h := gcPoseidon2.NewMerkleDamgardHasher()
	expected := make([]frontend.Variable, nbInputs)
	circInput := make([]frontend.Variable, nbInputs)
	for i := range nbInputs {
		buf[fr.Bytes-1] = byte(i)
		_, err := h.Write(buf[:])
		assert.NoError(err)
		circInput[i] = i
		expected[i] = h.Sum(nil)
	}
	assert.CheckCircuit(
		&Poseidon2Circuit{
			Input:    make([]frontend.Variable, nbInputs),
			Expected: make([]frontend.Variable, nbInputs),
		}, test.WithValidAssignment(&Poseidon2Circuit{
			Input:    circInput,
			Expected: expected,
		}), test.WithCurves(ecc.BLS12_377)) // we have parametrized currently only for BLS12-377
}
