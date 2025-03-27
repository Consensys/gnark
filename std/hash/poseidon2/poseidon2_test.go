package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254_poseidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	gchash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/hash"
	gprmp2 "github.com/consensys/gnark/std/permutation/poseidon2"
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

type Poseidon2BN254Circuit struct {
	Input    []frontend.Variable
	Expected frontend.Variable `gnark:",public"`

	width, nbFull, nbPartialRounds int
}

func (c *Poseidon2BN254Circuit) Define(api frontend.API) error {
	p, err := gprmp2.NewPoseidon2FromParameters(api, c.width, c.nbFull, c.nbPartialRounds)
	if err != nil {
		return err
	}
	h := hash.NewMerkleDamgardHasher(api, p, 0)
	h.Write(c.Input...)
	dgst := h.Sum()
	api.AssertIsEqual(dgst, c.Expected)
	return nil
}

// TestPoseidon2Custom tests the Poseidon2 permutation with custom parameters.
// Exemplifies how to use the Poseidon2 hasher in case default parameters are
// not defined
func TestPoseidon2Custom(t *testing.T) {
	assert := test.NewAssert(t)

	p := bn254_poseidon2.NewPermutation(2, 6, 50)
	h := gchash.NewMerkleDamgardHasher(p, make([]byte, fr_bn254.Bytes))

	inputs := []int{1, 2, 3, 4, 5}
	varInputs := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		var v fr_bn254.Element
		v.SetUint64(uint64(inputs[i]))
		vb := v.Bytes()
		_, err := h.Write(vb[:])
		assert.NoError(err)
		varInputs[i] = inputs[i]
	}

	res := h.Sum(nil)
	assert.CheckCircuit(
		&Poseidon2BN254Circuit{
			Input: make([]frontend.Variable, len(inputs)),
			width: 2, nbFull: 6, nbPartialRounds: 50,
		},
		test.WithValidAssignment(&Poseidon2BN254Circuit{Input: varInputs, Expected: res}),
		test.WithCurves(ecc.BN254))
}
