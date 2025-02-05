package poseidon2

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPoseidon2Hash(t *testing.T) {
	// prepare expected output
	h := poseidon2.NewMerkleDamgardHasher()
	for i := range 5 {
		_, err := h.Write([]byte{byte(i)})
		require.NoError(t, err)
	}
	res := h.Sum(nil)

	test.SingleFunction(ecc.BLS12_377, func(api frontend.API) []frontend.Variable {
		hsh, err := NewPoseidon2(api)
		require.NoError(t, err)
		hsh.Write(0, 1, 2, 3, 4)
		return []frontend.Variable{hsh.Sum()}
	}, res)(t)
}
