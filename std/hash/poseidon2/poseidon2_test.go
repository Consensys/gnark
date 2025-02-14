package poseidon2

import (
	"github.com/consensys/gnark-crypto/ecc"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func TestPoseidon2Hash(t *testing.T) {
	// prepare expected output
	h := poseidon2.NewMerkleDamgardHasher()
	for i := range 5 {
		_, err := h.Write([]byte{byte(i)})
		require.NoError(t, err)
	}
	res := h.Sum(nil)

	test.Function(func(api frontend.API) error {
		hsh, err := NewMerkleDamgardHasher(api)
		require.NoError(t, err)
		hsh.Write(0, 1, 2, 3, 4)
		api.AssertIsEqual(hsh.Sum(), res)
		return nil
	}, test.WithCurves(ecc.BLS12_377))(t)
}
