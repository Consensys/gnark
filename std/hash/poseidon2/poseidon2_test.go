package poseidon2

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPoseidon2Hash(t *testing.T) {
	test.SingleFunction(ecc.BLS12_377, func(api frontend.API) []frontend.Variable {
		hsh, err := NewPoseidon2(api)
		require.NoError(t, err)
		hsh.Write(0, 1, 2, 3, 4)
		api.AssertIsDifferent(hsh.Sum(), 0) // TODO add test vectors
		return nil
	})(t)
}
