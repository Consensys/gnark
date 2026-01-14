package poseidon2

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// New returns a Poseidon2 hasher using the Merkle-Damgard
// construction with the default parameters.
func New(api frontend.API) (hash.StateStorer, error) {
	f, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return nil, fmt.Errorf("could not create poseidon2 hasher: %w", err)
	}
	return hash.NewMerkleDamgardHasher(api, f, 0), nil
}

func init() {
	hash.Register(hash.POSEIDON2, func(api frontend.API) (hash.FieldHasher, error) {
		return New(api)
	})
}
