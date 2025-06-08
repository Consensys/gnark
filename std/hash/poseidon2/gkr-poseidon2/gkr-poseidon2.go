package gkr_poseidon2

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	_ "github.com/consensys/gnark/std/hash/all"
	gkr_poseidon2 "github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2"
)

func New(api frontend.API) (hash.FieldHasher, error) {
	f, err := gkr_poseidon2.NewGkrCompressor(api)
	if err != nil {
		return nil, fmt.Errorf("could not create poseidon2 hasher: %w", err)
	}
	return hash.NewMerkleDamgardHasher(api, f, 0), nil
}
