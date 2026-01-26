package gkr_mimc

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	gkr_mimc "github.com/consensys/gnark/std/permutation/gkr-mimc"
)

func New(api frontend.API) (hash.StateStorer, error) {
	f, err := gkr_mimc.NewCompressor(api)
	if err != nil {
		return nil, fmt.Errorf("could not create mimc hasher: %w", err)
	}
	return hash.NewMerkleDamgardHasher(api, f, 0), nil
}
