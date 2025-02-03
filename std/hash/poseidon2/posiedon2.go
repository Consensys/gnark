package poseidon2

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/hash"
	poseidon2 "github.com/consensys/gnark/std/permutation/poseidon2"
	"strings"
)

func NewPoseidon2(api frontend.API) (hash.FieldHasher, error) {
	curve := utils.FieldToCurve(api.Compiler().Field())
	params, ok := parameters[curve]
	if !ok {
		return nil, fmt.Errorf("poseidon2 hash for curve \"%s\" not yet supported", curve.String())
	}
	seed := fmt.Sprintf("Poseidon2 hash for %s with t=2, rF=%d, rP=%d, d=%d", strings.ToUpper(curve.String()), params.rF, params.rP, params.d)
	f := poseidon2.NewHash(2, params.d, params.rF, params.rP, seed, curve)
	return hash.NewMerkleDamgardHasher(api, &f, 0), nil
}

var parameters = map[ecc.ID]struct {
	d  int
	rF int
	rP int
}{
	ecc.BLS12_377: {
		rF: 6,
		rP: 26,
		d:  17,
	},
}
