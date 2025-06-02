package mimc

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/internal/mimc"
)

// MiMC contains the params of the MiMC hash func and the curves on which it is
// implemented. The reference to this type implements [hash.FieldHasher].
//
// NB! See the package documentation for length extension attack consideration.
type MiMC = mimc.MiMC

// NewMiMC returns a MiMC instance that can be used in a gnark circuit. The
// out-circuit counterpart of this function is provided in [gnark-crypto]. The
// reference to the returned type implements [hash.FieldHasher], but we keep the
// method for backwards compatibility. See also [New].
//
// NB! See the package documentation for length extension attack consideration.
//
// [gnark-crypto]: https://pkg.go.dev/github.com/consensys/gnark-crypto/hash
func NewMiMC(api frontend.API) (MiMC, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return MiMC{}, err
	}
	return h, nil
}

// New returns a new MiMC hasher that can be used in a gnark circuit. The
// out-circuit counterpart of this function is provided in [gnark-crypto].
//
// NB! See the package documentation for length extension attack consideration.
//
// [gnark-crypto]: https://pkg.go.dev/github.com/consensys/gnark-crypto/hash
func New(api frontend.API) (hash.FieldHasher, error) {
	h, err := NewMiMC(api)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func init() {
	hash.Register("MIMC", New)
}
