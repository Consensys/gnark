package std

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
	"github.com/consensys/gnark/std/math/bits"
)

// RegisterHints register std hints that are always injected in gnark solvers
func RegisterHints() {
	// note that importing these packages may already triggers a call to hint.Register(...)
	hint.Register(sw_bls24315.DecomposeScalar)
	hint.Register(sw_bls12377.DecomposeScalar)
	hint.Register(bits.NTrits)
	hint.Register(bits.NNAF)
	hint.Register(bits.IthBit)
	hint.Register(bits.NBits)
}
