package std

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
	"github.com/consensys/gnark/std/math/bits"
)

// RegisterHints register std hints that are always injected in gnark solvers
func RegisterHints() {
	// note that duplicate hints are not allowed in hint registry
	// but hints from std have a special path (to not panic)
	hint.Register(sw_bls24315.DecomposeScalar)
	hint.Register(sw_bls12377.DecomposeScalar)
	hint.Register(bits.NTrits)
	hint.Register(bits.NNAF)
	hint.Register(bits.IthBit)
	hint.Register(bits.NBits)
}
