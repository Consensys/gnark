package std

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
	"github.com/consensys/gnark/std/algebra/twistededwards/bandersnatch"
	"github.com/consensys/gnark/std/math/bits"
)

// GetHints return std hints that are always injected in gnark solvers
func GetHints() []hint.Function {
	return []hint.Function{
		sw_bls24315.DecomposeScalar,
		sw_bls12377.DecomposeScalar,
		bandersnatch.DecomposeScalar,
		bits.NTrits,
		bits.NNAF,
		bits.IthBit,
		bits.NBits,
	}
}
