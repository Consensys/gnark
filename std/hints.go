package std

import (
	"sync"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
	"github.com/consensys/gnark/std/lookup"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

var registerOnce sync.Once

// RegisterHints register all gnark/std hints
// In the case where the Solver/Prover code is loaded alongside the circuit, this is not useful.
// However, if a Solver/Prover services consumes serialized constraint systems, it has no way to
// know which hints were registered; caller code may add them through backend.WithHints(...).
func RegisterHints() {
	registerOnce.Do(registerHints)
}

func registerHints() {
	// note that importing these packages may already trigger a call to hint.Register(...)
	hint.Register(sw_bls24315.DecomposeScalarG1)
	hint.Register(sw_bls12377.DecomposeScalarG1)
	hint.Register(sw_bls24315.DecomposeScalarG2)
	hint.Register(sw_bls12377.DecomposeScalarG2)
	hint.Register(bits.NTrits)
	hint.Register(bits.NNAF)
	hint.Register(bits.IthBit)
	hint.Register(bits.NBits)
	hint.Register(emulated.GetHints()...)
	hint.Register(lookup.LookupHint, lookup.SortingHint)
}
