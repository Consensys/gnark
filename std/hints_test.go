package std

import (
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

func ExampleRegisterHints() {
	// this constraint system correspond to a circuit using gnark/std components which rely on hints
	// like bits.ToNAF(...)
	var ccs frontend.CompiledConstraintSystem

	// since package bits is not imported, the hint NNAF is not registered
	// --> hint.Register(bits.NNAF)
	// rather than to keep track on which hints are needed, a prover/solver service can register all
	// gnark/std hints with this call
	RegisterHints()

	// then -->
	ccs.IsSolved(&witness.Witness{})
}
