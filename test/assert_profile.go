package test

import (
	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

type Profile struct {
	Backends []backend.ID
	Curves   []ecc.ID

	WitnessSerialization bool
	Solidity             bool
	FullProver           bool
	Fuzzing              bool
}

// TestEngineOnly profile; good presets to check correctness of the circuit.
// Runs the test engine with
// * BN254 scalar field only if -short flag is set
// * BN254 and BLS12-381 scalar fields otherwise
// No prover, no serialization checks, no fuzzing, no solidity.
// It does not compile the circuit to a constraint system.
var TestEngineOnly = Profile{
	Backends: []backend.ID{},
}

// ConstraintOnlyProfile profile; good presets to check correctness of the circuit.
// and the validity of the constraint system.
// It is the same as TestEngineOnly, but it compiles the circuit to a constraint system.
// and runs the constraint system solver on the valid and invalid assignments.
var ConstraintOnlyProfile = Profile{
	Backends: nil, // default option for backend == nil will fill that.
}

// FullProfile profile; good presets to check correctness of the circuit.
// and the validity of the constraint system.
// It is the same as ConstraintOnlyProfile, but it also runs the prover.
var FullProfile = Profile{
	Backends:             []backend.ID{backend.GROTH16, backend.PLONK},
	Curves:               gnark.Curves(),
	WitnessSerialization: true,
	Solidity:             true,
	FullProver:           true,
	Fuzzing:              true,
}
