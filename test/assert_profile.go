package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

// serializationThreshold is the number of constraints above which we don't
// don't do serialization check for the proving and verifying keys.
const serializationThreshold = 1000

// see assert.CheckCircuit for details
type profile struct {
	backends []backend.ID
	curves   []ecc.ID

	checkSerialization bool
	checkSolidity      bool
	checkProver        bool
	fuzzing            bool
}

var testEngineOnly = profile{
	backends: []backend.ID{},
	curves:   []ecc.ID{ecc.BN254, ecc.BLS12_381},
}

var constraintOnlyProfile = profile{
	backends: []backend.ID{backend.GROTH16, backend.PLONK},
	curves:   []ecc.ID{ecc.BN254, ecc.BLS12_381},
}

var proverOnlyProfile = profile{
	backends:      []backend.ID{backend.GROTH16, backend.PLONK},
	curves:        []ecc.ID{ecc.BN254, ecc.BLS12_381, ecc.BW6_761},
	checkSolidity: true && solcCheck,
	checkProver:   true,
}

var releaseProfile = profile{
	backends:           []backend.ID{backend.GROTH16, backend.PLONK},
	curves:             []ecc.ID{ecc.BN254, ecc.BLS12_381, ecc.BW6_761, ecc.BLS12_377},
	checkSolidity:      true && solcCheck,
	checkProver:        true,
	checkSerialization: true,
	fuzzing:            true,
}
