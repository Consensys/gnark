package plonk_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
)

// TestProvingKeyTraceReuse proves the SAME proving key multiple times and verifies every
// proof. The bls12-381 backend caches the circuit-fixed trace on the proving key at Setup
// and clones it per-proof (instead of rebuilding it with NewTrace). The prover mutates its
// trace in place (Lagrange->canonical in computeNumerator, Qk.ToCanonical in the linearized
// poly), so if the per-proof clone aliased the cached trace, the first prove would corrupt
// every subsequent one. A single-prove test cannot catch that; reusing one pk for several
// successful prove+verify rounds does.
func TestProvingKeyTraceReuse(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &smallCircuit{})
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	w, err := frontend.NewWitness(&smallCircuit{X: 1}, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	pubW, err := w.Public()
	assert.NoError(err)

	// every round must succeed off the same pk — a stale/aliased cached trace would
	// make round >0 produce an invalid proof.
	for i := 0; i < 4; i++ {
		proof, err := plonk.Prove(ccs, pk, w)
		assert.NoError(err, "prove round %d", i)
		assert.NoError(plonk.Verify(proof, vk, pubW), "verify round %d", i)
	}
}
