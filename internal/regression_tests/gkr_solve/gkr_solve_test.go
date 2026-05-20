// Package gkr_solve hosts a regression test that exercises the full GKR
// proving path on a constraint system deserialized from disk, without
// importing gkrapi or any package that builds GKR circuits in-process.
//
// The testdata is produced by internal/gkr/test_vectors/generate.go, which
// compiles a small Poseidon2 GKR validator circuit (defined in
// std/permutation/poseidon2/gkr-poseidon2/gkrposeidon2testing) and writes
// both the constraint system and a matching witness to testdata/.
//
// The point of the separation is to mirror a production solver/prover
// process, which loads a pre-compiled constraint system and proves new
// witnesses against it without ever invoking the GKR builder API. Bugs that
// only manifest after CBOR serialization round-trip — e.g. pointer- vs
// value-typed schedule levels — are caught here and not by any in-process
// test that keeps the schedule in memory.
package gkr_solve

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	_ "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc" // register native MIMC, used by GKR Fiat-Shamir during Solve
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/stretchr/testify/require"
)

func TestGkrIntegration(t *testing.T) {
	ccs := plonk.NewCS(ecc.BLS12_377)
	scsFile, err := os.Open("testdata/gkr_poseidon2.scs")
	require.NoError(t, err)
	defer scsFile.Close()
	_, err = ccs.ReadFrom(scsFile)
	require.NoError(t, err)

	w, err := witness.New(ecc.BLS12_377.ScalarField())
	require.NoError(t, err)
	wtnsFile, err := os.Open("testdata/gkr_poseidon2.wtns")
	require.NoError(t, err)
	defer wtnsFile.Close()
	_, err = w.ReadFrom(wtnsFile)
	require.NoError(t, err)

	_, err = ccs.Solve(w)
	require.NoError(t, err)
}
