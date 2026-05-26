package integration_test

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	_ "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc" // register native MIMC for GKR Fiat-Shamir
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/stretchr/testify/require"
)

func TestGkrIntegration(t *testing.T) {
	ccs := plonk.NewCS(ecc.BLS12_377)
	scsFile, err := os.Open("gkr_poseidon2.scs")
	require.NoError(t, err)
	defer scsFile.Close()
	_, err = ccs.ReadFrom(scsFile)
	require.NoError(t, err)

	w, err := witness.New(ecc.BLS12_377.ScalarField())
	require.NoError(t, err)
	wtnsFile, err := os.Open("gkr_poseidon2.wtns")
	require.NoError(t, err)
	defer wtnsFile.Close()
	_, err = w.ReadFrom(wtnsFile)
	require.NoError(t, err)

	_, err = ccs.Solve(w)
	require.NoError(t, err)
}
