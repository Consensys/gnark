package issue1787

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
)

type squareCircuit struct {
	X          frontend.Variable `gnark:",public"`
	Y          frontend.Variable
	WithCommit bool `gnark:"-"`
}

func (c *squareCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.Y, c.Y), c.X)
	if c.WithCommit {
		commitment, err := api.(frontend.Committer).Commit(c.Y)
		if err != nil {
			return err
		}
		api.AssertIsDifferent(commitment, c.Y)
	}
	return nil
}

func TestPlonkVerifyClaimedValuesLenMismatch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withCommit bool
		nbQcp      int
	}{
		{name: "without_commit", nbQcp: 0},
		{name: "with_commit", withCommit: true, nbQcp: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof, vk, publicWitness, expectedClaimedValues := newPlonkProof(t, tc.withCommit, tc.nbQcp)

			runMalformedProof := func(name string, claimedValuesLen int) {
				t.Run(name, func(t *testing.T) {
					malformedProof := *proof
					malformedProof.BatchedProof.ClaimedValues = make([]fr_bn254.Element, claimedValuesLen)
					copy(malformedProof.BatchedProof.ClaimedValues, proof.BatchedProof.ClaimedValues)
					var err error
					require.NotPanics(t, func() {
						err = plonk.Verify(&malformedProof, vk, publicWitness)
					})
					require.Error(t, err)

					var encoded bytes.Buffer
					_, err = malformedProof.WriteTo(&encoded)
					require.NoError(t, err)

					var decoded plonk_bn254.Proof
					if _, err = decoded.ReadFrom(bytes.NewReader(encoded.Bytes())); err != nil {
						return
					}
					require.NotPanics(t, func() {
						err = plonk.Verify(&decoded, vk, publicWitness)
					})
					require.Error(t, err)
				})
			}

			runMalformedProof("too_small_base", 5)
			if tc.withCommit {
				runMalformedProof("missing_commitment_claimed_value", expectedClaimedValues-1)
			}
			runMalformedProof("too_large", expectedClaimedValues+1)
		})
	}
}

func newPlonkProof(t *testing.T, withCommit bool, nbQcp int) (*plonk_bn254.Proof, plonk.VerifyingKey, witness.Witness, int) {
	t.Helper()
	assert := require.New(t)

	circuit := &squareCircuit{WithCommit: withCommit}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	assignment := &squareCircuit{X: 4, Y: 2, WithCommit: withCommit}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	publicWitness, err := fullWitness.Public()
	assert.NoError(err)

	proof, err := plonk.Prove(ccs, pk, fullWitness)
	assert.NoError(err)
	assert.NoError(plonk.Verify(proof, vk, publicWitness))

	bn254Proof := proof.(*plonk_bn254.Proof)
	bn254VK := vk.(*plonk_bn254.VerifyingKey)
	assert.Len(bn254VK.Qcp, nbQcp)

	expectedClaimedValues := 6 + len(bn254VK.Qcp)
	assert.Len(bn254Proof.BatchedProof.ClaimedValues, expectedClaimedValues)
	assert.Len(bn254Proof.Bsb22Commitments, len(bn254VK.Qcp))

	return bn254Proof, vk, publicWitness, expectedClaimedValues
}
