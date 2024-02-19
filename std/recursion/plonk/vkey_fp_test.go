package plonk

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

type OuterCircuitDual[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proofs         []Proof[FR, G1El, G2El]
	VerifyingKeys  []VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	InnerWitnesses []Witness[FR]                  `gnark:",public"`
}

func (c *OuterCircuitDual[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	fp, err := c.VerifyingKeys[0].FingerPrint(api)
	if err != nil {
		return fmt.Errorf("new curve for verification keys: %w", err)
	}
	api.Println(fp)
	err = verifier.AssertProof(c.VerifyingKeys[0], c.Proofs[0], c.InnerWitnesses[0], WithCompleteArithmetic())

	fp2, err := c.VerifyingKeys[1].FingerPrint(api)
	if err != nil {
		return fmt.Errorf("new curve for verification keys: %w", err)
	}
	api.Println(fp2)
	// err = verifier.AssertProof(c.VerifyingKeys[1], c.Proofs[1], c.InnerWitnesses[1], WithCompleteArithmetic())
	// same constant value should result same verification key
	api.AssertIsEqual(fp, fp2)

	fp3, err := c.VerifyingKeys[2].FingerPrint(api)
	if err != nil {
		return fmt.Errorf("new curve for verification keys: %w", err)
	}
	api.Println(fp3)
	// err = verifier.AssertProof(c.VerifyingKeys[2], c.Proofs[2], c.InnerWitnesses[2], WithCompleteArithmetic())
	// different constant value should result different verification key
	api.AssertIsDifferent(fp, fp3)

	return err
}

// the constant value (c.multiplier) should impact not only the relationship between X and Y
// but also the circuit structure, meaning the vkey fingerprint will *change* with a different constant value
type InnerCircuitWithConstant struct {
	X          frontend.Variable
	Y          frontend.Variable `gnark:",public"`
	multiplier int
}

func (c *InnerCircuitWithConstant) Define(api frontend.API) error {
	res := api.Mul(c.X, c.multiplier)
	api.AssertIsEqual(res, c.Y)

	return nil
}

func getInnerCircuitProof(assert *test.Assert, field, outer *big.Int) ([]constraint.ConstraintSystem, []native_plonk.VerifyingKey, []witness.Witness, []native_plonk.Proof) {

	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitWithConstant{multiplier: 5})
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitWithConstant{
		X: 3,
		Y: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, GetNativeVerifierOptions(outer, field))

	assert.NoError(err)

	// innerCcs is only needed for nbConstraints/nbPublicVarialbes and .Field()
	// so we could reuse generated srs for another CCS instance which only differs in the constant multiplier
	innerCcs2, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitWithConstant{multiplier: 5})
	assert.NoError(err)

	innerPK2, innerVK2, err := native_plonk.Setup(innerCcs2, srs, srsLagrange)
	assert.NoError(err)

	// inner proof2
	innerAssignment2 := &InnerCircuitWithConstant{
		X: 3,
		Y: 15,
	}
	innerWitness2, err := frontend.NewWitness(innerAssignment2, field)
	assert.NoError(err)
	innerProof2, err := native_plonk.Prove(innerCcs2, innerPK2, innerWitness2, GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness2, err := innerWitness2.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof2, innerVK2, innerPubWitness2, GetNativeVerifierOptions(outer, field))

	assert.NoError(err)

	innerCcs3, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitWithConstant{multiplier: 7})
	assert.NoError(err)

	innerPK3, innerVK3, err := native_plonk.Setup(innerCcs3, srs, srsLagrange)
	assert.NoError(err)

	// inner proof3
	innerAssignment3 := &InnerCircuitWithConstant{
		X: 3,
		Y: 21,
	}
	innerWitness3, err := frontend.NewWitness(innerAssignment3, field)
	assert.NoError(err)
	innerProof3, err := native_plonk.Prove(innerCcs3, innerPK3, innerWitness3, GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness3, err := innerWitness3.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof3, innerVK3, innerPubWitness3, GetNativeVerifierOptions(outer, field))

	assert.NoError(err)

	return []constraint.ConstraintSystem{innerCcs, innerCcs2, innerCcs3},
		[]native_plonk.VerifyingKey{innerVK, innerVK2, innerVK3},
		[]witness.Witness{innerPubWitness, innerPubWitness2, innerPubWitness3},
		[]native_plonk.Proof{innerProof, innerProof2, innerProof3}
}

func TestBW6InBN254VkeyFp(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCircuitProof(assert, ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())

	// outer proofs
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerVK[0])
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness[0])
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof[0])
	assert.NoError(err)

	circuitVk2, err := ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerVK[1])
	assert.NoError(err)
	circuitWitness2, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness[1])
	assert.NoError(err)
	circuitProof2, err := ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof[1])
	assert.NoError(err)

	circuitVk3, err := ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerVK[2])
	assert.NoError(err)
	circuitWitness3, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness[2])
	assert.NoError(err)
	circuitProof3, err := ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof[2])
	assert.NoError(err)

	outerCircuit := &OuterCircuitDual[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitnesses: []Witness[sw_bw6761.ScalarField]{
			PlaceholderWitness[sw_bw6761.ScalarField](innerCcs[0]),
			PlaceholderWitness[sw_bw6761.ScalarField](innerCcs[1]),
			PlaceholderWitness[sw_bw6761.ScalarField](innerCcs[2]),
		},
		Proofs: []Proof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine]{
			PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs[0]),
			PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs[1]),
			PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs[2]),
		},
		VerifyingKeys: []VerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine]{
			circuitVk,
			circuitVk2,
			circuitVk3,
		},
	}
	outerAssignment := &OuterCircuitDual[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitnesses: []Witness[sw_bw6761.ScalarField]{circuitWitness, circuitWitness2, circuitWitness3},
		Proofs:         []Proof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine]{circuitProof, circuitProof2, circuitProof3},
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
