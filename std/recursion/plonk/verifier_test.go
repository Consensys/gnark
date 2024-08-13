package plonk

import (
	"crypto/rand"
	"fmt"
	"math/big"
	stdbits "math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[FR, G1El, G2El]
	VerifyingKey VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	InnerWitness Witness[FR]                  `gnark:",public"`
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness, WithCompleteArithmetic())
	return err
}

///-----------------------------------------------------------------
// Without api.Commit

type InnerCircuitNativeWoCommit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNativeWoCommit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInnerWoCommit(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitNativeWoCommit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitNativeWoCommit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, GetNativeProverOptions(outer, field))
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

func TestBLS12InBW6WoCommit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerWoCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	assert.NoError(err)
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

}

func TestBW6InBN254WoCommit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerWoCommit(assert, ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBLS12381InBN254WoCommit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerWoCommit(assert, ecc.BLS12_381.ScalarField(), ecc.BN254.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12381.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bls12381.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

//-----------------------------------------------------------------
// With api.Commit

type InnerCircuitCommit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitCommit) Define(api frontend.API) error {

	x := api.Mul(c.P, c.P)
	y := api.Mul(c.Q, c.Q)
	z := api.Add(x, y)

	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("builder does not implement frontend.Committer")
	}
	u, err := committer.Commit(x, z)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(u, c.N)
	return nil
}

func getInnerCommit(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {

	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitCommit{})
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitCommit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, GetNativeVerifierOptions(outer, field))

	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

func TestBLS12InBW6Commit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}

	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

}

func TestBW6InBN254Commit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBLS12381InBN254Commit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_381.ScalarField(), ecc.BN254.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12381.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bls12381.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBN254InBN254Commit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BN254.ScalarField(), ecc.BN254.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type InnerCircuitParametric struct {
	X         frontend.Variable
	Y         frontend.Variable `gnark:",public"`
	parameter int
}

func (c *InnerCircuitParametric) Define(api frontend.API) error {
	res := c.X
	for i := 0; i < c.parameter; i++ {
		res = api.Mul(res, res)
	}
	api.AssertIsEqual(res, c.Y)

	commitment, err := api.(frontend.Committer).Commit(c.X, res)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commitment, res)

	return nil
}

func getParametricSetups(assert *test.Assert, field *big.Int, nbParams int) ([]constraint.ConstraintSystem, []native_plonk.VerifyingKey, []native_plonk.ProvingKey) {
	var err error

	ccss := make([]constraint.ConstraintSystem, nbParams)
	vks := make([]native_plonk.VerifyingKey, nbParams)
	pks := make([]native_plonk.ProvingKey, nbParams)
	for i := range ccss {
		ccss[i], err = frontend.Compile(field, scs.NewBuilder, &InnerCircuitParametric{parameter: 8 << i})
		assert.NoError(err)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccss[nbParams-1])
	assert.NoError(err)
	srsT, ok := srs.(*kzg_bls12377.SRS)
	assert.True(ok)
	srsLagrangeT, ok := srsLagrange.(*kzg_bls12377.SRS)
	assert.True(ok)

	for i := range vks {
		sizeSystem := ccss[i].GetNbPublicVariables() + ccss[i].GetNbConstraints()
		nextPowerTwo := 1 << stdbits.Len(uint(sizeSystem))
		srsLagrangeT.Pk.G1, err = kzg_bls12377.ToLagrangeG1(srsT.Pk.G1[:nextPowerTwo])
		assert.NoError(err)
		pks[i], vks[i], err = native_plonk.Setup(ccss[i], srsT, srsLagrangeT)
		assert.NoError(err)
	}
	return ccss, vks, pks
}

func getRandomParametricProof(assert *test.Assert, field, outer *big.Int, ccss []constraint.ConstraintSystem, vks []native_plonk.VerifyingKey, pks []native_plonk.ProvingKey) (int, witness.Witness, native_plonk.Proof) {
	rndIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(ccss))))
	assert.NoError(err)
	idx := int(rndIdx.Int64())
	x, err := rand.Int(rand.Reader, field)
	assert.NoError(err)
	y := new(big.Int).Set(x)
	for i := 0; i < (8 << idx); i++ {
		y.Mul(y, y)
		y.Mod(y, field)
	}
	// inner proof
	innerAssignment := &InnerCircuitParametric{
		X: x,
		Y: y,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := native_plonk.Prove(ccss[idx], pks[idx], innerWitness, GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof, vks[idx], innerPubWitness, GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return idx, innerPubWitness, innerProof
}

type AggregationCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BaseKey     BaseVerifyingKey[FR, G1El, G2El] `gnark:"-"`
	CircuitKeys []CircuitVerifyingKey[FR, G1El]
	Selectors   []frontend.Variable
	Proofs      []Proof[FR, G1El, G2El]
	Witnesses   []Witness[FR] `gnark:",public"`
}

func (c *AggregationCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	v, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	if err = v.AssertDifferentProofs(c.BaseKey, c.CircuitKeys, c.Selectors, c.Proofs, c.Witnesses); err != nil {
		return fmt.Errorf("assert proofs: %w", err)
	}
	return nil
}

func TestBLS12InBW6Multi(t *testing.T) {
	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()
	nbCircuits := 5
	nbProofs := 5
	assert := test.NewAssert(t)
	ccss, vks, pks := getParametricSetups(assert, innerField, nbCircuits)
	innerProofs := make([]native_plonk.Proof, nbProofs)
	innerWitnesses := make([]witness.Witness, nbProofs)
	innerSelectors := make([]int, nbProofs)
	for i := 0; i < nbProofs; i++ {
		innerSelectors[i], innerWitnesses[i], innerProofs[i] = getRandomParametricProof(assert, innerField, outerField, ccss, vks, pks)
	}

	circuitBvk, err := ValueOfBaseVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](vks[0])
	assert.NoError(err)
	circuitVks := make([]CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine], nbCircuits)
	for i := range circuitVks {
		circuitVks[i], err = ValueOfCircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine](vks[i])
		assert.NoError(err)
	}
	circuitSelector := make([]frontend.Variable, nbProofs)
	for i := range circuitSelector {
		circuitSelector[i] = innerSelectors[i]
	}
	circuitProofs := make([]Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine], nbProofs)
	for i := range circuitProofs {
		circuitProofs[i], err = ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProofs[i])
		assert.NoError(err)
	}
	circuitWitnesses := make([]Witness[sw_bls12377.ScalarField], nbProofs)
	for i := range circuitWitnesses {
		circuitWitnesses[i], err = ValueOfWitness[sw_bls12377.ScalarField](innerWitnesses[i])
		assert.NoError(err)
	}
	aggCircuit := &AggregationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		BaseKey:     circuitBvk,
		CircuitKeys: make([]CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine], nbCircuits),
		Selectors:   make([]frontend.Variable, nbProofs),
		Proofs:      make([]Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine], nbProofs),
		Witnesses:   make([]Witness[sw_bls12377.ScalarField], nbProofs),
	}
	for i := 0; i < nbCircuits; i++ {
		aggCircuit.CircuitKeys[i] = PlaceholderCircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine](ccss[i])
	}
	for i := 0; i < nbProofs; i++ {
		aggCircuit.Proofs[i] = PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccss[0])
		aggCircuit.Witnesses[i] = PlaceholderWitness[sw_bls12377.ScalarField](ccss[0])
	}
	aggAssignment := &AggregationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		CircuitKeys: circuitVks,
		Selectors:   circuitSelector,
		Proofs:      circuitProofs,
		Witnesses:   circuitWitnesses,
	}
	err = test.IsSolved(aggCircuit, aggAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

type AggregationCircuitWithHash[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BaseKey     BaseVerifyingKey[FR, G1El, G2El] `gnark:"-"`
	CircuitKeys []CircuitVerifyingKey[FR, G1El]
	Selectors   []frontend.Variable
	Proofs      []Proof[FR, G1El, G2El]
	Witnesses   []Witness[FR]
	WitnessHash frontend.Variable
}

func (c *AggregationCircuitWithHash[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	v, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	var fr FR
	h, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return fmt.Errorf("new hash: %w", err)
	}
	crv, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	for i := range c.Witnesses {
		for j := range c.Witnesses[i].Public {
			h.Write(crv.MarshalScalar(c.Witnesses[i].Public[j])...)
		}
	}
	s := h.Sum()
	api.AssertIsEqual(s, c.WitnessHash)
	if err = v.AssertDifferentProofs(c.BaseKey, c.CircuitKeys, c.Selectors, c.Proofs, c.Witnesses); err != nil {
		return fmt.Errorf("assert proofs: %w", err)
	}
	return nil
}

func TestBLS12InBW6MultiHashed(t *testing.T) {
	// in previous test we provided all the public inputs of the inner circuits
	// as public witness of the aggregation circuit. This is not efficient
	// though - public witness has to be public and increases calldata cost when
	// done in Solidity (also increases verifier cost). Instead, we can only
	// provide hash of the public input of the inne circuits as public input to
	// the aggregation circuit and verify inside the aggregation circuit that
	// the private input corresponds.
	//
	// In practice this is even more involved - we're storing the merkle root of
	// the whole state and would be providing this as an input.
	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()
	nbCircuits := 4
	nbProofs := 20
	assert := test.NewAssert(t)
	ccss, vks, pks := getParametricSetups(assert, innerField, nbCircuits)
	innerProofs := make([]native_plonk.Proof, nbProofs)
	innerWitnesses := make([]witness.Witness, nbProofs)
	innerSelectors := make([]int, nbProofs)
	for i := 0; i < nbProofs; i++ {
		innerSelectors[i], innerWitnesses[i], innerProofs[i] = getRandomParametricProof(assert, innerField, outerField, ccss, vks, pks)
	}

	circuitBvk, err := ValueOfBaseVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](vks[0])
	assert.NoError(err)
	circuitVks := make([]CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine], nbCircuits)
	for i := range circuitVks {
		circuitVks[i], err = ValueOfCircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine](vks[i])
		assert.NoError(err)
	}
	circuitSelector := make([]frontend.Variable, nbProofs)
	for i := range circuitSelector {
		circuitSelector[i] = innerSelectors[i]
	}
	circuitProofs := make([]Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine], nbProofs)
	for i := range circuitProofs {
		circuitProofs[i], err = ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProofs[i])
		assert.NoError(err)
	}
	circuitWitnesses := make([]Witness[sw_bls12377.ScalarField], nbProofs)
	for i := range circuitWitnesses {
		circuitWitnesses[i], err = ValueOfWitness[sw_bls12377.ScalarField](innerWitnesses[i])
		assert.NoError(err)
	}
	// hash to compute the public hash, which is the hash of all the public inputs
	// of all the inner circuits
	h, err := recursion.NewShort(outerField, innerField)
	assert.NoError(err)
	for i := 0; i < nbProofs; i++ {
		tvec := innerWitnesses[i].Vector().(fr_bls12377.Vector)
		for j := range tvec {
			h.Write(tvec[j].Marshal())
		}
	}
	digest := h.Sum(nil)

	aggAssignment := &AggregationCircuitWithHash[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		CircuitKeys: circuitVks,
		Selectors:   circuitSelector,
		Proofs:      circuitProofs,
		Witnesses:   circuitWitnesses,
		WitnessHash: digest,
	}

	aggCircuit := &AggregationCircuitWithHash[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		BaseKey:     circuitBvk,
		CircuitKeys: make([]CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine], nbCircuits),
		Selectors:   make([]frontend.Variable, nbProofs),
		Proofs:      make([]Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine], nbProofs),
		Witnesses:   make([]Witness[sw_bls12377.ScalarField], nbProofs),
	}
	for i := 0; i < nbCircuits; i++ {
		aggCircuit.CircuitKeys[i] = PlaceholderCircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine](ccss[i])
	}
	for i := 0; i < nbProofs; i++ {
		aggCircuit.Proofs[i] = PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccss[0])
		aggCircuit.Witnesses[i] = PlaceholderWitness[sw_bls12377.ScalarField](ccss[0])
	}
	err = test.IsSolved(aggCircuit, aggAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}
