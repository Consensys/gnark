package groth16

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16backend_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16backend_bls24315 "github.com/consensys/gnark/backend/groth16/bls24-315"
	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// TODO: placeholder circuits for when we have implemented commitment verification for the verifier.
type InnerCircuitSHA2 struct {
	PreImage [9]uints.U8
	Digest   [32]uints.U8 `gnark:",public"`
}

func (c *InnerCircuitSHA2) Define(api frontend.API) error {
	h, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("new sha2: %w", err)
	}
	h.Write(c.PreImage[:])
	dgst := h.Sum()
	if len(dgst) != len(c.Digest) {
		return fmt.Errorf("wrong digest size")
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return fmt.Errorf("new uints api: %w", err)
	}
	for i := range dgst {
		uapi.ByteAssertEq(dgst[i], c.Digest[i])
	}
	return nil
}

type InnerCircuitEmulation struct {
	P, Q emulated.Element[emparams.Goldilocks]
	N    emulated.Element[emparams.Goldilocks] `gnark:",public"`
}

func (c *InnerCircuitEmulation) Define(api frontend.API) error {
	f, err := emulated.NewField[emparams.Goldilocks](api)
	if err != nil {
		return err
	}
	res := f.Mul(&c.P, &c.Q)
	f.AssertIsEqual(res, &c.N)
	return nil
}

type InnerCircuitNative struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInner(assert *test.Assert, field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitNative{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitNative{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[G1El, G2El]
	VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	InnerWitness Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := NewVerifier(curve, pairing)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func TestBN254InBN254(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BN254.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BN254))
}

func TestBLS12InBW6(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BW6_761))
}

type WitnessCircut struct {
	A emulated.Element[emparams.Secp256k1Fr] `gnark:",public"`
}

func (c *WitnessCircut) Define(frontend.API) error { return nil }

func TestValueOfWitness(t *testing.T) {
	assignment := WitnessCircut{
		A: emulated.ValueOf[emparams.Secp256k1Fr]("1234"),
	}
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bn254.ScalarField](w)
		assert.NoError(err)
		_ = ww
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bls12377.ScalarField](w)
		assert.NoError(err)
		_ = ww
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bls12381.ScalarField](w)
		assert.NoError(err)
		_ = ww
	}, "bls12381")
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BLS24_315.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bls24315.ScalarField](w)
		assert.NoError(err)
		_ = ww
	}, "bls24315")
}

func TestValueOfProof(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		_, _, G1, G2 := bn254.Generators()
		proof := groth16backend_bn254.Proof{
			Ar:  G1,
			Krs: G1,
			Bs:  G2,
		}
		assignment, err := ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](&proof)
		assert.NoError(err)
		_ = assignment
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, G2 := bls12377.Generators()
		proof := groth16backend_bls12377.Proof{
			Ar:  G1,
			Krs: G1,
			Bs:  G2,
		}
		assignment, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](&proof)
		assert.NoError(err)
		_ = assignment
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, G2 := bls12381.Generators()
		proof := groth16backend_bls12381.Proof{
			Ar:  G1,
			Krs: G1,
			Bs:  G2,
		}
		assignment, err := ValueOfProof[sw_bls12381.G1Affine, sw_bls12381.G2Affine](&proof)
		assert.NoError(err)
		_ = assignment
	}, "bls12381")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, G2 := bls24315.Generators()
		proof := groth16backend_bls24315.Proof{
			Ar:  G1,
			Krs: G1,
			Bs:  G2,
		}
		assignment, err := ValueOfProof[sw_bls24315.G1Affine, sw_bls24315.G2Affine](&proof)
		assert.NoError(err)
		_ = assignment
	}, "bls24315")
}

func TestValueOfVerifyingKey(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &WitnessCircut{})
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		_ = vvk
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &WitnessCircut{})
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
		assert.NoError(err)
		_ = vvk
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &WitnessCircut{})
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](vk)
		assert.NoError(err)
		_ = vvk
	}, "bls12381")
	assert.Run(func(assert *test.Assert) {
		ccs, err := frontend.Compile(ecc.BLS24_315.ScalarField(), r1cs.NewBuilder, &WitnessCircut{})
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bls24315.G1Affine, sw_bls24315.G2Affine, sw_bls24315.GT](vk)
		assert.NoError(err)
		_ = vvk
	}, "bls24315")
}

func TestBW6InBN254(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BN254))
}

func TestBW6InBN254Precomputed(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BN254))
}

type OuterCircuitConstant[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[G1El, G2El]
	vk           VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness Witness[FR]
}

func (c *OuterCircuitConstant[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := NewVerifier(curve, pairing)
	err = verifier.AssertProof(c.vk, c.Proof, c.InnerWitness)
	return err
}

func TestBW6InBN254Constant(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuitConstant[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		vk:           circuitVk,
	}
	outerAssignment := &OuterCircuitConstant[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BN254))
}
