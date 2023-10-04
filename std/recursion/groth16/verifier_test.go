package groth16

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

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

type InnerCircuitNative struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
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

// BN254-in-BN254 using field emulation
type OuterCircuitBN254 struct {
	Proof        Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness Witness[sw_bn254.Scalar]
}

func (c *OuterCircuitBN254) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	verifier := NewVerifier(curve, pairing)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func TestBN254BN254(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &InnerCircuitNative{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitNative{
		P: 3,
		Q: 5,
		N: 15,
	}
	witness, err := frontend.NewWitness(innerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(innerCcs, innerPK, witness)
	assert.NoError(err)
	pubWitness, err := witness.Public()
	assert.NoError(err)
	err = groth16.Verify(proof, innerVK, pubWitness)
	assert.NoError(err)

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bn254.Scalar](witness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
	assert.NoError(err)
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &OuterCircuitBN254{InnerWitness: circuitWitness.ToPlaceholder(), VerifyingKey: circuitVk.ToPlaceholder()})
	assert.NoError(err)

	outerAssignment := &OuterCircuitBN254{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	outerPK, outerVK, err := groth16.Setup(outerCcs)
	assert.NoError(err)
	outerProof, err := groth16.Prove(outerCcs, outerPK, outerWitness)
	assert.NoError(err)
	pubOuterWitness, err := outerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(outerProof, outerVK, pubOuterWitness)
	assert.NoError(err)
}

// BLS12377-in-BW6 using 2-chain

func getPreimageAndDigest() (preimage [9]byte, digest [32]byte) {
	copy(preimage[:], []byte("recursion"))
	digest = sha256.Sum256(preimage[:])
	return
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
		ww, err := ValueOfWitness[sw_bn254.Scalar](w)
		assert.NoError(err)
		_ = ww
	}, "bn")
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bls12377.Scalar](w)
		assert.NoError(err)
		_ = ww
	}, "bls12377")
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
	}, "bn-in-bn")
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
	}, "bls12-in-bw6")
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
	}, "bn")
	assert.Run(func(assert *test.Assert) {
		ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &WitnessCircut{})
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
		assert.NoError(err)
		_ = vvk
	}, "bls12377")
}
