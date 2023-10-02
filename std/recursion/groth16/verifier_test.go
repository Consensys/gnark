package groth16

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
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

// BN254-in-BN254 using field emulation
type OuterCircuitBN254 struct {
	Proof        Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness Witness[emulated.Element[emparams.BN254Fr]]
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
	verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return nil
}

func TestBN254BN254(t *testing.T) {
	assert := test.NewAssert(t)
	preimage, digest := getPreimageAndDigest()
	// inner proof
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &InnerCircuitSHA2{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)
	innerAssignment := &InnerCircuitSHA2{}
	copy(innerAssignment.PreImage[:], uints.NewU8Array(preimage[:]))
	copy(innerAssignment.Digest[:], uints.NewU8Array(digest[:]))
	witness, err := frontend.NewWitness(innerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(innerCcs, innerPK, witness)
	assert.NoError(err)

	// innerVKTyped, ok := innerVK.(*groth16_bn254.VerifyingKey)
	circuitWitness, err := ValueOfWitness[emulated.Element[emparams.BN254Fr]](witness)
	assert.NoError(err)
	_ = circuitWitness
	// outerAssignment := &OuterCircuitBN254{
	// 	InnerWitness: ValueOfWitness[emulated.Element[emparams.BN254Fr]](),
	// }

	_, _ = proof, innerVK
}

// BLS12377-in-BW6 using 2-chain

func getPreimageAndDigest() (preimage [9]byte, digest [32]byte) {
	copy(preimage[:], []byte("recursion"))
	digest = sha256.Sum256(preimage[:])
	return
}
