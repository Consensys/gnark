//go:build icicle

package bls12377_test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	icicle_bls12377 "github.com/consensys/gnark/backend/accelerated/icicle/groth16/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	cs_bls12377 "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type circuit struct {
	A, B frontend.Variable `gnark:",public"`
	Res  frontend.Variable
}

func (c *circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.Res)
	return nil
}

func TestMarshal(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	tCcs := ccs.(*cs_bls12377.R1CS)
	nativePK := groth16_bls12377.ProvingKey{}
	nativeVK := groth16_bls12377.VerifyingKey{}
	err = groth16_bls12377.Setup(tCcs, &nativePK, &nativeVK)
	assert.NoError(err)

	pk := groth16.NewProvingKey(ecc.BLS12_377)
	buf := new(bytes.Buffer)
	_, err = nativePK.WriteTo(buf)
	assert.NoError(err)
	_, err = pk.ReadFrom(buf)
	assert.NoError(err)
	if pk.IsDifferent(&nativePK) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)
	proofNative, err := groth16_bls12377.Prove(tCcs, &nativePK, w)
	assert.NoError(err)
	proofIcicle, err := groth16.Prove(tCcs, pk, w, backend.WithIcicleAcceleration())
	assert.NoError(err)
	err = groth16.Verify(proofNative, &nativeVK, pw)
	assert.NoError(err)
	err = groth16.Verify(proofIcicle, &nativeVK, pw)
	assert.NoError(err)
}

func TestMarshal2(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	tCcs := ccs.(*cs_bls12377.R1CS)
	iciPK := icicle_bls12377.ProvingKey{}
	iciVK := groth16_bls12377.VerifyingKey{}
	err = groth16_bls12377.Setup(tCcs, &iciPK.ProvingKey, &iciVK)
	assert.NoError(err)

	nativePK := groth16_bls12377.ProvingKey{}
	buf := new(bytes.Buffer)
	_, err = iciPK.WriteTo(buf)
	assert.NoError(err)
	_, err = nativePK.ReadFrom(buf)
	assert.NoError(err)
	if iciPK.IsDifferent(&nativePK) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)
	proofNative, err := groth16_bls12377.Prove(tCcs, &nativePK, w)
	assert.NoError(err)
	proofIcicle, err := groth16.Prove(tCcs, &iciPK, w, backend.WithIcicleAcceleration())
	assert.NoError(err)
	err = groth16.Verify(proofNative, &iciVK, pw)
	assert.NoError(err)
	err = groth16.Verify(proofIcicle, &iciVK, pw)
	assert.NoError(err)
}
