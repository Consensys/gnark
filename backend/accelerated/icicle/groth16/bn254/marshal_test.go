//go:build icicle

package bn254_test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	icicle_bn254 "github.com/consensys/gnark/backend/accelerated/icicle/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
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
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	tCcs := ccs.(*cs_bn254.R1CS)
	nativePK := groth16_bn254.ProvingKey{}
	nativeVK := groth16_bn254.VerifyingKey{}
	err = groth16_bn254.Setup(tCcs, &nativePK, &nativeVK)
	assert.NoError(err)

	pk := groth16.NewProvingKey(ecc.BN254)
	buf := new(bytes.Buffer)
	_, err = nativePK.WriteTo(buf)
	assert.NoError(err)
	_, err = pk.ReadFrom(buf)
	assert.NoError(err)
	if pk.IsDifferent(&nativePK) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)
	proofNative, err := groth16_bn254.Prove(tCcs, &nativePK, w)
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
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	tCcs := ccs.(*cs_bn254.R1CS)
	iciPK := icicle_bn254.ProvingKey{}
	iciVK := groth16_bn254.VerifyingKey{}
	err = groth16_bn254.Setup(tCcs, &iciPK.ProvingKey, &iciVK)
	assert.NoError(err)

	nativePK := groth16_bn254.ProvingKey{}
	buf := new(bytes.Buffer)
	_, err = iciPK.WriteTo(buf)
	assert.NoError(err)
	_, err = nativePK.ReadFrom(buf)
	assert.NoError(err)
	if iciPK.IsDifferent(&nativePK) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)
	proofNative, err := groth16_bn254.Prove(tCcs, &nativePK, w)
	assert.NoError(err)
	proofIcicle, err := groth16.Prove(tCcs, &iciPK, w, backend.WithIcicleAcceleration())
	assert.NoError(err)
	err = groth16.Verify(proofNative, &iciVK, pw)
	assert.NoError(err)
	err = groth16.Verify(proofIcicle, &iciVK, pw)
	assert.NoError(err)
}
