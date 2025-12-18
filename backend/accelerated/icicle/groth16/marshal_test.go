//go:build icicle

package groth16_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/accelerated/icicle/groth16"
	icicle_groth16 "github.com/consensys/gnark/backend/accelerated/icicle/groth16"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
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

func testMarshalNativeToIcicle(t *testing.T, curve ecc.ID) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	nativePK, vk, err := native_groth16.Setup(ccs)
	assert.NoError(err)
	iciPK := icicle_groth16.NewProvingKey(curve)
	buf := new(bytes.Buffer)
	_, err = nativePK.WriteTo(buf)
	assert.NoError(err)
	_, err = iciPK.ReadFrom(buf)
	assert.NoError(err)
	if iciPK.IsDifferent(nativePK) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, curve.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)
	proofNative, err := native_groth16.Prove(ccs, nativePK, w)
	assert.NoError(err)
	proofIcicle, err := icicle_groth16.Prove(ccs, iciPK, w)
	assert.NoError(err)
	err = groth16.Verify(proofNative, vk, pw)
	assert.NoError(err)
	err = groth16.Verify(proofIcicle, vk, pw)
	assert.NoError(err)
}

func testMarshalIcicleToNative(t *testing.T, curve ecc.ID) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	iciPK, vk, err := icicle_groth16.Setup(ccs)
	assert.NoError(err)
	nativePK := native_groth16.NewProvingKey(curve)
	buf := new(bytes.Buffer)
	_, err = iciPK.WriteTo(buf)
	assert.NoError(err)
	_, err = nativePK.ReadFrom(buf)
	assert.NoError(err)
	if iciPK.IsDifferent(nativePK) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, curve.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)
	proofNative, err := native_groth16.Prove(ccs, nativePK, w)
	assert.NoError(err)
	proofIcicle, err := icicle_groth16.Prove(ccs, iciPK, w)
	assert.NoError(err)
	err = groth16.Verify(proofNative, vk, pw)
	assert.NoError(err)
	err = groth16.Verify(proofIcicle, vk, pw)
	assert.NoError(err)
}

func TestMarshalNativeToIcicle(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BLS12_377, ecc.BLS12_381, ecc.BN254, ecc.BW6_761} {
		t.Run(fmt.Sprintf("curve=%s", curve.String()), func(t *testing.T) {
			testMarshalNativeToIcicle(t, curve)
		})
	}
}

func TestMarshalIcicleToNative(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BLS12_377, ecc.BLS12_381, ecc.BN254, ecc.BW6_761} {
		t.Run(fmt.Sprintf("curve=%s", curve.String()), func(t *testing.T) {
			testMarshalIcicleToNative(t, curve)
		})
	}
}
