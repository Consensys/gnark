package zeknox_bn254_test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	zeknox_bn254 "github.com/consensys/gnark/backend/groth16/bn254/zeknox"
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

func TestMarshalNative(t *testing.T) {
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
}

func TestMarshalZeknox(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	tCcs := ccs.(*cs_bn254.R1CS)
	zePK := zeknox_bn254.ProvingKey{}
	VK := groth16_bn254.VerifyingKey{}
	err = zeknox_bn254.Setup(tCcs, &zePK, &VK)
	assert.NoError(err)

	nativePK := groth16_bn254.ProvingKey{}
	buf := new(bytes.Buffer)
	_, err = zePK.WriteTo(buf)
	assert.NoError(err)
	_, err = nativePK.ReadFrom(buf)
	assert.NoError(err)
	if zePK.IsDifferent(&nativePK) {
		t.Error("marshal output difference")
	}
}
