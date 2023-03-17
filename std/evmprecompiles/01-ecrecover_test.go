package evmprecompiles

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestSignForRecoverCorrectness(t *testing.T) {
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	_, r, s, err := sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	var sig ecdsa.Signature
	r.FillBytes(sig.R[:fr.Bytes])
	s.FillBytes(sig.S[:fr.Bytes])
	sigM := sig.Bytes()
	ok, err := pk.Verify(sigM, msg, nil)
	if err != nil {
		t.Fatal("verify", err)
	}
	if !ok {
		t.Fatal("not verified")
	}
}

type ecrecoverCircuit struct {
	Message  emulated.Element[emulated.Secp256k1Fr]
	V        frontend.Variable
	R        emulated.Element[emulated.Secp256k1Fr]
	S        emulated.Element[emulated.Secp256k1Fr]
	Expected sw_emulated.AffinePoint[emulated.Secp256k1Fp]
}

func (c *ecrecoverCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	res := ECRecover(api, c.Message, c.V, c.R, c.S)
	curve.AssertIsEqual(&c.Expected, res)
	return nil
}

func testRoutineECRecover(t *testing.T) (circ, wit frontend.Circuit) {
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	v, r, s, err := sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message: emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:       v + 27, // EVM constant
		R:       emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:       emulated.ValueOf[emulated.Secp256k1Fr](s),
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	return &circuit, &witness
}

func TestECRecoverCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitFull(t *testing.T) {
	t.Skip("skipping very long test")
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t)
	assert.ProverSucceeded(circuit, witness,
		test.NoFuzzing(), test.NoSerialization(),
		test.WithBackends(backend.GROTH16, backend.PLONK), test.WithCurves(ecc.BN254),
	)
}
