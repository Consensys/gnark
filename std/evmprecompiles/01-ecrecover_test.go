package evmprecompiles

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
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
	Strict   frontend.Variable
	Expected sw_emulated.AffinePoint[emulated.Secp256k1Fp]
}

func (c *ecrecoverCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	res := ECRecover(api, c.Message, c.V, c.R, c.S, c.Strict)
	curve.AssertIsEqual(&c.Expected, res)
	return nil
}

func testRoutineECRecover(t *testing.T, wantStrict bool) (circ, wit *ecrecoverCircuit, largeS bool) {
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))

	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	for {
		v, r, s, err = sk.SignForRecover(msg, nil)
		if err != nil {
			t.Fatal("sign", err)
		}
		if !wantStrict || halfFr.Cmp(s) > 0 {
			break
		}
	}
	strict := 0
	if wantStrict {
		strict = 1
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message: emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:       v + 27, // EVM constant
		R:       emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:       emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:  strict,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	return &circuit, &witness, halfFr.Cmp(s) <= 0
}

func TestECRecoverCircuitShortStrict(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness, _ := testRoutineECRecover(t, true)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortLax(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness, _ := testRoutineECRecover(t, false)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))
	var circuit, witness *ecrecoverCircuit
	var largeS bool
	for {
		circuit, witness, largeS = testRoutineECRecover(t, false)
		if largeS {
			witness.Strict = 1
			break
		}
	}
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.Error(err)
}

func TestECRecoverCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness, _ := testRoutineECRecover(t, false)

	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254, ecc.BLS12_377),
		test.NoProverChecks(),
	)
}
