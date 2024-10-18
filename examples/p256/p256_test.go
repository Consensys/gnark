package p256

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestP256(t *testing.T) {
	assert := test.NewAssert(t)
	witnessCircuit := generateWitnessCircuit()
	circuit := EcdsaCircuit[emulated.P256Fp, emulated.P256Fr]{}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witnessCircuit), test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithProverOpts(backend.WithZeknoxAcceleration()))
}
