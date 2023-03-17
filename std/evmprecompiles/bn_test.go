package evmprecompiles

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ecaddCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	X1       sw_emulated.AffinePoint[emulated.BN254Fp]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *ecaddCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := ECAdd(api, &c.X0, &c.X1)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECAdd(t *testing.T) (circ, wit frontend.Circuit) {
	_, _, G, _ := bn254.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P, Q bn254.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	var expected bn254.G1Affine
	expected.Add(&P, &Q)
	circuit := ecaddCircuit{}
	witness := ecaddCircuit{
		X0: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](P.X),
			Y: emulated.ValueOf[emulated.BN254Fp](P.Y),
		},
		X1: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](Q.X),
			Y: emulated.ValueOf[emulated.BN254Fp](Q.Y),
		},
		Expected: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](expected.X),
			Y: emulated.ValueOf[emulated.BN254Fp](expected.Y),
		},
	}
	return &circuit, &witness
}

func TestECAddCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAdd(t)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECAddCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAdd(t)
	assert.ProverSucceeded(circuit, witness,
		test.NoFuzzing(), test.NoSerialization(),
		test.WithBackends(backend.GROTH16, backend.PLONK), test.WithCurves(ecc.BN254),
	)
}

type ecmulCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	U        emulated.Element[emulated.BN254Fr]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *ecmulCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := ECMul(api, &c.X0, &c.U)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECMul(t *testing.T) (circ, wit frontend.Circuit) {
	_, _, G, _ := bn254.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P bn254.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	var expected bn254.G1Affine
	expected.ScalarMultiplication(&P, v.BigInt(new(big.Int)))
	circuit := ecmulCircuit{}
	witness := ecmulCircuit{
		X0: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](P.X),
			Y: emulated.ValueOf[emulated.BN254Fp](P.Y),
		},
		U: emulated.ValueOf[emulated.BN254Fr](v),
		Expected: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](expected.X),
			Y: emulated.ValueOf[emulated.BN254Fp](expected.Y),
		},
	}
	return &circuit, &witness
}

func TestECMulCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECMul(t)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECMulCircuitFull(t *testing.T) {
	t.Skip("skipping very long test")
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECMul(t)
	assert.ProverSucceeded(circuit, witness,
		test.NoFuzzing(), test.NoSerialization(),
		test.WithBackends(backend.GROTH16, backend.PLONK), test.WithCurves(ecc.BN254),
	)
}

type ecpairCircuit struct {
	P        sw_bn254.G1Affine
	Q        sw_bn254.G2Affine
	Expected sw_bn254.GTEl
}

func (c *ecpairCircuit) Define(api frontend.API) error {
	pair, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	res := ECPair(api, &c.P, &c.Q)
	pair.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestECPairCircuitShort(t *testing.T) {
	_, _, G1, G2 := bn254.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P bn254.G1Affine
	P.ScalarMultiplication(&G1, u.BigInt(new(big.Int)))
	var Q bn254.G2Affine
	Q.ScalarMultiplication(&G2, v.BigInt(new(big.Int)))
	expected, err := bn254.Pair([]bn254.G1Affine{P}, []bn254.G2Affine{Q})
	if err != nil {
		t.Fatal(err)
	}
	circuit := ecpairCircuit{}
	witness := ecpairCircuit{
		P:        sw_bn254.NewG1Affine(P),
		Q:        sw_bn254.NewG2Affine(Q),
		Expected: sw_bn254.NewGTEl(expected),
	}
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
