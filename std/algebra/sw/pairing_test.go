package sw

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower"
	"github.com/consensys/gnark/std/algebra/tower/fp12"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/test"
)

type wideMillerLoopCircuit[T tower.Tower, B tower.Basis, PT tower.TowerPt[T, B], PB tower.BasisPt[B]] struct {
	P G1Affine
	Q G2Affine[B, PB]
	R GT[T, B, PT, PB]
}

func (circuit *wideMillerLoopCircuit[T, B, PT, PB]) Define(api frontend.API) error {
	gt, err := NewGT[T, B, PT, PB](api)
	if err != nil {
		return fmt.Errorf("new gt: %w", err)
	}
	res, err := gt.WideMillerLoop(G1G2[B, PB]{circuit.P, circuit.Q})
	if err != nil {
		return fmt.Errorf("wide miller loop: %w", err)
	}
	PT(&(res.E)).MustBeEqual(circuit.R.E)
	return nil
}

func TestWideMillerLoop(t *testing.T) {
	assert := test.NewAssert(t)
	var r1, r2 bls12377fr.Element
	r1b := big.NewInt(1)
	r2b := big.NewInt(2)
	r1.SetRandom()
	r2.SetRandom()
	r1.ToBigIntRegular(r1b)
	r2.ToBigIntRegular(r2b)
	_, _, a, b := bls12377.Generators()
	a.ScalarMultiplication(&a, r1b)
	b.ScalarMultiplication(&b, r2b)
	c, err := bls12377.MillerLoop([]bls12377.G1Affine{a}, []bls12377.G2Affine{b})
	assert.NoError(err)

	var circuit, circuitWitness wideMillerLoopCircuit[fp12.E12, fp2.E2]
	circuitWitness.P = FromG1Affine(a)
	circuitWitness.Q = FromG2Affine[fp2.E2](b)
	circuitWitness.R = FromGT[fp12.E12, fp2.E2](c)

	ccs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	fullWitness, err := frontend.NewWitness(&circuitWitness, ecc.BW6_761)
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	assert.NoError(err)
	err = groth16.Verify(proof, vk, fullWitness)
	assert.NoError(err)

	// assert.SolvingSucceeded(&circuit, &circuitWitness, test.WithCurves(ecc.BW6_761))
}

type pairingCircuit[T tower.Tower, B tower.Basis, PT tower.TowerPt[T, B], PB tower.BasisPt[B]] struct {
	P G1Affine         `gnark:",public"`
	Q G2Affine[B, PB]  `gnark:",public"`
	R GT[T, B, PT, PB] `gnark:",public"`
}

func (circuit *pairingCircuit[T, B, PT, PB]) Define(api frontend.API) error {
	gt, err := NewGT[T, B, PT, PB](api)
	if err != nil {
		return fmt.Errorf("new gt: %w", err)
	}
	res := gt.Pairing(circuit.P, circuit.Q)
	PT(&(res.E)).MustBeEqual(circuit.R.E)

	return nil
}

func TestPairing(t *testing.T) {
	assert := test.NewAssert(t)
	var r1, r2 bls12377fr.Element
	r1b := big.NewInt(1)
	r2b := big.NewInt(2)
	r1.SetRandom()
	r2.SetRandom()
	r1.ToBigIntRegular(r1b)
	r2.ToBigIntRegular(r2b)
	_, _, a, b := bls12377.Generators()
	a.ScalarMultiplication(&a, r1b)
	b.ScalarMultiplication(&b, r2b)
	d, err := bls12377.Pair([]bls12377.G1Affine{a}, []bls12377.G2Affine{b})
	assert.NoError(err)

	var circuit, circuitWitness pairingCircuit[fp12.E12, fp2.E2]
	circuitWitness.P = FromG1Affine(a)
	circuitWitness.Q = FromG2Affine[fp2.E2](b)
	circuitWitness.R = FromGT[fp12.E12, fp2.E2](d)

	ccs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	fullWitness, err := frontend.NewWitness(&circuitWitness, ecc.BW6_761)
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	assert.NoError(err)

	publicWitness, err := fullWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(err)

	// assert.SolvingSucceeded(&circuit, &circuitWitness, test.WithCurves(ecc.BW6_761))
}

func BenchmarkPairingCompile(bb *testing.B) {
	var r1, r2 bls12377fr.Element
	r1b := big.NewInt(1)
	r2b := big.NewInt(2)
	r1.SetRandom()
	r2.SetRandom()
	r1.ToBigIntRegular(r1b)
	r2.ToBigIntRegular(r2b)
	_, _, a, b := bls12377.Generators()
	a.ScalarMultiplication(&a, r1b)
	b.ScalarMultiplication(&b, r2b)
	d, err := bls12377.Pair([]bls12377.G1Affine{a}, []bls12377.G2Affine{b})
	if err != nil {
		bb.Fatal(bb)
	}
	var circuit, circuitWitness pairingCircuit[fp12.E12, fp2.E2]
	circuitWitness.P = FromG1Affine(a)
	circuitWitness.Q = FromG2Affine[fp2.E2](b)
	circuitWitness.R = FromGT[fp12.E12, fp2.E2](d)
	for i := 0; i < bb.N; i++ {
		ccs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
		if err != nil {
			bb.Fatal(err)
		}
		_ = ccs
	}
}
