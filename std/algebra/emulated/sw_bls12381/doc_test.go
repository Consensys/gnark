package sw_bls12381_test

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

type PairCircuit struct {
	InG1 sw_bls12381.G1Affine
	InG2 sw_bls12381.G2Affine
	Res  sw_bls12381.GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	// Pair method does not check that the points are in the proper groups.
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	// Compute the pairing
	res, err := pairing.Pair([]*sw_bls12381.G1Affine{&c.InG1}, []*sw_bls12381.G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func ExamplePairing() {
	p, q, err := randomG1G2Affines()
	if err != nil {
		panic(err)
	}
	res, err := bls12381.Pair([]bls12381.G1Affine{p}, []bls12381.G2Affine{q})
	if err != nil {
		panic(err)
	}
	circuit := PairCircuit{}
	witness := PairCircuit{
		InG1: sw_bls12381.NewG1Affine(p),
		InG2: sw_bls12381.NewG2Affine(q),
		Res:  sw_bls12381.NewGTEl(res),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	secretWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}

func randomG1G2Affines() (p bls12381.G1Affine, q bls12381.G2Affine, err error) {
	_, _, G1AffGen, G2AffGen := bls12381.Generators()
	mod := bls12381.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		return p, q, err
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		return p, q, err
	}
	p.ScalarMultiplication(&G1AffGen, s1)
	q.ScalarMultiplication(&G2AffGen, s2)
	return
}
