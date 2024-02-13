package sw_bw6761_test

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
)

type PairCircuit struct {
	InG1 sw_bw6761.G1Affine
	InG2 sw_bw6761.G2Affine
	Res  sw_bw6761.GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := sw_bw6761.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	// Check if the points are in the proper groups (up to the user choice)
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	// Pair method does not check that the points are in the proper groups.
	// Compute the pairing
	res, err := pairing.Pair([]*sw_bw6761.G1Affine{&c.InG1}, []*sw_bw6761.G2Affine{&c.InG2})
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
	res, err := bw6761.Pair([]bw6761.G1Affine{p}, []bw6761.G2Affine{q})
	if err != nil {
		panic(err)
	}
	circuit := PairCircuit{}
	witness := PairCircuit{
		InG1: sw_bw6761.NewG1Affine(p),
		InG2: sw_bw6761.NewG2Affine(q),
		Res:  sw_bw6761.NewGTEl(res),
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

func randomG1G2Affines() (p bw6761.G1Affine, q bw6761.G2Affine, err error) {
	_, _, G1AffGen, G2AffGen := bw6761.Generators()
	mod := bw6761.ID.ScalarField()
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
