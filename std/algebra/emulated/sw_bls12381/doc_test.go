package sw_bls12381_test

import (
	"crypto/rand"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

/*
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
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("compiled")
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("setup done")
	}
	secretWitness, err := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	} else {
		fmt.Println("secret witness")
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness")
	}
	proof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proof")
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verify")
	}
}
*/

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
