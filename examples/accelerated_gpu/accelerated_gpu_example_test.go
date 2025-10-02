//go:build icicle

package accelerated_gpu

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark/backend/accelerated/icicle"
	icicle_groth "github.com/consensys/gnark/backend/accelerated/icicle/groth16"
	"github.com/consensys/gnark/backend/solidity"

	"github.com/consensys/gnark/backend/groth16"
)

type ExampleCircuit struct {
	A   [2]sw_bls12381.G1Affine
	B   [2]sw_bls12381.G2Affine
	Res sw_bls12381.GTEl `gnark:",public"`
}

func (c *ExampleCircuit) Define(api frontend.API) error {
	pr, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	res, err := pr.Pair([]*sw_bls12381.G1Affine{&c.A[0], &c.A[1]}, []*sw_bls12381.G2Affine{&c.B[0], &c.B[1]})
	if err != nil {
		return err
	}
	pr.AssertIsEqual(res, &c.Res)

	// we have commented out another option for the circuit implementation for
	// faster testing. Comment the previous part and uncomment the following to
	// use it.

	// api.AssertIsDifferent(c.Res.A0.Limbs[0], 0) // dummy constraint to avoid empty circuit
	// api.AssertIsDifferent(c.Res.A0.Limbs[1], 0)
	// api.AssertIsDifferent(c.Res.A0.Limbs[2], 0)
	// api.AssertIsDifferent(c.Res.A0.Limbs[3], 0)
	return nil
}

func Example() {
	// generate random data
	var a [2]bls12381.G1Affine
	var b [2]bls12381.G2Affine

	var s1, s2, s3, s4 fr_bls12381.Element
	s1.MustSetRandom()
	s2.MustSetRandom()
	s3.MustSetRandom()
	s4.MustSetRandom()

	a[0].ScalarMultiplicationBase(s1.BigInt(new(big.Int)))
	a[1].ScalarMultiplicationBase(s2.BigInt(new(big.Int)))

	b[0].ScalarMultiplicationBase(s3.BigInt(new(big.Int)))
	b[1].ScalarMultiplicationBase(s4.BigInt(new(big.Int)))

	res, err := bls12381.Pair([]bls12381.G1Affine{a[0], a[1]}, []bls12381.G2Affine{b[0], b[1]})
	if err != nil {
		panic(err)
	}

	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_377, ecc.BLS12_381, ecc.BW6_761} {
		fmt.Println("testing curve", curve.String())

		// define assignment
		assignment := ExampleCircuit{
			A: [2]sw_bls12381.G1Affine{
				sw_bls12381.NewG1Affine(a[0]),
				sw_bls12381.NewG1Affine(a[1]),
			},
			B: [2]sw_bls12381.G2Affine{
				sw_bls12381.NewG2Affine(b[0]),
				sw_bls12381.NewG2Affine(b[1]),
			},
			Res: sw_bls12381.NewGTEl(res),
		}

		// run sanity check to see if the solution is valid
		err = test.IsSolved(&ExampleCircuit{}, &assignment, curve.ScalarField())
		if err != nil {
			panic(err)
		}

		// compile the circuit over given curve
		ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &ExampleCircuit{})
		if err != nil {
			panic(err)
		}

		// setup the keys. NB! Unsafe, should use MPC in production.
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			panic(err)
		}
		// create ICICLE proving key by initializing it from serialized data
		pkAcc := icicle_groth.NewProvingKey(curve)
		buf := new(bytes.Buffer)
		pk.WriteTo(buf)
		_, err = pkAcc.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		// create the witness
		wit, err := frontend.NewWitness(&assignment, curve.ScalarField())
		if err != nil {
			panic(err)
		}

		// prove natively
		proof, err := groth16.Prove(ccs, pk, wit)
		if err != nil {
			panic(err)
		}
		// prove using acceleration. We have commented out possible options for the backend.
		proofAcc, err := icicle_groth.Prove(ccs, pkAcc, wit,
			// icicle.WithBackendLibrary("/usr/local/lib/backend/"),
			// icicle.WithBackend(icicle.CUDA),
			// icicle.WithDeviceID(0),
			icicle.WithProverOptions(solidity.WithProverTargetSolidityVerifier(backend.GROTH16)),
		)
		if err != nil {
			panic(err)
		}

		// create public part of the witness
		pubwit, err := wit.Public()
		if err != nil {
			panic(err)
		}
		// ensure that both proofs verify
		err = groth16.Verify(proof, vk, pubwit)
		if err != nil {
			panic(err)
		}
		err = groth16.Verify(proofAcc, vk, pubwit)
		if err != nil {
			panic(err)
		}
	}
}
