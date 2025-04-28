package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/pkg/profile"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
)

// goal here is to profile and identify the bottlenecks in the solver
// and improve the solver performance.
//
// we want a circuit that
// 1. can be solved in parallel
// 2. uses hints
// 3. has deferred constraints
//
// emulated arithmetic is a good candidate for 2 and 3, so we are going to have a toy circuit that
// does N ECRecovers checks.
const N = 10

// note that since this uses BSB22 commitments, to run only the solver the debug tag should be used
// go run -tags=debug ./main.go

func main() {
	// first we generate our witness
	witness, err := generateWitness()
	if err != nil {
		panic(fmt.Errorf("generate witness: %w", err))
	}

	// now we compile our circuit
	// note that we can also test with r1cs.NewBuilder (groth16)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &Circuit{})
	if err != nil {
		panic(fmt.Errorf("compile circuit: %w", err))
	}

	// now we solve the circuit using the solver;
	// (can use TraceProfile or CPUProfile as needed )
	// then run go tool trace trace.out
	p := profile.Start(profile.TraceProfile, profile.ProfilePath("."), profile.NoShutdownHook)

	start := time.Now()
	_, err = ccs.Solve(witness)
	took := time.Since(start)

	p.Stop()
	if err != nil {
		panic(fmt.Errorf("solve circuit: %w", err))
	}

	fmt.Printf("solved in %s\n", took)

}

type ecrecoverCircuit struct {
	Message   emulated.Element[emulated.Secp256k1Fr]
	V         frontend.Variable
	R         emulated.Element[emulated.Secp256k1Fr]
	S         emulated.Element[emulated.Secp256k1Fr]
	Strict    frontend.Variable
	IsFailure frontend.Variable
	Expected  sw_emulated.AffinePoint[emulated.Secp256k1Fp]
}

type Circuit struct {
	Instances [N]ecrecoverCircuit
}

func (c *Circuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	for i := 0; i < N; i++ {
		res := evmprecompiles.ECRecover(api, c.Instances[i].Message, c.Instances[i].V, c.Instances[i].R, c.Instances[i].S, c.Instances[i].Strict, c.Instances[i].IsFailure)
		curve.AssertIsEqual(&c.Instances[i].Expected, res)
	}
	return nil
}

func generateWitness() (witness.Witness, error) {
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	witness := &Circuit{}
	for i := 0; i < N; i++ {
		msg := []byte("test" + fmt.Sprint(i))
		v, r, s, err := sk.SignForRecover(msg, nil)
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}

		witness.Instances[i] = ecrecoverCircuit{
			Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
			V:         v + 27, // EVM constant
			R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
			S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
			Strict:    0,
			IsFailure: 0,
			Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](sk.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](sk.PublicKey.A.Y),
			},
		}
	}

	return frontend.NewWitness(witness, ecc.BN254.ScalarField())
}
