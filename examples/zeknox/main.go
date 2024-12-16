// main.go

package main

import (
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
	cryptosha3 "golang.org/x/crypto/sha3"
)

type sha3Circuit struct {
	In       []uints.U8 `gnark:",secret"`
	Expected [32]uints.U8 `gnark:",public"`
}

func (c *sha3Circuit) Define(api frontend.API) error {
	h, err := sha3.New256(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	h.Write(c.In)
	res := h.Sum()

	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

const inputLength = 128

func compileCircuit(newBuilder frontend.NewBuilder) (constraint.ConstraintSystem, error) {
	circuit := sha3Circuit{
		In: make([]uints.U8, inputLength),
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), newBuilder, &circuit)
	if err != nil {
		return nil, err
	}
	return r1cs, nil
}

func generateWitness() (witness.Witness, error) {
	input := make([]byte, inputLength)
	dgst := cryptosha3.Sum256(input)
	witness := sha3Circuit{
		In: uints.NewU8Array(input[:]),
	}
	copy(witness.Expected[:], uints.NewU8Array(dgst[:]))

	witnessData, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	return witnessData, nil
}

func main() {
	r1cs, err := compileCircuit(r1cs.NewBuilder)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	// Witness generation
	witnessData, err := generateWitness()
	if err != nil {
		panic(err)
	}
	publicWitness, err := witnessData.Public()
	if err != nil {
		panic(err)
	}

	// GPU Prove & Verify
	start := time.Now()
	proofZeknox, err := groth16.Prove(r1cs, pk, witnessData, backend.WithZeknoxAcceleration())
	if err != nil {
		panic(err)
	}
	log.Printf("zeknox GPU prove: %d ms", time.Since(start).Milliseconds())
	if err := groth16.Verify(proofZeknox, vk, publicWitness); err != nil {
		panic(err)
	}

	// CPU Prove & Verify
	start = time.Now()
	proof, err := groth16.Prove(r1cs, pk, witnessData)
	if err != nil {
		panic(err)
	}
	log.Printf("CPU prove: %d ms", time.Since(start).Milliseconds())
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}
}
