package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	bn254plonk "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/plonk/bn254/solidity/tmpl"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

// ---------------------------------------------------------
// single commit
type commitmentCircuit struct {
	Public [3]frontend.Variable `gnark:",public"`
	X      [3]frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {

	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("type %T doesn't impl the Committer interface", api)
	}
	commitment, err := committer.Commit(c.X[:]...)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		api.AssertIsDifferent(commitment, c.X[i])
		for _, p := range c.Public {
			api.AssertIsDifferent(p, 0)
		}
	}
	return err
}

func getVkProofCommitmentCircuit() (bn254plonk.Proof, bn254plonk.VerifyingKey, []fr.Element) {

	var circuit commitmentCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness commitmentCircuit
	witness.X = [3]frontend.Variable{3, 4, 5}
	witness.Public = [3]frontend.Variable{6, 7, 8}
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, err := test.NewKZGSRS(ccs)
	checkError(err)

	pk, vk, err := plonk.Setup(ccs, srs)
	checkError(err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	checkError(err)

	err = plonk.Verify(proof, vk, witnessPublic)
	checkError(err)

	tvk := vk.(*bn254plonk.VerifyingKey)
	tproof := proof.(*bn254plonk.Proof)

	ipi := witnessPublic.Vector()
	pi := ipi.(fr.Vector)

	return *tproof, *tvk, pi
}

// ---------------------------------------------------------
// vanilla plonk
type vanillaPlonk struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *vanillaPlonk) Define(api frontend.API) error {
	a := api.Mul(circuit.X, circuit.X, circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(a, circuit.Y)
	return nil
}

func getVkProofVanillaPlonkCircuit() (bn254plonk.Proof, bn254plonk.VerifyingKey, []fr.Element) {

	var circuit vanillaPlonk
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness vanillaPlonk
	witness.X = 2
	witness.Y = 32
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, err := test.NewKZGSRS(ccs)
	checkError(err)

	pk, vk, err := plonk.Setup(ccs, srs)
	checkError(err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	checkError(err)

	err = plonk.Verify(proof, vk, witnessPublic)
	checkError(err)

	tvk := vk.(*bn254plonk.VerifyingKey)
	tproof := proof.(*bn254plonk.Proof)

	ipi := witnessPublic.Vector()
	pi := ipi.(fr.Vector)

	return *tproof, *tvk, pi
}

// ---------------------------------------------------------
// multi commit

type MultiCommit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *MultiCommit) Define(api frontend.API) error {

	a := api.Mul(circuit.X, circuit.X)
	b := api.Mul(a, circuit.X)

	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("type %T doesn't impl the Committer interface", api)
	}
	c1, err := committer.Commit(a)
	if err != nil {
		return err
	}

	c2, err := committer.Commit(b)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(c1, circuit.Y)
	api.AssertIsDifferent(c2, circuit.Y)

	return nil
}

func getVkProofMultiCommitCircuit() (bn254plonk.Proof, bn254plonk.VerifyingKey, []fr.Element) {

	var circuit MultiCommit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness MultiCommit
	witness.X = 2
	witness.Y = 32
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, err := test.NewKZGSRS(ccs)
	checkError(err)

	pk, vk, err := plonk.Setup(ccs, srs)
	checkError(err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	checkError(err)

	err = plonk.Verify(proof, vk, witnessPublic)
	checkError(err)

	tvk := vk.(*bn254plonk.VerifyingKey)
	tproof := proof.(*bn254plonk.Proof)

	ipi := witnessPublic.Vector()
	pi := ipi.(fr.Vector)

	return *tproof, *tvk, pi
}

func writeData(vk bn254plonk.VerifyingKey, proof bn254plonk.Proof) error {

	fproof, err := os.Create("proof")
	if err != nil {
		return err
	}
	_, err = proof.WriteRawTo(fproof)
	if err != nil {
		return err
	}

	fvk, err := os.Create("vk")
	if err != nil {
		return err
	}
	_, err = vk.WriteRawTo(fvk)
	if err != nil {
		return err
	}

	fproof.Close()

	return nil
}

//go:generate go run main.go
func main() {

	proof, vk, pi := getVkProofMultiCommitCircuit()
	// proof, vk, pi := getVkProofCommitmentCircuit()
	// proof, vk, pi := getVkProofVanillaPlonkCircuit()

	err := writeData(vk, proof)
	checkError(err)

	err = tmpl.GenerateVerifier(vk, proof, pi, "../contracts")
	checkError(err)
	// printvk(vk)

}
