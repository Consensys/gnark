package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	bn254plonk "github.com/consensys/gnark/backend/plonk/bn254"

	// "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

// ------------------------------------------
// Mul circuit

type MulCircuit struct {
	A, B, C frontend.Variable
	D       frontend.Variable `gnark:",public"`
}

func (c *MulCircuit) Define(api frontend.API) error {

	a := api.Mul(c.A, c.B)
	b := api.Mul(a, c.C)

	api.AssertIsEqual(b, c.D)

	return nil
}

func getVkProofMulCircuit() (bn254plonk.Proof, bn254plonk.VerifyingKey, []fr.Element) {

	var circuit MulCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness MulCircuit
	witness.A = 2
	witness.B = 2
	witness.C = 2
	witness.D = 8

	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	checkError(err)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
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

// ------------------------------------------
// school book Fiat Shamir
type FiatShamir struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *FiatShamir) Define(api frontend.API) error {

	// a := api.Mul(circuit.X, circuit.X, circuit.X, circuit.X, circuit.X)
	a := circuit.X
	for i := 0; i < 200; i++ {
		a = api.Mul(a, circuit.X)
	}

	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("type %T doesn't impl the Committer interface", api)
	}
	b, err := committer.Commit(a, circuit.Y)
	if err != nil {
		return err
	}

	// c := api.Mul(a, circuit.X)
	// d, err := committer.Commit(c, circuit.X)
	// if err != nil {
	// 	return err
	// }

	// b := api.Mul(circuit.X, circuit.X, circuit.X, circuit.X, circuit.X)

	api.AssertIsDifferent(b, circuit.Y)
	// api.AssertIsDifferent(b, circuit.Y)
	// api.AssertIsDifferent(d, circuit.Y)
	return nil
}

func getVkProofFiatShamir() (bn254plonk.Proof, bn254plonk.VerifyingKey, []fr.Element) {

	var circuit FiatShamir
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness FiatShamir
	witness.X = 2
	witness.Y = 2
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	checkError(err)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
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

//go:generate go run main.go
func main() {

	// proof, vk, pi := getVkProofFiatShamir()
	proof, vk, pi := getVkProofMulCircuit()

	fpi, err := os.Create("../data/pi")
	var spi []byte
	checkError(err)
	for i := 0; i < len(pi); i++ {
		spi = append(spi, pi[i].Marshal()...)
	}
	_, err = fpi.Write(spi)
	checkError(err)
	fpi.Close()

	fvk, err := os.Create("../data/vk")
	checkError(err)
	_, err = vk.WriteRawTo(fvk)
	checkError(err)
	fvk.Close()

	fproof, err := os.Create("../data/proof")
	checkError(err)
	_, err = proof.WriteRawTo(fproof)
	checkError(err)
	fproof.Close()

	contract, err := os.Create("../contracts/verifier.sol")
	checkError(err)
	err = vk.ExportSolidity(contract) //, solidity.WithPragmaVerions("0.8.25"))
	checkError(err)
	err = contract.Close()
	checkError(err)

}
