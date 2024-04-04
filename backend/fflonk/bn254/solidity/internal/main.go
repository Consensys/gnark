package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	// "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/fflonk"
	bn254fflonk "github.com/consensys/gnark/backend/fflonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"

	// "github.com/consensys/gnark/test/unsafekzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
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
	for i := 0; i < 5; i++ {
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

func getVkProofFiatShamir() (bn254fflonk.Proof, bn254fflonk.VerifyingKey, []fr.Element) {

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

	// srs, _, err := unsafekzg.NewSRS(ccs)
	// checkError(err)
	srs, err := kzg_bn254.NewSRS(500, big.NewInt(10))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	pk, vk, err := fflonk.Setup(ccs, srs)
	checkError(err)

	proof, err := fflonk.Prove(ccs, pk, witnessFull)
	checkError(err)

	err = fflonk.Verify(proof, vk, witnessPublic)
	checkError(err)

	tvk := vk.(*bn254fflonk.VerifyingKey)
	tproof := proof.(*bn254fflonk.Proof)

	ipi := witnessPublic.Vector()
	pi := ipi.(fr.Vector)

	return *tproof, *tvk, pi
}

//go:generate go run main.go
func main() {

	proof, vk, pi := getVkProofFiatShamir()
	// proof, vk, pi := getVkProofSbFiatShamir()

	fpi, err := os.Create("../pi")
	var spi []byte
	checkError(err)
	for i := 0; i < len(pi); i++ {
		spi = append(spi, pi[i].Marshal()...)
	}
	_, err = fpi.Write(spi)
	checkError(err)
	fpi.Close()

	fvk, err := os.Create("../vk")
	checkError(err)
	_, err = vk.WriteRawTo(fvk)
	checkError(err)
	fvk.Close()

	fproof, err := os.Create("../proof")
	checkError(err)
	_, err = proof.WriteRawTo(fproof)
	checkError(err)
	fproof.Close()

	contract, err := os.Create("../contracts/verifier.sol")
	checkError(err)
	err = vk.ExportSolidity(contract)
	checkError(err)
	err = contract.Close()
	checkError(err)

}
