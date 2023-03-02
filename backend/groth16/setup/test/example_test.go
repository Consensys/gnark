package test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/setup/keys"
	"github.com/consensys/gnark/backend/groth16/setup/phase1"
	"github.com/consensys/gnark/backend/groth16/setup/phase2"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	mimc, _ := mimc.NewMiMC(api)

	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())

	return nil
}

func TestSetupCircuit(t *testing.T) {
	nContributionsPhase1 := 3
	power := 9
	contributionsPhase1 := make([]phase1.Contribution, nContributionsPhase1)
	contributionsPhase1[0].Initialize(power)

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		contributionsPhase1[i].Contribute(&contributionsPhase1[i-1])
		err := contributionsPhase1[i].Verify(&contributionsPhase1[i-1])
		if err != nil {
			t.Error(err)
		}
	}

	// Compile the circuit
	var myCircuit Circuit
	ccs, _ := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)

	nContributionsPhase2 := 3
	var evals phase2.Evaluations
	contributionsPhase2 := make([]phase2.Contribution, nContributionsPhase2)
	switch r1cs := ccs.(type) {
	case *cs_bn254.R1CS:
		// Prepare for phase-2
		evals = contributionsPhase2[0].PreparePhase(&contributionsPhase1[nContributionsPhase1-1], r1cs)
	default:
		panic("Unsupported curve")
	}

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase2; i++ {
		contributionsPhase2[i].Contribute(&contributionsPhase2[i-1])
		err := contributionsPhase2[i].Verify(&contributionsPhase2[i-1])
		if err != nil {
			t.Error(err)
		}
	}

	pk, vk := keys.ExtractKeys(&contributionsPhase1[nContributionsPhase1-1], &contributionsPhase2[nContributionsPhase2-1], &evals, ccs.GetNbConstraints())
	var bufPK, bufVK bytes.Buffer
	// Write PK and VK
	pk.WriteTo(&bufPK, false)
	vk.WriteTo(&bufVK, false)

	// Read PK and VK

	pkk := groth16.NewProvingKey(ecc.BN254)
	pkk.ReadFrom(&bufPK)
	vkk := groth16.NewVerifyingKey(ecc.BN254)
	vkk.ReadFrom(&bufVK)

	assignment := &Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}
	witness, _ := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	prf, err := groth16.Prove(ccs, pkk, witness)
	if err != nil {
		panic(err)
	}
	pubWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(prf, vkk, pubWitness)
	if err != nil {
		panic(err)
	}
}
