package fri

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fri"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type ProofOfProximityTest struct {
	Proof ProofOfProximity
	Salt  frontend.Variable
}

var sizePolyTest = uint64(32)
var nbSteps = 5

const nbRounds = 1

func (p *ProofOfProximityTest) Define(api frontend.API) error {

	// creation of the hash function
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return nil
	}

	// oracle proof of proximity
	opp := NewRadixTwoFri(sizePolyTest, &h)
	err = opp.verifyProofOfProximitySingleRound(api, p.Salt, p.Proof.Rounds[0])
	if err != nil {
		return err
	}

	return nil

}

func TestFriVerification(t *testing.T) {

	// 1 - generate random polynomial of degree 32
	polynomial := make([]fr.Element, sizePolyTest)
	for i := 0; i < int(sizePolyTest); i++ {
		polynomial[i].SetRandom()
	}

	// 2 - build the proximity proof, verify it in plain go to verify it is correctly formed
	commitmentScheme := fri.RADIX_2_FRI.New(sizePolyTest, hash.MIMC_BN254.New())
	proximityProof, err := commitmentScheme.BuildProofOfProximity(polynomial)
	if err != nil {
		t.Fatal(err)
	}
	err = commitmentScheme.VerifyProofOfProximity(proximityProof)
	if err != nil {
		t.Fatal(err)
	}

	// 3 - create the circuit, allocate the slices...
	var circuit ProofOfProximityTest
	circuit.Proof.Rounds = make([]Round, nbRounds)
	for i := 0; i < nbRounds; i++ {
		circuit.Proof.Rounds[i].Interactions = make([][2]merkle.MerkleProof, nbSteps)
		for j := 0; j < nbSteps; j++ {

			// only one of the paths is filled, it is the longest of the 2.
			a := len(proximityProof.Rounds[i].Interactions[j][0].ProofSet)
			b := len(proximityProof.Rounds[i].Interactions[j][1].ProofSet)
			if b > a {
				a = b
			}
			circuit.Proof.Rounds[i].Interactions[j][0].Path = make([]frontend.Variable, a)
			circuit.Proof.Rounds[i].Interactions[j][1].Path = make([]frontend.Variable, a)
		}
	}

	cc, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}

	// 4 - populate the witness, allocate the slice first...
	var witness ProofOfProximityTest
	witness.Salt = 0
	witness.Proof.Rounds = make([]Round, nbRounds)
	for i := 0; i < nbRounds; i++ {
		witness.Proof.Rounds[i].Evaluation = proximityProof.Rounds[i].Evaluation
		witness.Proof.Rounds[i].Interactions = make([][2]merkle.MerkleProof, nbSteps)
		for j := 0; j < nbSteps; j++ {

			// Merkle root
			witness.Proof.Rounds[i].Interactions[j][0].RootHash = proximityProof.Rounds[i].Interactions[j][0].MerkleRoot
			witness.Proof.Rounds[i].Interactions[j][1].RootHash = proximityProof.Rounds[i].Interactions[j][1].MerkleRoot

			// leaves
			witness.Proof.Rounds[i].Interactions[j][0].Leaf = 0
			witness.Proof.Rounds[i].Interactions[j][1].Leaf = 0

			// Merkle paths. Only one of the paths is filled in the plain proof, it is the longest of the 2.
			// In any case, the first 2 entries of each proofPath is available in the plain proof.
			a := len(proximityProof.Rounds[i].Interactions[j][0].ProofSet)
			b := len(proximityProof.Rounds[i].Interactions[j][1].ProofSet)
			c := 0
			if b > a {
				a = b
				c = 1
			}
			witness.Proof.Rounds[i].Interactions[j][0].Path = make([]frontend.Variable, a)
			witness.Proof.Rounds[i].Interactions[j][1].Path = make([]frontend.Variable, a)
			witness.Proof.Rounds[i].Interactions[j][0].Path[0] = proximityProof.Rounds[i].Interactions[j][0].ProofSet[0]
			witness.Proof.Rounds[i].Interactions[j][0].Path[1] = proximityProof.Rounds[i].Interactions[j][0].ProofSet[1]
			witness.Proof.Rounds[i].Interactions[j][1].Path[0] = proximityProof.Rounds[i].Interactions[j][1].ProofSet[0]
			witness.Proof.Rounds[i].Interactions[j][1].Path[1] = proximityProof.Rounds[i].Interactions[j][1].ProofSet[1]
			for k := 2; k < a; k++ {
				witness.Proof.Rounds[i].Interactions[j][0].Path[k] = proximityProof.Rounds[i].Interactions[j][c].ProofSet[k]
				witness.Proof.Rounds[i].Interactions[j][1].Path[k] = proximityProof.Rounds[i].Interactions[j][c].ProofSet[k]
			}
		}
	}

	// 5 - check if the prover is ok
	cwitness, err := frontend.NewWitness(&witness, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	err = cc.IsSolved(cwitness)
	if err != nil {
		t.Fatal(err)
	}

}
