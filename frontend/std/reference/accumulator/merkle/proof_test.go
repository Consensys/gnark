package merkle

import (
	"testing"

	"github.com/consensys/gnark/curve/fr"
	"github.com/consensys/gnark/frontend/std/reference/hash/mimc"
)

func TestMerkleTree(t *testing.T) {

	t.Skip("wip")

	// hash function
	hash := mimc.NewMiMC("seed")

	var proof Proof
	var leaf, goodRoot, badRoot fr.Element

	badRoot.SetUint64(213921)
	goodRoot.SetUint64(213923)
	leaf.SetUint64(213923)

	proof.Path = make([]TreeLevel, 10)

	// build the membership proof and compute the root hash
	for i := 0; i < 10; i++ {
		// childs for current node
		var left, right fr.Element
		left.SetUint64(uint64(i))
		right.SetUint64(uint64(10 * i))

		proof.Path[i] = TreeLevel{
			Index:    1,
			Elements: []fr.Element{left, right},
		}

		goodRoot = hash.Hash(left, goodRoot, right)
	}

	// verifying the merkle path with the correct root should return true
	{
		res, err := proof.Verify(goodRoot, leaf)
		if err != nil {
			t.Fatal(err)
		}
		if !res {
			t.Fatal("correct proof should be accepted")
		}
	}
	// verifying the merkle path with an incorrect root should return false
	{
		res, err := proof.Verify(badRoot, leaf)
		if err != nil {
			t.Fatal(err)
		}
		if res {
			t.Fatal("incorrect proof accepted")
		}
	}

	// put the membership proof in a circuit
	// s := cs.New()
	// proof.Allocate(&s)
	// leafAllocated := s.SECRET_INPUT("leaf")
	// rootAllocated := s.PUBLIC_INPUT("root")
	// proof.VerifyProofGadget(&s, rootAllocated, leafAllocated)

	// inputs := cs.NewAssignment()
	// inputs.Assign(cs.Secret, "leaf", "213923")
	// inputs.Assign(cs.Public, "root", "2")

	// r1cs := cs.NewR1CS(&s)
	// r1cs.Solve(inputs)
	// r := r1cs.Debug()

}
