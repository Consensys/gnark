package merkle

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	backend_common "github.com/consensys/gnark/backend"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/bn256/groth16"
	"github.com/consensys/gnark/crypto/hash/mimc/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
	"gitlab.com/NebulousLabs/merkletree"
)

func TestLeafNode(t *testing.T) {

	t.Skip("need to fix the domain separation")

	// computation of expected result
	leafPrefix := []byte{0x00}
	var leaf big.Int
	leaf.SetString("13624385163935458283869439134075429264189673484676236437911217620784009712594", 10)
	h := bn256.NewMiMC("seed")
	binLeaf := leaf.Bytes()
	h.Write(leafPrefix)
	h.Write(binLeaf[:len(binLeaf)-1])
	var binExpectedRes []byte
	binExpectedRes = h.Sum(binExpectedRes)
	var expectedRes fr.Element
	expectedRes.SetBytes(binExpectedRes)
	solution := make(map[string]fr.Element)
	solution["res"] = expectedRes

	// computation of leafNode using gadget
	circuit := frontend.New()
	hg, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}
	leafg := circuit.SECRET_INPUT("leaf")
	res := leafSum(&circuit, hg, leafg)
	res.Tag("res")
	assignment := backend_common.NewAssignment()
	assignment.Assign(backend_common.Secret, "leaf", expectedRes)

	r1cs := backend_bn256.New(&circuit)
	assert := groth16.NewAssert(t)
	assert.CorrectExecution(&r1cs, assignment, solution)
}

// TODO need tests
func TestVerify(t *testing.T) {

	t.Skip("need to fix the domain separation")

	// get merkle root of a file
	segmentSize := 32
	file, err := os.Open("../../../crypto/hash/mimc/bn256/mimc_bn256.go")
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// build & verify proof for an elmt in the file
	file.Seek(0, 0)
	proofIndex := uint64(7)
	merkleRoot, proof, numLeaves, err := merkletree.BuildReaderProof(file, bn256.NewMiMC("seed"), segmentSize, proofIndex)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	verified := merkletree.VerifyProof(bn256.NewMiMC("seed"), merkleRoot, proof, proofIndex, numLeaves)
	if !verified {
		t.Fatal("The merkle proof in plain go should pass")
	}

	// create circuit
	circuit := frontend.New()

	// public root hash
	rh := circuit.PUBLIC_INPUT("rootHash")

	// private
	priv := make([]*frontend.Constraint, 0)
	for i := 0; i < len(proof); i++ {
		tmp := circuit.SECRET_INPUT("path" + string(i))
		priv = append(priv, tmp)
	}

	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}
	VerifyProof(&circuit, hFunc, rh, priv, proofIndex, numLeaves)

	// compilation of the circuit
	r1cs := backend_bn256.New(&circuit)

	assert := groth16.NewAssert(t)

	assignment := backend_common.NewAssignment()
	assignment.Assign(backend_common.Public, "rootHash", merkleRoot)
	for i := 0; i < len(proof); i++ {
		assignment.Assign(backend_common.Secret, "path"+string(i), proof[i])
	}

	assert.Solved(&r1cs, assignment, nil)
}
