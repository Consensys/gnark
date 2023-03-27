package splitted

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	Cnt = 6
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
	cnt := 1 << Cnt

	for i := 0; i < cnt; i++ {
		// hash function
		mimc, _ := mimc.NewMiMC(api)

		// specify constraints
		// mimc(preImage) == hash
		mimc.Write(circuit.PreImage)
		api.AssertIsEqual(circuit.Hash, mimc.Sum())
	}

	return nil
}

func TestCircuit(t *testing.T) {
	// Compile the circuit
	var myCircuit Circuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(t, err)
	session := "stest"

	pk, vk, _ := groth16.Setup(ccs)
	groth16.SplitDumpPK(pk, session)

	assignment := &Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}
	witness, _ := frontend.NewWitness(assignment, bn254.ID.ScalarField())

	pks, err := groth16.ReadSegmentProveKey(session)
	assert.NoError(t, err)

	prf, err := groth16.ProveRoll(ccs, pks[0], pks[1], witness, session)
	assert.NoError(t, err)

	pubWitness, err := witness.Public()
	assert.NoError(t, err)
	err = groth16.Verify(prf, vk, pubWitness)
	assert.NoError(t, err)
}
