package splitted

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/assert"
	"os"
	"runtime"
	"testing"
)

const (
	Cnt = 9
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

	v1, err := api.Compiler().Commit(circuit.PreImage, circuit.Hash)
	if err != nil {
		return err
	}
	v2 := api.Mul(v1, v1)
	api.AssertIsDifferent(v2, 0)
	for i := 0; i < cnt; i++ {
		// hash function
		handler, _ := mimc.NewMiMC(api)

		// specify constraints
		// mimc(preImage) == hash
		handler.Write(circuit.PreImage)
		api.AssertIsEqual(circuit.Hash, handler.Sum())
	}

	return nil
}

func TestCircuit(t *testing.T) {
	// Compile the circuit
	var myCircuit Circuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(t, err)
	ccs.Lazify()
	session := "stest"
	batchSize := 10000
	err = ccs.SplitDumpBinary(session, batchSize)
	assert.NoError(t, err)
	cs2 := groth16.NewCS(ecc.BN254)
	cs2.LoadFromSplitBinaryConcurrent(session, ccs.GetNbR1C(), batchSize, runtime.NumCPU())

	// pk, vk, _ := groth16.Setup(ccs)
	// groth16.SplitDumpPK(pk, session+"2")

	err = groth16.SetupDumpKeys(ccs, session)
	assert.NoError(t, err)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	name := fmt.Sprintf("%s.vk.save", session)
	vkFile, err := os.Open(name)
	_, err = vk.ReadFrom(vkFile)
	assert.NoError(t, err)

	assignment := &Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}
	witness, _ := frontend.NewWitness(assignment, bn254.ID.ScalarField())

	pks, err := groth16.ReadSegmentProveKey(ecc.BN254, session)
	assert.NoError(t, err)

	prf, err := groth16.ProveRoll(cs2, pks[0], pks[1], witness, session)
	assert.NoError(t, err)

	pubWitness, err := witness.Public()
	assert.NoError(t, err)
	err = groth16.Verify(prf, vk, pubWitness)
	assert.NoError(t, err)
}
