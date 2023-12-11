package lzss

import (
	goCompress "github.com/consensys/compress"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestReadBytes(t *testing.T) {
	expected := []byte{254, 0, 0, 0}
	circuit := &readBytesCircuit{
		Words:      make([]frontend.Variable, 8*len(expected)),
		WordNbBits: 1,
		Expected:   expected,
	}
	words, err := goCompress.NewStream(expected, 8)
	assert.NoError(t, err)
	words = words.BreakUp(2)
	assignment := &readBytesCircuit{
		Words: test_vector_utils.ToVariableSlice(words.D),
	}
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

type readBytesCircuit struct {
	Words      []frontend.Variable
	WordNbBits int
	Expected   []byte
}

func (c *readBytesCircuit) Define(api frontend.API) error {
	byts := combineIntoBytes(api, c.Words, c.WordNbBits)
	for i := range c.Expected {
		api.AssertIsEqual(c.Expected[i], byts[i*8])
	}
	return nil
}

func TestChecksumBls12_377(t *testing.T) {

}

/*
type checksumCircuit struct {
	C        []frontend.Variable
	Checksum frontend.Variable
	WordLen  int
}

func (c *checksumCircuit) Define(api frontend.API) error {
	cPacked := compress.Pack(api, c.C, c.WordLen)

}
*/
