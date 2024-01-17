package internal

import (
	"bytes"
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/icza/bitio"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRecombineBytes(t *testing.T) {
	// get some random bytes
	_bytes := make([]byte, 1) // todo increase size
	_, err := rand.Read(_bytes)
	assert.NoError(t, err)

	// turn them into bits
	r := bitio.NewReader(bytes.NewReader(_bytes))
	bits := make([]byte, 8*len(_bytes))
	for i := range bits {
		if b := r.TryReadBool(); b {
			bits[i] = 1
		}
	}

	// turn them back into bytes
	recombined := make([]byte, len(bits))
	for i := range recombined {
		for j := 0; j < 8 && i+j < len(bits); j++ {
			recombined[i] += bits[i+j] << (7 - j)
		}
	}
	assert.NoError(t, r.TryError)

	circuit := recombineBytesCircuit{
		Bytes:      make([]frontend.Variable, len(_bytes)),
		Bits:       make([]frontend.Variable, len(bits)),
		Recombined: make([]frontend.Variable, len(recombined)),
	}

	assignment := recombineBytesCircuit{
		Bytes:      test_vector_utils.ToVariableSlice(_bytes),
		Bits:       test_vector_utils.ToVariableSlice(bits),
		Recombined: test_vector_utils.ToVariableSlice(recombined),
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

type recombineBytesCircuit struct {
	Bytes, Bits, Recombined []frontend.Variable
}

func (c *recombineBytesCircuit) Define(api frontend.API) error {
	r := NewRangeChecker(api)
	bits := r.BreakUpBytesIntoWords(1, c.Bytes...)
	if len(bits) != len(c.Bits) {
		panic("wrong number of bits")
	}
	for i := range bits {
		api.AssertIsEqual(c.Bits[i], bits[i])
	}
	recombined := CombineIntoBytes(api, bits, c.Bytes, 1)
	if len(recombined) != len(c.Recombined) {
		panic("wrong number of bytes")
	}
	for i := range recombined {
		api.AssertIsEqual(c.Recombined[i], recombined[i])
	}
	return nil
}

/*
func TestReadBytes(t *testing.T) {
	expected := []byte{254, 0, 0, 0}
	circuit := &readBytesCircuit{
		Words:      make([]frontend.Variable, 8*len(expected)),
		WordNbBits: 1,
		Expected:   expected,
	}
	words, err := compress.NewStream(expected, 8)
	assert.NoError(t, err)
	words = words.BreakUp(2)
	assignment := &readBytesCircuit{
		Words: test_vector_utils.ToVariableSlice(words.D),
	}
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

type readBytesCircuit struct {
	Words      []frontend.Variable
	WordNbBits int
	Expected   []byte
}

func (c *readBytesCircuit) Define(api frontend.API) error {
	byts := internal.CombineIntoBytes(api, c.Words, c.WordNbBits)
	for i := range c.Expected {
		api.AssertIsEqual(c.Expected[i], byts[i*8])
	}
	return nil
}*/
