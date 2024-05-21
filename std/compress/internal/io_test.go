package internal_test

import (
	"bytes"
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/internal"
	"github.com/consensys/gnark/std/compress/lzss"
	"github.com/consensys/gnark/std/math/bits"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/icza/bitio"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRecombineBytes(t *testing.T) {
	// get some random bytes
	_bytes := make([]byte, 50000)
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

	lzss.RegisterHints()
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

type recombineBytesCircuit struct {
	Bytes, Bits, Recombined []frontend.Variable
}

func (c *recombineBytesCircuit) Define(api frontend.API) error {
	r := internal.NewRangeChecker(api)
	bits, recombined := r.BreakUpBytesIntoWords(1, c.Bytes...)
	if len(bits) != len(c.Bits) {
		panic("wrong number of bits")
	}
	for i := range bits {
		api.AssertIsEqual(c.Bits[i], bits[i])
	}
	if len(recombined) != len(c.Recombined) {
		panic("wrong number of bytes")
	}
	for i := range recombined {
		api.AssertIsEqual(c.Recombined[i], recombined[i])
	}
	return nil
}

func TestRangeChecker_IsLessThan(t *testing.T) {
	ins := []frontend.Variable{-3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	outs := []frontend.Variable{0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0}
	circuit := rangeCheckerCircuit{
		Ins:   make([]frontend.Variable, len(ins)),
		Outs:  make([]frontend.Variable, len(outs)),
		Range: 8,
	}
	assignment := rangeCheckerCircuit{
		Ins:  ins,
		Outs: outs,
	}
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.GROTH16, backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

type rangeCheckerCircuit struct {
	Ins, Outs []frontend.Variable
	Range     uint
}

func (c *rangeCheckerCircuit) Define(api frontend.API) error {
	if len(c.Ins) != len(c.Outs) {
		panic("witness length mismatch")
	}
	r := internal.NewRangeChecker(api)

	for i := range c.Ins {
		lt := r.IsLessThan(c.Range, c.Ins[i])
		api.AssertIsEqual(c.Outs[i], lt)
	}

	return nil
}

func TestBreakUpBytesIntoWordsGains(t *testing.T) {
	customCircuit := breakUpBytesIntoWordsCustomCircuit{make([]frontend.Variable, 128*1024)}
	stdCircuit := breakUpBytesIntoWordsStdCircuit{make([]frontend.Variable, 128*1024)}

	csCustom, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &customCircuit)
	assert.NoError(t, err)

	csStd, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &stdCircuit)
	assert.NoError(t, err)

	customNbConstraints := csCustom.GetNbConstraints()
	stdNbConstraints := csStd.GetNbConstraints()

	assert.Greater(t, stdNbConstraints-customNbConstraints, 1000000, "custom circuit must save at least 1M constraints")
	assert.LessOrEqual(t, 100*customNbConstraints/stdNbConstraints, 75, "custom circuit should achieve at least a 25%% reduction in constraints")
}

type breakUpBytesIntoWordsCircuit struct {
	Bytes []frontend.Variable
}

type breakUpBytesIntoWordsStdCircuit breakUpBytesIntoWordsCircuit
type breakUpBytesIntoWordsCustomCircuit breakUpBytesIntoWordsCircuit

func (c *breakUpBytesIntoWordsStdCircuit) Define(api frontend.API) error {
	words := make([]frontend.Variable, 0, len(c.Bytes)*8)
	for _, _byte := range c.Bytes {
		words = append(words,
			bits.ToBase(api, bits.Binary, _byte, bits.WithNbDigits(8), bits.WithUnconstrainedInputs(), bits.OmitModulusCheck())...,
		)
	}

	_bytes := make([]frontend.Variable, len(words))
	r := compress.NewNumReader(api, words, 8, 1)
	for i := range words {
		_bytes[i] = r.Next()
	}
	return nil
}

func (c *breakUpBytesIntoWordsCustomCircuit) Define(api frontend.API) error {
	r := internal.NewRangeChecker(api)
	_, _ = r.BreakUpBytesIntoWords(1, c.Bytes...)
	return nil
}
