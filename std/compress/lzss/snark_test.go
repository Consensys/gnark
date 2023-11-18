package lzss

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/icza/bitio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func Test1ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0}, nil)
}

func Test0To10Explicit(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil)
}

func TestNoCompressionSnark(t *testing.T) {

	d, err := os.ReadFile("./testdata/test_cases/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	compressor, err := NewCompressor(dict, NoCompression)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	cStream := ReadIntoStream(c, dict, BestCompression)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            BestCompression,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func Test4ZerosBackref(t *testing.T) {

	shortBackRefType, longBackRefType, _ := initBackRefTypes(0, BestCompression)

	testDecompressionSnark(t, nil, BestCompression, 0, backref{
		address: 0,
		length:  2,
		bType:   shortBackRefType,
	}, backref{
		address: 1,
		length:  1,
		bType:   longBackRefType,
	},
	)
}

func Test255_254_253(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{255, 254, 253}, nil)
}

func Test3c2943Snark(t *testing.T) {
	d, err := os.ReadFile("./testdata/test_cases/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	testCompressionRoundTripSnark(t, d, dict)
}

// Fuzz test the decompression
func FuzzSnark(f *testing.F) {
	f.Fuzz(func(t *testing.T, input, dict []byte) {
		if len(input) > maxInputSize {
			t.Skip("input too large")
		}
		if len(dict) > maxDictSize {
			t.Skip("dict too large")
		}
		if len(input) == 0 {
			t.Skip("input too small")
		}
		testCompressionRoundTripSnark(t, input, dict)
	})
}

func testCompressionRoundTripSnark(t *testing.T, d, dict []byte) {

	level := BestCompression
	if len(d) > 1000 {
		level = GoodCompression
	}

	compressor, err := NewCompressor(dict, level)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	cStream := ReadIntoStream(c, dict, level)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            level,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func testDecompressionSnark(t *testing.T, dict []byte, level Level, compressedStream ...interface{}) {
	var bb bytes.Buffer
	w := bitio.NewWriter(&bb)
	bb.WriteByte(byte(level))
	i := 0
	for _, c := range compressedStream {
		switch v := c.(type) {
		case byte:
			assert.NoError(t, w.WriteByte(v))
			i++
		case int:
			assert.True(t, v >= 0 && v <= 255)
			assert.NoError(t, w.WriteByte(byte(v)))
			i++
		case []byte:
			for _, b := range v {
				assert.NoError(t, w.WriteByte(b))
			}
			i += len(v)
		case backref:
			v.writeTo(w, i)
			i += v.length
		default:
			panic("not implemented")
		}
	}
	assert.NoError(t, w.Close())
	c := bb.Bytes()
	d, err := DecompressGo(c, dict)
	require.NoError(t, err)
	cStream := ReadIntoStream(c, dict, BestCompression)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            BestCompression,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func TestReadBytes(t *testing.T) {
	expected := []byte{0, 254, 0, 0}
	circuit := &readBytesCircuit{
		Words:      make([]frontend.Variable, 8*len(expected)),
		WordNbBits: 1,
		Expected:   expected,
	}
	words := compress.NewStreamFromBytes(expected)
	words = words.BreakUp(2)
	assignment := &readBytesCircuit{
		Words: test_vector_utils.ToVariableSlice(words.D),
	}
	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
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
