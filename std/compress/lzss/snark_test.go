package lzss

import (
	goCompress "github.com/consensys/compress"
	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func Test1ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0}, nil)
}

func TestGoodCompressionSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{1, 2}, nil, withLevel(lzss.GoodCompression))
}

func Test0To10ExplicitSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil)
}

func TestNoCompressionSnark(t *testing.T) {

	d, err := os.ReadFile("./testdata/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	compressor, err := lzss.NewCompressor(dict, lzss.NoCompression)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	decompressorLevel := lzss.BestCompression

	cStream, err := goCompress.NewStream(c, uint8(decompressorLevel))
	require.NoError(t, err)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            decompressorLevel,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func Test255_254_253Snark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{255, 254, 253}, nil)
}

func Test3c2943Snark(t *testing.T) {
	d, err := os.ReadFile("./testdata/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	testCompressionRoundTripSnark(t, d, dict)
}

// Fuzz test the decompression
func FuzzSnark(f *testing.F) { // TODO This is always skipped
	f.Fuzz(func(t *testing.T, input, dict []byte) {
		if len(input) > lzss.MaxInputSize {
			t.Skip("input too large")
		}
		if len(dict) > lzss.MaxDictSize {
			t.Skip("dict too large")
		}
		if len(input) == 0 {
			t.Skip("input too small")
		}
		testCompressionRoundTripSnark(t, input, dict)
	})
}

type testCompressionRoundTripOption func(*lzss.Level)

func withLevel(level lzss.Level) testCompressionRoundTripOption {
	return func(l *lzss.Level) {
		*l = level
	}
}

func testCompressionRoundTripSnark(t *testing.T, d, dict []byte, options ...testCompressionRoundTripOption) {

	level := lzss.BestCompression

	for _, option := range options {
		option(&level)
	}

	compressor, err := lzss.NewCompressor(dict, level)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	cStream, err := lzss.ReadIntoStream(c, dict, level)
	require.NoError(t, err)

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

func getDictionary() []byte {
	d, err := os.ReadFile("./testdata/dict_naive")
	if err != nil {
		panic(err)
	}
	return d
}
