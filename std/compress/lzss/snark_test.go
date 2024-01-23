package lzss

import (
	"os"
	"testing"

	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test1One(t *testing.T) {
	testCompressionRoundTrip(t, []byte{1}, nil)
}

func TestGoodCompression(t *testing.T) {
	testCompressionRoundTrip(t, []byte{1, 2}, nil, withLevel(lzss.GoodCompression))
}

func Test0To10Explicit(t *testing.T) {
	testCompressionRoundTrip(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil)
}

const inputExtraBytes = 5

func TestNoCompression(t *testing.T) {

	d, err := os.ReadFile("./testdata/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	compressor, err := lzss.NewCompressor(dict, lzss.NoCompression)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	decompressorLevel := lzss.BestCompression

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(c)+inputExtraBytes),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            decompressorLevel,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(append(c, make([]byte, inputExtraBytes)...)),
		CBegin:  0,
		CLength: len(c),
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func Test255_254_253(t *testing.T) {
	testCompressionRoundTrip(t, []byte{255, 254, 253}, nil)
}

func Test3c2943(t *testing.T) {
	d, err := os.ReadFile("./testdata/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	testCompressionRoundTrip(t, d, dict)
}

func Test3c2943withHeader(t *testing.T) {
	d, err := os.ReadFile("./testdata/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	compressor, err := lzss.NewCompressor(dict, lzss.BestCompression)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)
	c = append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, c...)

	decompressorLevel := lzss.BestCompression

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(c)+inputExtraBytes),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            decompressorLevel,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(append(c, make([]byte, inputExtraBytes)...)),
		CBegin:  10,
		CLength: len(c) - 10,
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

// Fuzz test the decompression
func Fuzz(f *testing.F) { // TODO This is always skipped
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
		testCompressionRoundTrip(t, input, dict)
	})
}

type testCompressionRoundTripSettings struct {
	level  lzss.Level
	cBegin int
}

type testCompressionRoundTripOption func(settings *testCompressionRoundTripSettings)

func withLevel(level lzss.Level) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.level = level
	}
}

func withCBegin(cBegin int) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.cBegin = cBegin
	}
}

func testCompressionRoundTrip(t *testing.T, d, dict []byte, options ...testCompressionRoundTripOption) {

	settings := testCompressionRoundTripSettings{
		level: lzss.BestCompression,
	}

	for _, option := range options {
		option(&settings)
	}

	compressor, err := lzss.NewCompressor(dict, settings.level)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	//assert.NoError(t, os.WriteFile("compress.csv", lzss.CompressedStreamInfo(c, dict).ToCsv(), 0644))

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(c)+inputExtraBytes),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            settings.level,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(append(c, make([]byte, inputExtraBytes)...)),
		CBegin:  settings.cBegin,
		CLength: len(c),
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func getDictionary() []byte {
	d, err := os.ReadFile("./testdata/dict_naive")
	if err != nil {
		panic(err)
	}
	return d
}
