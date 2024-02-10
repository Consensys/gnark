package lzss

import (
	"crypto/sha256"
	"encoding/hex"
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

func TestOutBufTooShort(t *testing.T) {
	const truncationAmount = 3
	d := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	compressor, err := lzss.NewCompressor(nil, lzss.BestCompression)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	circuit := decompressionLengthTestCircuit{
		C: make([]frontend.Variable, len(c)+inputExtraBytes),
		D: make([]frontend.Variable, len(d)-truncationAmount), // not enough room

	}

	assignment := decompressionLengthTestCircuit{
		C:               test_vector_utils.ToVariableSlice(append(c, make([]byte, inputExtraBytes)...)),
		CLength:         len(c),
		D:               test_vector_utils.ToVariableSlice(d[:len(d)-truncationAmount]),
		ExpectedDLength: -1,
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_377))
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
	level                lzss.Level
	cBegin               int
	compressedPaddingLen int
	compressedPaddedLen  int
	compressed           []byte
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

func withCompressedPaddingLen(compressedPaddingLen int) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.compressedPaddingLen = compressedPaddingLen
	}
}

// withCompressedPaddedLen overrides withCompressedPaddingLen
func withCompressedPaddedLen(compressedPaddedLen int) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.compressedPaddedLen = compressedPaddedLen
	}
}

func withCompressed(compressed []byte) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.compressed = compressed
	}
}

func checksum(b []byte) string {
	hsh := sha256.New()
	hsh.Write(b)
	sum := hsh.Sum(nil)
	return hex.EncodeToString(sum[:128/8])
}

func testCompressionRoundTrip(t *testing.T, d, dict []byte, options ...testCompressionRoundTripOption) {

	t.Log("using dict", checksum(dict))

	s := testCompressionRoundTripSettings{
		level:               lzss.BestCompression,
		compressedPaddedLen: -1,
	}

	for _, option := range options {
		option(&s)
	}

	if s.compressed == nil {
		compressor, err := lzss.NewCompressor(dict, s.level)
		require.NoError(t, err)
		s.compressed, err = compressor.Compress(d)
		require.NoError(t, err)
	}

	t.Log("compressed checksum:", checksum(s.compressed))

	// duplicating tests from the compress repo, for sanity checking
	dBack, err := lzss.Decompress(s.compressed, dict)
	require.NoError(t, err)
	assert.Equal(t, d, dBack)

	//assert.NoError(t, os.WriteFile("compress.csv", lzss.CompressedStreamInfo(c, dict).ToCsv(), 0644))

	// from the blob maker it seems like the compressed stream is 129091 bytes long

	if s.compressedPaddedLen != -1 {
		s.compressedPaddingLen = s.compressedPaddedLen - len(s.compressed)
		require.LessOrEqual(t, len(s.compressed), s.compressedPaddedLen, "length must not be greater than padded length")
	} else {
		require.GreaterOrEqual(t, s.compressedPaddingLen, 0, "padding length must be non-negative")
	}

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(s.compressed)+s.compressedPaddingLen),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            s.level,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(append(s.compressed, make([]byte, s.compressedPaddingLen)...)),
		CBegin:  s.cBegin,
		CLength: len(s.compressed),
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

type decompressionLengthTestCircuit struct {
	C, D            []frontend.Variable
	CLength         frontend.Variable
	ExpectedDLength frontend.Variable
}

func (c *decompressionLengthTestCircuit) Define(api frontend.API) error {
	dict := test_vector_utils.ToVariableSlice(lzss.AugmentDict(nil))
	if dLength, err := Decompress(api, c.C, c.CLength, c.D, dict, lzss.BestCompression); err != nil {
		return err
	} else {
		api.AssertIsEqual(dLength, c.ExpectedDLength)
		return nil
	}
}
