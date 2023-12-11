package lzss

import (
	goCompress "github.com/consensys/compress"
	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark/std/compress"
	"math/bits"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func TestCompression1ZeroE2E(t *testing.T) {
	testCompressionE2E(t, []byte{0}, nil, "1_zero")
}

func BenchmarkCompression26KBE2E(b *testing.B) {
	_, err := BenchCompressionE2ECompilation(nil, "./testdata/3c2943")
	assert.NoError(b, err)
}

func testCompressionE2E(t *testing.T, d, dict []byte, name string) {
	if d == nil {
		var err error
		d, err = os.ReadFile("./testdata/" + name + "/data.bin")
		assert.NoError(t, err)
	}

	// compress

	level := lzss.GoodCompression
	wordNbBits := 63 - bits.LeadingZeros64(uint64(level))
	const curveId = ecc.BLS12_377

	compressor, err := lzss.NewCompressor(dict, level)
	assert.NoError(t, err)

	c, err := compressor.Compress(d)
	assert.NoError(t, err)

	cStream, err := goCompress.NewStream(c, uint8(level))
	assert.NoError(t, err)

	cWords, cSum, err := compress.ToSnarkData(curveId, cStream, wordNbBits*cStream.Len(), level)
	assert.NoError(t, err)

	dStream, err := goCompress.NewStream(d, 8)
	assert.NoError(t, err)

	dWords, dSum, err := compress.ToSnarkData(curveId, dStream, 8*len(d), level)
	assert.NoError(t, err)

	circuit := compressionCircuit{
		C:     make([]frontend.Variable, len(cWords)),
		D:     make([]frontend.Variable, len(dWords)),
		Dict:  make([]byte, len(dict)),
		Level: level,
	}

	// solve the circuit or only compile it

	assignment := compressionCircuit{
		CChecksum: cSum,
		DChecksum: dSum,
		C:         cWords,
		D:         dWords,
		Dict:      dict,
		CLen:      cStream.Len(),
		DLen:      len(d),
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(curveId))
}

func TestChecksumNothing(t *testing.T) {
	testChecksum(t, goCompress.Stream{D: []int{}, NbSymbs: 256}, 0, lzss.BestSnarkDecompression)
}

func TestChecksumOne(t *testing.T) {
	testChecksum(t, goCompress.Stream{D: []int{1}, NbSymbs: 256}, 8, lzss.BestSnarkDecompression)
}

func TestChecksumOneWithBits(t *testing.T) {
	testChecksum(t, goCompress.Stream{D: []int{1}, NbSymbs: 256}, 9, lzss.BestCompression)
}

func testChecksum(t *testing.T, d goCompress.Stream, paddedNbBits int, level lzss.Level) {
	const curveId = ecc.BLS12_377

	words, checksum, err := compress.ToSnarkData(curveId, d, paddedNbBits, level)
	assert.NoError(t, err)

	circuit := checksumTestCircuit{
		Inputs:  make([]frontend.Variable, len(words)),
		WordLen: int(level),
	}

	assignment := checksumTestCircuit{
		Inputs:   words,
		InputLen: len(words),
		Sum:      checksum,
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(curveId))
}

type checksumTestCircuit struct {
	Inputs   []frontend.Variable
	InputLen frontend.Variable
	Sum      frontend.Variable
	WordLen  int
}

func (c *checksumTestCircuit) Define(api frontend.API) error {
	sum := compress.Checksum(api, c.Inputs, c.InputLen, c.WordLen)
	api.AssertIsEqual(c.Sum, sum)
	return nil
}
