package lzss_v2

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/icza/bitio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test1ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0}, nil)
}

func Test0To10Explicit(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil)
}

func testCompressionRoundTripSnark(t *testing.T, d, dict []byte) {
	compressor, err := NewCompressor(dict)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	cStream := ReadIntoStream(c, dict)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))

}

func testDecompressionSnark(t *testing.T, dict []byte, compressedStream ...interface{}) {
	var bb bytes.Buffer
	w := bitio.NewWriter(&bb)
	i := 0
	for _, c := range compressedStream {
		switch v := c.(type) {
		case byte:
			assert.NoError(t, w.WriteByte(v))
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
	cStream := ReadIntoStream(c, dict)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}
