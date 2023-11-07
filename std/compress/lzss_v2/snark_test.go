package lzss_v2

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test1ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0}, nil)
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
