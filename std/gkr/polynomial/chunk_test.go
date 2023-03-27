package polynomial

import (
	"github.com/consensys/gnark/std/gkr/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunked(t *testing.T) {

	nEvals := 10

	testCases := []struct {
		logSize    int
		logNChunks int
		mixedSize  int
	}{
		{
			logSize:    10,
			logNChunks: 5,
			mixedSize:  3,
		},
		{
			logSize:    10,
			logNChunks: 1,
			mixedSize:  3,
		},
		{
			logSize:    10,
			logNChunks: 4,
			mixedSize:  1,
		},
	}

	for _, test := range testCases {
		// Initialize the case
		qPrime := common.RandomFrArray(test.logSize)
		size := 1 << test.logSize
		nChunks := 1 << test.logNChunks
		chunkSize := 1 << (test.logSize - test.logNChunks)
		// Initialize the tables
		eqChunked := GetChunkedEqTable(qPrime, nChunks, 1)
		eq := GetFoldedEqTable(qPrime)

		// The first and the last elements should match
		assert.Equal(t, eq.Table[0], eqChunked[0].Table[0], "Eq and EqChunk are inconsistent")
		assert.Equal(t, eq.Table[size-1], eqChunked[nChunks-1].Table[chunkSize-1], "Eq and EqChunk are inconsistent")
		// Then tests at random points
		u := []int{1897979 % chunkSize, 987950 % chunkSize, 4547687 % chunkSize}
		s := []int{5648709 % nChunks, 907532 % nChunks, 367570 % nChunks}
		for k := range u {
			id := u[k]*nChunks + s[k]
			assert.Equal(t, eq.Table[id], eqChunked[s[k]].Table[u[k]], "Eq and EqChunk are inconsistent")
		}

		// Test that evaluation gives the same results
		for i := 0; i < nEvals; i++ {
			hPrime := common.RandomFrArray(test.logSize)
			res := eq.Evaluate(hPrime)
			resChunked := EvaluateChunked(eqChunked, hPrime)
			assert.Equal(t, res, resChunked, "Inconsistency in the evaluation of eq")
		}

		// Test for eval mixed
		for i := 0; i < nEvals; i++ {
			hCommon := common.RandomFrArray(test.logSize - test.mixedSize)
			hL := common.RandomFrArray(test.mixedSize)
			hR := common.RandomFrArray(test.mixedSize)
			resChunkedA, resChunkedB := EvaluateMixedChunked(eqChunked, hCommon, hL, hR)
			resA, resB := eq.EvaluateLeftAndRight(hCommon, hL, hR)
			assert.Equal(t, resA, resChunkedA, "Error in eval mixed")
			assert.Equal(t, resB, resChunkedB, "Error in eval mixed")
		}
	}
}
