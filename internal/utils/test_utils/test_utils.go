package test_utils

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// Range (n, startingPoints...) = [startingPoints[0], startingPoints[0]+1, ..., startingPoints[0]+n-1, startingPoints[1], startingPoints[1]+1, ...,]
// or [0, 1, ..., n-1] if startingPoints is empty
func Range(n int, startingPoints ...int) []int {
	if len(startingPoints) == 0 {
		startingPoints = []int{0}
	}
	res := make([]int, n*len(startingPoints))

	for i := range startingPoints {
		for j := range n {
			res[i*n+j] = startingPoints[i] + j
		}
	}

	return res
}

func CopyThruSerialization(t *testing.T, dst, src interface {
	io.ReaderFrom
	io.WriterTo
}) {
	var bb bytes.Buffer

	n, err := src.WriteTo(&bb)
	require.NoError(t, err)
	require.Equal(t, int64(bb.Len()), n)
	n, err = dst.ReadFrom(bytes.NewReader(bb.Bytes()))
	require.NoError(t, err)
	require.Equal(t, int64(bb.Len()), n)
}
