package debug

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseStack(t *testing.T) {
	assert := require.New(t)

	const (
		f1 = "/usr/local/file1.go"
		f2 = "/usr/local/file2.go"
		f3 = "/usr/local/lib/file3.go"
	)

	stackPaths := make(map[uint32]string)
	stackPaths[0] = f1
	stackPaths[1] = f2
	stackPaths[2] = f3

	stack := []uint64{
		uint64(0<<32) | 27,
		uint64(1<<32) | 42,
		uint64(2<<32) | 2,
	}

	parsed, err := ParseStack(stack, stackPaths)
	assert.NoError(err)

	assert.True(len(parsed) == 3)
	assert.Equal(f1, parsed[0].File)
	assert.Equal(uint32(27), parsed[0].Line)

	assert.Equal(f2, parsed[1].File)
	assert.Equal(uint32(42), parsed[1].Line)

	assert.Equal(f3, parsed[2].File)
	assert.Equal(uint32(2), parsed[2].Line)

	stack = append(stack, uint64(8000<<32)|2)
	_, err = ParseStack(stack, stackPaths)
	assert.Error(err)

}
