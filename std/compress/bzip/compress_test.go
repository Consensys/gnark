package bzip

import (
	"fmt"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/huffman"
	"github.com/stretchr/testify/assert"
	"math"
	"os"
	"testing"
)

func TestBwtLarge(t *testing.T) {
	d, err := os.ReadFile("../large/data.bin")
	assert.NoError(t, err)
	D := compress.NewStreamFromBytes(d)
	D = bwt(D)
}

func testWithPipe(d []byte, pipe compress.Pipeline) {
	D := compress.NewStreamFromBytes(d)
	D = pipe.Run(D)

	nbBitsIn := 8 * len(d)
	nbBitsOut := math.Log2(float64(D.NbSymbs)) * float64(D.Len())

	fmt.Println(float64(nbBitsIn)/nbBitsOut, len(d), "->", int(nbBitsOut/8), "bytes")
}

func testFileWithPipe(t *testing.T, filename string, pipe compress.Pipeline) {
	d, err := os.ReadFile(filename)
	assert.NoError(t, err)
	testWithPipe(d, pipe)
}

func TestPipe0(t *testing.T) {
	d, err := os.ReadFile("../large/data.bin")
	assert.NoError(t, err)
	D := compress.NewStreamFromBytes(d)

	D = compress.Pipeline{bwt, moveToFront, rle0bzip2}.Run(D)
	fmt.Println(8.00562454919 * float64(D.Len()) / float64(len(d)))
}

func TestPipe1(t *testing.T) {
	testFileWithPipe(t, "../large/data.bin", compress.Pipeline{bwt, moveToFront, rle0zct})
}

func TestPipe1Lorem(t *testing.T) {
	const lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	testWithPipe([]byte(lorem), compress.Pipeline{bwt, moveToFront, rle0zct})
}

func TestPipe1LoremWithHuffman(t *testing.T) {
	const lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	testWithPipe([]byte(lorem), compress.Pipeline{bwt, moveToFront, rle0zct, huffman.Encode})
}

func TestLargeZct(t *testing.T) {
	testFileWithPipe(t, "../large/data.bin", compress.Pipeline{bwt, moveToFront, rle0zct, huffman.Encode})
}

func TestLargeRLE2(t *testing.T) {
	testFileWithPipe(t, "../large/data.bin", compress.Pipeline{bwt, moveToFront, rle0bzip2, huffman.Encode})
}
