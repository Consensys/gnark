package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/lzss_v1/lzssv1-analyze/require"
	"os"
	"strings"
)

func main() {
	inFilename := flag.String("in", "", "lzssv1 input file")
	//diffIn := flag.String("diff", "", "second lzssv1 input file to diff against")
	posU := flag.Uint("pos", 1<<63, "position of interest (decompressed)")
	hx := flag.Bool("hx", false, "read input files in hx format")
	symb := flag.Int("symb", 0, "symbol that indicates a backref (default: 0)")
	nbBytesLenU := flag.Uint("len", 1, "number of bytes used to encode the length of a backref (default: 1)")
	nbBytesAddrU := flag.Uint("addr", 2, "number of bytes used to encode the address of a backref (default: 2)")
	ctx := flag.String("ctx", "", "address of context file (defaults to 2^len zeros)")
	flag.Parse()

	nbBytesLen := int(*nbBytesLenU)
	nbBytesAddr := int(*nbBytesAddrU)
	pos := int(*posU)

	var c compress.Stream
	if *inFilename == "" {
		require.NotEqual(*inFilename, "", "TODO: Read from stdin when no file is provided")
	} else {
		b, err := os.ReadFile(*inFilename)
		require.NoError(err)
		if *hx {
			b, err = hex.DecodeString(string(b))
			require.NoError(err)
		}
		c.Read(b)
	}

	var d []byte
	if *ctx == "" {
		d = make([]byte, 1<<(nbBytesLen*8))
	} else {
		panic("TODO: read context file")
	}

	var br0, br1 backref
	startAt := len(d)
	cI := 0
	dI := startAt
	for br1.dst <= pos {
		if c.D[cI] == *symb { // backref
			length := c.ReadNum(cI+1, nbBytesLen) + 1
			offset := c.ReadNum(cI+1+nbBytesLen, nbBytesAddr) + 1

			br0 = br1
			br1 = backref{offset, length, dI - startAt}

			for end := dI + length; dI < end; dI++ {
				d[dI] = d[dI-offset]
			}

			cI += 1 + nbBytesLen + nbBytesAddr
		} else {
			d[dI] = byte(c.D[cI])
			dI++
			cI++
		}
	}

	printFindings(d[startAt:], pos, br0, br1)
}

func printFindings(d []byte, pos int, br0, br1 backref) {
	s0 := br0.string()
	s1 := br1.string()
	const lenEachSide = 44
	arrow := strings.Repeat(" ", lenEachSide)
	arrow = arrow + "^" + arrow

	fmt.Print(s0)
	if len(s0)%2 != 0 {
		fmt.Print(" ")
	}
	nbL := lenEachSide/2 - (len(s0)+1)/2
	nbR := lenEachSide/2 - (len(s1)+1)/2
	fmt.Print(hex.EncodeToString(d[pos-nbL : nbL+nbR]))
	if len(s1)%2 != 0 {
		fmt.Print(" ")
	}
	fmt.Print(s1)
}

type backref struct {
	offset, len, dst int
}

func (b backref) string() string {
	return fmt.Sprintf("[(%d,%d)@%d->%d]", -b.offset, b.len, b.dst-b.offset, b.dst)
}
