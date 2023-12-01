package lzss

import (
	"math"

	"github.com/icza/bitio"
)

const (
	maxInputSize = 1 << 21 // 2Mb
	maxDictSize  = 1 << 22 // 4Mb
)

type backrefType struct {
	delimiter      byte
	nbBitsAddress  uint8
	nbBitsLength   uint8
	nbBitsBackRef  uint8
	nbBytesBackRef int
	maxAddress     int
	maxLength      int
	dictOnly       bool
}

func newBackRefType(symbol byte, nbBitsAddress, nbBitsLength uint8, dictOnly bool) backrefType {
	return backrefType{
		delimiter:      symbol,
		nbBitsAddress:  nbBitsAddress,
		nbBitsLength:   nbBitsLength,
		nbBitsBackRef:  8 + nbBitsAddress + nbBitsLength,
		nbBytesBackRef: int(8+nbBitsAddress+nbBitsLength+7) / 8,
		maxAddress:     1 << nbBitsAddress,
		maxLength:      1 << nbBitsLength,
		dictOnly:       dictOnly,
	}
}

const (
	symbolDict  = 0xFF
	symbolShort = 0xFE
	symbolLong  = 0xFD
)

type backref struct {
	address int
	length  int
	bType   backrefType
}

func panicIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func (b *backref) writeTo(w *bitio.Writer, i int) {
	panicIfErr(w.WriteByte(b.bType.delimiter))
	panicIfErr(w.WriteBits(uint64(b.length-1), b.bType.nbBitsLength))
	addrToWrite := b.address
	if !b.bType.dictOnly {
		addrToWrite = i - b.address - 1
	}
	panicIfErr(w.WriteBits(uint64(addrToWrite), b.bType.nbBitsAddress))
}

func (b *backref) readFrom(r *bitio.Reader) {
	n, err := r.ReadBits(b.bType.nbBitsLength)
	panicIfErr(err)
	b.length = int(n) + 1

	n, err = r.ReadBits(b.bType.nbBitsAddress)
	panicIfErr(err)
	b.address = int(n)
	if !b.bType.dictOnly {
		b.address++
	}
}

func (b *backref) savings() int {
	if b.length == -1 {
		return math.MinInt // -1 is a special value
	}
	return b.length - b.bType.nbBytesBackRef
}
