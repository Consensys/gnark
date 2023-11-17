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

func (b *backref) writeTo(w *bitio.Writer, i int) {
	w.TryWriteByte(b.bType.delimiter)
	w.TryWriteBits(uint64(b.length-1), b.bType.nbBitsLength)
	if b.bType.dictOnly {
		w.TryWriteBits(uint64(b.address), b.bType.nbBitsAddress)
	} else {
		w.TryWriteBits(uint64(i-b.address-1), b.bType.nbBitsAddress)
	}
}

func (b *backref) readFrom(r *bitio.Reader) {
	b.length = int(r.TryReadBits(b.bType.nbBitsLength)) + 1
	if b.bType.dictOnly {
		b.address = int(r.TryReadBits(b.bType.nbBitsAddress))
	} else {
		b.address = int(r.TryReadBits(b.bType.nbBitsAddress)) + 1
	}
}

func (b *backref) savings() int {
	if b.length == -1 {
		return math.MinInt // -1 is a special value
	}
	return b.length - b.bType.nbBytesBackRef
}
