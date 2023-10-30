package lzss_v2

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark/std/compress/lzss_v2/suffixarray"
	"github.com/icza/bitio"
)

const (
	nbBitsAddress   = 20
	nbBitsLength    = 9
	nbBitsBackRef   = 8 + nbBitsAddress + nbBitsLength
	nbBytesBackRef  = (nbBitsBackRef + 7) / 8
	maxInputSize    = 1 << 21 // 2Mb
	maxDictSize     = 1 << 22 // 4Mb
	maxAddress      = 1 << nbBitsAddress
	maxLength       = 1 << nbBitsLength
	debugCompressor = false
)

type Compressor struct {
	data  [maxDictSize + maxInputSize]byte
	dict  []byte
	end   int
	index *suffixarray.Index
	sa    [maxDictSize + maxInputSize]int32 // suffix array space.
	buf   bytes.Buffer
	bw    *bitio.Writer
}

// NewCompressor returns a new compressor with the given dictionary
func NewCompressor(dict []byte) (*Compressor, error) {
	if len(dict) > maxDictSize {
		return nil, fmt.Errorf("dict size must be <= %d", maxDictSize)
	}
	c := &Compressor{
		dict: dict,
		end:  len(dict),
	}
	c.buf.Grow(maxInputSize)
	copy(c.data[:], dict)
	return c, nil
}

// Compress compresses the given data
func (compressor *Compressor) Compress(d []byte) (c []byte, err error) {
	// check input size
	if len(d) > maxInputSize {
		return nil, fmt.Errorf("input size must be <= %d", maxInputSize)
	}

	// reset output buffer
	compressor.buf.Reset()
	compressor.bw = bitio.NewWriter(&compressor.buf)

	// copy d into compressor.data
	copy(compressor.data[len(compressor.dict):], d)
	compressor.end = len(compressor.dict) + len(d)

	// build the index
	compressor.index = suffixarray.New(compressor.data[:compressor.end], compressor.sa[:compressor.end])

	// start after dictionary
	i := len(compressor.dict)

	// under that threshold, it's more interesting to write the symbol directly.
	const minRefLen = nbBytesBackRef

	for i < compressor.end {
		if !canEncodeSymbol(compressor.data[i]) {
			// we must find a backref.
			addr, length := compressor.findBackRef(i, 1)
			if length == -1 {
				// we didn't find a backref but can't write the symbol directly
				return nil, fmt.Errorf("could not find a backref at index %d", i)
			}
			compressor.writeBackRef(i-addr, length)
			i += length
			continue
		}

		addr, length := compressor.findBackRef(i, minRefLen)
		if length == -1 {
			// we didn't find a backref, let's write the symbol directly
			compressor.writeByte(compressor.data[i])
			i++
			continue
		}

		if length < maxLength && i+1 < compressor.end {
			// let's try to find a better backref
			if lazyAddr, lazyLength := compressor.findBackRef(i+1, length+1); lazyLength != -1 {
				// we found a better backref
				// first emit the symbol at i
				compressor.writeByte(compressor.data[i])
				i++

				// then emit the backref at i+1
				addr, length = lazyAddr, lazyLength

				// can we find an even better backref?
				if canEncodeSymbol(compressor.data[i]) && i+1 < compressor.end {
					if lazyAddr, lazyLength := compressor.findBackRef(i+1, length+1); lazyLength != -1 {
						// we found an even better backref
						// write the symbol at i
						compressor.writeByte(compressor.data[i])
						i++
						addr, length = lazyAddr, lazyLength
					}
				}
			} else if i+2 < compressor.end && canEncodeSymbol(compressor.data[i+1]) {
				// maybe at i+2 ? (we already tried i+1)
				if lazyAddr, lazyLength := compressor.findBackRef(i+2, length+2); lazyLength != -1 {
					// we found a better backref
					// write the symbol at i
					compressor.writeByte(compressor.data[i])
					i++
					compressor.writeByte(compressor.data[i])
					i++

					// then emit the backref at i+2
					addr, length = lazyAddr, lazyLength
				}
			}
		}
		compressor.writeBackRef(i-addr, length)
		i += length

	}

	if compressor.bw.TryError != nil {
		return nil, compressor.bw.TryError
	}
	if err := compressor.bw.Close(); err != nil {
		return nil, err
	}

	return compressor.buf.Bytes(), nil
}

// canEncodeSymbol returns true if the symbol can be encoded directly
func canEncodeSymbol(b byte) bool {
	return b != 0
}

func (compressor *Compressor) writeByte(b byte) {
	if debugCompressor && canEncodeSymbol(b) {
		panic("can't encode symbol directly")
	}
	compressor.bw.TryWriteByte(b)
}

func (compressor *Compressor) writeBackRef(offset, length int) {
	compressor.bw.TryWriteByte(0)
	compressor.bw.TryWriteBits(uint64(offset-1), nbBitsAddress)
	compressor.bw.TryWriteBits(uint64(length-1), nbBitsLength)
}

// findBackRef attempts to find a backref in the window [i-brAddressRange, i+brLengthRange]
// if no backref is found, it returns -1, -1
// else returns the address and length of the backref
func (compressor *Compressor) findBackRef(i, minRefLen int) (addr, length int) {
	if i+minRefLen > compressor.end {
		return -1, -1
	}

	windowStart := max(0, i-maxAddress)
	maxRefLen := maxLength

	if i+maxRefLen > compressor.end {
		maxRefLen = compressor.end - i
	}
	if minRefLen > maxRefLen {
		return -1, -1
	}

	return compressor.index.LookupLongest(compressor.data[i:i+maxRefLen], minRefLen, maxRefLen, windowStart, i)
}
