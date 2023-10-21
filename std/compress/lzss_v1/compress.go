package lzss_v1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"index/suffixarray"
	"math/bits"

	"github.com/consensys/gnark-crypto/utils"
)

// The backref logic can produce RLE as a special case, which is good for decompressor state machine complexity
// however we have to make some sacrifices such as allowing very small lengths/offsets that wouldn't be viable for a "real" backref
// if the state machine logic turned out to be a tiny portion of total decompressor constraints, as it's expected to be,
// consider separating RLE/backref logics

// Compress applies a DEFLATE-inspired, LZSS-type compression on d.
// It does well on data with many long repeated substrings and long runs of similar bytes, e.g. programmatic data.
// It can be improved by further compression using a prefix-free code, such as Huffman coding.
// In fact, DEFLATE is LZSS + Huffman coding. It is implemented in gzip which is the standard tool for compressing programmatic data.
// For more information, refer to Bill Bird's fantastic undergraduate course on Data Compression
// In particular those on the LZ family: https://youtu.be/z1I1o7zySUI and DEFLATE: https://youtu.be/SJPvNi4HrWQ
func Compress(d []byte, settings Settings) (c []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer

	emitBackRef := func(offset, length int) {
		out.WriteByte(0)
		emit(&out, offset-1, settings.NbBytesAddress)
		emit(&out, length-1, settings.NbBytesLength)
	}
	compressor := newCompressor(d, settings)
	i := int(settings.StartAt)
	for i < len(d) {
		addr, length := compressor.longestMostRecentBackRef(i)
		if length == -1 {
			// no backref found
			if d[i] == 0 {
				return nil, fmt.Errorf("could not find an RLE backref at index %d", i)
			}
			out.WriteByte(d[i])
			i++
			continue
		}
		emitBackRef(i-addr, length)
		i += length
	}

	return out.Bytes(), nil
}

type compressor struct {
	// TODO @gbotrel we have to be a bit careful with the size
	// and do some extra checks; here we assume that we never compress more than 1MB
	longestZeroPrefix [1 << 20]int // longestZeroPrefix[i] = longest run of zeroes starting at i
	d                 []byte
	index             *suffixarray.Index
	settings          Settings
}

func newCompressor(d []byte, settings Settings) *compressor {
	compressor := &compressor{
		d:        d,
		index:    suffixarray.New(d),
		settings: settings,
	}
	compressor.initZeroPrefix()
	return compressor
}

func (compressor *compressor) initZeroPrefix() {
	d := compressor.d
	for j := len(d) - 1; j >= 0; j-- {
		if d[j] != 0 {
			compressor.longestZeroPrefix[j] = 0
			continue
		}
		compressor.longestZeroPrefix[j] = 1 + compressor.longestZeroPrefix[j+1]
	}
}

// longestMostRecentBackRef attempts to find a backref that is 1) longest 2) most recent in that order of priority
func (compressor *compressor) longestMostRecentBackRef(i int) (addr, length int) {
	d := compressor.d
	// var backRefLen int
	brAddressRange := 1 << (compressor.settings.NbBytesAddress * 8)
	brLengthRange := 1 << (compressor.settings.NbBytesLength * 8)
	minBackRefAddr := i - brAddressRange

	windowStart := utils.Max(0, minBackRefAddr)
	endWindow := utils.Min(i+brAddressRange, len(d))

	if d[i] == 0 { // RLE; prune the options
		// we can't encode 0 as is, so we must find a backref.

		// runLen := compressor.countZeroes(i, brLengthRange) // utils.Min(getRunLength(d, i), brLengthRange)
		runLen := utils.Min(compressor.longestZeroPrefix[i], brLengthRange)

		backrefAddr := -1
		backrefLen := -1
		for j := i - 1; j >= windowStart; j-- {
			n := utils.Min(compressor.longestZeroPrefix[j], runLen)
			if n == 0 {
				continue
			}
			// check if we can make this backref longer
			m := matchLen(d[i+n:endWindow], d[j+n:]) + n

			if m > backrefLen {
				if m >= brLengthRange {
					// we can stop we won't find a longer backref
					return j, brLengthRange
				}
				backrefLen = m
				backrefAddr = j
			}
		}
		return backrefAddr, backrefLen
	}

	// else -->
	// d[i] != 0

	// under that threshold, it's more interesting to write the symbol directly.
	t := int(1 + compressor.settings.NbBytesAddress + compressor.settings.NbBytesLength)

	if i+t > len(d) {
		return -1, -1
	}

	matches := compressor.index.Lookup(d[i:i+t], -1)

	bLen := -1
	bAddr := -1
	for _, offset := range matches {
		if offset < windowStart || offset >= i {
			// out of the window bound
			continue
		}
		n := matchLen(d[i+t:endWindow], d[offset+t:]) + t
		if n > bLen {
			bLen = n
			if bLen >= brLengthRange {
				// we can stop we won't find a longer backref
				return offset, brLengthRange
			}
			bAddr = offset
		}

	}

	return bAddr, bLen

}

// matchLen returns the maximum common prefix length of a and b.
// a must be the shortest of the two.
func matchLen(a, b []byte) (n int) {
	for ; len(a) >= 8 && len(b) >= 8; a, b = a[8:], b[8:] {
		diff := binary.LittleEndian.Uint64(a) ^ binary.LittleEndian.Uint64(b)
		if diff != 0 {
			return n + bits.TrailingZeros64(diff)>>3
		}
		n += 8
	}

	for i := range a {
		if a[i] != b[i] {
			break
		}
		n++
	}
	return n

}

func emit(bb *bytes.Buffer, n int, nbBytes uint) {
	for i := uint(0); i < nbBytes; i++ {
		bb.WriteByte(byte(n))
		n >>= 8
	}
	if n != 0 {
		panic("n does not fit in nbBytes")
	}
}
