package lzss_v1

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/std/compress"
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
	// d[i < 0] = settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer

	if settings.ReferenceTo == Compressed {
		return nil, errors.New("compressed ref not implemented")
	}
	if settings.AddressingMode == Absolute {
		return nil, errors.New("absolute addressing not implemented")
	}

	// we write offset first and then length, for no particular reason
	// "nontrivial" meaning of length and offset more than 1
	minNontrivialBackRefCost := int(compress.ByteGasCost(settings.Symbol)) + 8 + int(settings.NbBytesAddress+settings.NbBytesLength-2)
	// any string of lesser cost than minBackrefCost is not worth compressing
	// this also means that very short runs of zeros are expanded rather than compressed
	backRefAddressRange := 1 << (settings.NbBytesAddress * 8)
	backRefLengthRange := 1 << (settings.NbBytesLength * 8)

	getRunLength := func(i int) int {
		j := i + 1
		for j < len(d) && d[j] == d[i] {
			j++
		}
		return j - i
	}

	i := 0
	for i < len(d) {
		*settings.LogHeads = append(*settings.LogHeads, LogHeads{
			Compressed:   out.Len(),
			Decompressed: i,
		})

		emitBackRef := func(offset, length int) {
			out.WriteByte(settings.Symbol)
			emit(&out, offset-1, settings.NbBytesAddress)
			emit(&out, length-1, settings.NbBytesLength)
			if settings.Logger != nil {
				_, err = settings.Logger.WriteString(
					fmt.Sprintf("(%d:%d) %d->%d\t%s", offset, length, i, i-offset, hex.EncodeToString(d[i-offset:min(i-offset+length, len(d))])),
				)
			}
		}

		// if there is a run of the character used to mark backrefs, we have to make a backref regardless of whether it achieves compression

		// attempt to find a backref, if it's worthwhile
		// first we decide how long a backref would have to be just to be worth it
		// this would minimize the backref search space early on and thus improve performance
		minViableBackRefLength := 2
		noBackRefCost := int(compress.ByteGasCost(d[i]))
		var midRle bool
		for {
			if i+minViableBackRefLength > len(d) {
				minViableBackRefLength = -1 // just not viable
				break
			}

			curr := d[i+minViableBackRefLength-1]

			if curr == settings.Symbol {
				midRle = true
			} else {
				if midRle {
					noBackRefCost += minViableBackRefLength // getting rid of an RLE, though the cost is not exact. TODO: fix that (probably move the RLE logic to a separate function that could be called here)
				}
				midRle = false

				noBackRefCost += int(compress.ByteGasCost(curr))
				if noBackRefCost > minNontrivialBackRefCost {
					break
				}
			}
			minViableBackRefLength++
		}

		if minViableBackRefLength != -1 { // if a backref is deemed possible, try and find one
			if addr, length := longestMostRecentBackRef(d, i, i-backRefAddressRange-1, minViableBackRefLength); length != -1 {

				// if we're fortunate enough to have found a backref that is "too long", break it up
				for remainingLen := length; remainingLen > 0; remainingLen -= backRefLengthRange {
					nbWriting := utils.Min(remainingLen, backRefLengthRange)
					emitBackRef(i-addr, nbWriting)
				}
				i += length
				continue
			}
		}

		// no backref found
		if d[i] == settings.Symbol { // TODO Make negative indices a last resort. Better to still try and find a "real" backref first.
			// TODO This way we may be able to reduce the size of offsets dramatically and possibly get away with fewer bytes dedicated
			// TODO to denoting offsets. Removing extra bytes that are zeros may not help gas compression much, but will likely help with snark efficiency
			runLength := getRunLength(i) // TODO If logging, go past maxJExpressible to spot missed opportunities
			// making a "back reference" to negative indices
			if i == 0 { // "back reference" the stream itself as it is being written
				for remainingRun := runLength; remainingRun > 0; remainingRun -= backRefLengthRange {
					emitBackRef(1, utils.Min(remainingRun, backRefLengthRange))
				}
			} else if
			// TODO Limit the negative index idea to only -1 and add an explicit rule to handle it in the decompressor if the extra 1 << NbLengthBytes table entries were too expensive
			i+1 <= backRefAddressRange { // TODO make sure the boundary is correct
				maxNegativeBackRefLength := backRefAddressRange - i - 1
				// try and get it all done with a "negative" ref
				currentRun := min(runLength, maxNegativeBackRefLength, backRefLengthRange)
				emitBackRef(i+currentRun, currentRun)
				for remainingRun := runLength - currentRun; remainingRun > 0; remainingRun -= backRefLengthRange {
					emitBackRef(1, utils.Min(remainingRun, backRefLengthRange))
				}
			}
			i += runLength
		} else {
			out.WriteByte(d[i])
			i++
		}

	}

	return out.Bytes(), nil
}

// longestMostRecentBackRef attempts to find a backref that is 1) longest 2) most recent in that order of priority
func longestMostRecentBackRef(d []byte, i, minBackRefAddr, minViableBackRefLen int) (addr, length int) {
	// TODO: Implement an efficient string search algorithm
	// greedily find the longest backref with smallest offset TODO better heuristic?
	minViableBackRef := d[i : i+minViableBackRefLen]
	remainingOptions := make(map[int]struct{})
	// find backref candidates that satisfy the minimum length requirement
	for j := i - 1; j >= 0 && j >= minBackRefAddr; j-- { // TODO If logging is enabled, go past minBackRefAddr to spot missed opportunities
		if j+minViableBackRefLen > len(d) {
			continue
		}
		if bytesEqual(d[j:j+minViableBackRefLen], minViableBackRef) {
			remainingOptions[j] = struct{}{}
		}
	}
	var toDelete []int
	l := minViableBackRefLen
	// now find the longest backref among the candidates
	for ; i+l < len(d); l++ {
		for _, j := range toDelete {
			delete(remainingOptions, j)
		}
		toDelete = toDelete[:0]
		for j := range remainingOptions {
			if j+l > len(d) || d[j+l] != d[i+l] {
				toDelete = append(toDelete, j)
			}
		}
		// no options left
		if len(toDelete) == len(remainingOptions) {
			break
		}
	}
	// never had any candidates in the first place
	if len(remainingOptions) == 0 {
		return -1, -1
	}
	// we have candidates of the same length, so pick the most recent
	mostRecent := minBackRefAddr - 1
	for j := range remainingOptions {
		if j > mostRecent {
			mostRecent = j
		}
	}
	return mostRecent, l
}

// emit writes little endian
func emit(bb *bytes.Buffer, n int, nbBytes uint) {
	for i := uint(0); i < nbBytes; i++ {
		bb.WriteByte(byte(n))
		n >>= 8
	}
	if n != 0 {
		panic("n does not fit in nbBytes")
	}
}

func min(a ...int) int {
	res := a[0]
	for _, v := range a[1:] {
		if v < res {
			res = v
		}
	}
	return res
}

// bytes.Equal is acting erratically?
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
