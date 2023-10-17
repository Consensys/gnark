package lzss_v1

import (
	"bytes"
	"fmt"
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

	backRefLengthRange := 1 << (settings.NbBytesLength * 8)

	emitBackRef := func(offset, length int) {
		out.WriteByte(0)
		emit(&out, offset-1, settings.NbBytesAddress)
		emit(&out, length-1, settings.NbBytesLength)
	}

	i := 0
	for i < len(d) {

		if addr, length := longestMostRecentBackRef(d, i, settings); length != -1 {

			// if we're fortunate enough to have found a backref that is "too long", break it up
			for remainingLen := length; remainingLen > 0; remainingLen -= backRefLengthRange { // TODO Is this necessary? Does longestMostRecentBackRef ever give an overly lengthy result?
				nbWriting := utils.Min(remainingLen, backRefLengthRange)
				emitBackRef(i-addr, nbWriting)
			}
			i += length
			continue
		}

		// no backref found
		if d[i] == 0 {
			return nil, fmt.Errorf("could not find an RLE backref at index %d", i)
		} else {
			out.WriteByte(d[i])
			i++
		}

	}

	return out.Bytes(), nil
}

// longestMostRecentBackRef attempts to find a backref that is 1) longest 2) most recent in that order of priority
func longestMostRecentBackRef(d []byte, i int, settings Settings) (addr, length int) {
	var backRefLen int
	brAddressRange := 1 << (settings.NbBytesAddress * 8)
	brLengthRange := 1 << (settings.NbBytesLength * 8)
	minBackRefAddr := i - brAddressRange

	// TODO: Implement an efficient string search algorithm
	// greedily find the longest backref with smallest offset TODO better heuristic?
	remainingOptions := make(map[int]struct{})
	if d[i] == 0 { // RLE; prune the options
		runLen := utils.Min(getRunLength(d, i), brLengthRange)
		longestLen := 0
		if i == 0 || d[i-1] == 0 {
			remainingOptions[i-1] = struct{}{}
			longestLen = runLen
		}

		for j := i - 1; j >= 0 && j >= minBackRefAddr; {
			if d[j] != 0 {
				j--
				continue
			}

			currentRunLen := getRunLengthRev(d, j)
			usableRunLen := min(currentRunLen, runLen, j-minBackRefAddr)
			if usableRunLen == longestLen {
				remainingOptions[j-usableRunLen+1] = struct{}{}
			} else if usableRunLen > longestLen {
				remainingOptions = map[int]struct{}{j - usableRunLen + 1: {}}
				longestLen = usableRunLen
			}
			j -= currentRunLen
		}
		if negativeRun := utils.Min(utils.Max(0, -minBackRefAddr), runLen); longestLen < negativeRun {
			longestLen = negativeRun
			remainingOptions = map[int]struct{}{-negativeRun: {}}
		}

		backRefLen = longestLen

	} else {
		backRefLen = 1 + int(settings.NbBytesAddress+settings.NbBytesLength)
		if i+backRefLen > len(d) {
			return -1, -1
		}
		minViableBackRef := d[i : i+backRefLen]
		// find backref candidates that satisfy the minimum length requirement

		for j := i - 1; j >= 0 && j >= minBackRefAddr; j-- {
			if j+backRefLen > len(d) {
				continue
			}
			if bytesEqual(d[j:j+backRefLen], minViableBackRef) {
				remainingOptions[j] = struct{}{}
			}
		}
	}

	var toDelete []int

	// now find the longest backref among the candidates
	for ; i+backRefLen <= len(d); backRefLen++ {
		for _, j := range toDelete {
			delete(remainingOptions, j)
		}
		toDelete = toDelete[:0]
		for j := range remainingOptions {
			if i+backRefLen >= len(d) || d[j+backRefLen] != d[i+backRefLen] {
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
	return mostRecent, backRefLen
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

func getRunLength(d []byte, i int) int {
	j := i + 1
	for j < len(d) && d[j] == d[i] {
		j++
	}
	return j - i
}

func getRunLengthRev(d []byte, i int) int {
	j := i - 1
	for j >= 0 && d[j] == d[i] {
		j--
	}
	return i - j
}
