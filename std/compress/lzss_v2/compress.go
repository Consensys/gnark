package lzss_v2

// lzss_v2 is a worse-performing but more efficiently snark-decompressed version of lzss_v1.
// it works on a 2-byte granularity level
// since 0s can only be encoded as backrefs and backref lengths are even, we devise a special case for two-byte sequences starting with a 0
// for this purpose, we reserve the last backref address
// annoyingly, this means that there are two canonical ways to encode two 0s

// lzss_v2 is an almost generalized version of lzss_v1 with word sizes that are not necessarily 8 bits.
// it's not quite a generalization because currently only one word (plus delta bits) are dedicated to backref offset

import (
	"fmt"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/std/compress"
)

// Compress dge
func Compress(D compress.Stream, brAdrNbBits int) (c compress.Stream, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	c.D = make([]int, 0)
	c.NbSymbs = D.NbSymbs

	// trying to encode both in one word
	backRefAddressRange := 1 << brAdrNbBits
	backRefLengthRange := D.NbSymbs >> brAdrNbBits

	emitBackRef := func(offset, length int) {
		if offset > backRefAddressRange || offset <= 0 {
			panic("offset out of range")
		}
		if length > backRefLengthRange || length <= 0 {
			panic("length out of range")
		}
		offset--
		length--
		c.D = append(c.D, 0, offset|(length<<brAdrNbBits))
	}

	i := 0
	for i < len(D.D) {

		if addr, length := longestMostRecentBackRef(D, i, brAdrNbBits, i-backRefAddressRange); length != -1 {

			// if we're fortunate enough to have found a backref that is "too long", break it up
			for remainingLen := length; remainingLen > 0; remainingLen -= backRefLengthRange {
				nbWriting := utils.Min(remainingLen, backRefLengthRange)
				emitBackRef(i-addr, nbWriting)
			}
			i += length
			continue
		}

		// no backref found
		if D.D[i] == 0 { // TODO Make negative indices a last resort. Better to still try and find a "real" backref first.
			return compress.Stream{NbSymbs: -1}, fmt.Errorf("could not find an RLE backref at index %d", i)
		} else {
			c.D = append(c.D, D.D[i])
			i++
		}

	}

	return c, nil
}

// longestMostRecentBackRef attempts to find a backref that is 1) longest 2) most recent in that order of priority
func longestMostRecentBackRef(D compress.Stream, i int, brAdrNbBits, minBackRefAddr int) (addr, length int) {

	minBackRefLen := 3

	// TODO: Implement an efficient string search algorithm
	// greedily find the longest backref with smallest offset TODO better heuristic?
	remainingOptions := make(map[int]struct{})
	if D.D[i] == 0 { // RLE; prune the options
		runLen := utils.Min(getRunLength(D.D, i), D.NbSymbs>>brAdrNbBits)
		longestLen := 0
		if i == 0 || D.D[i-1] == 0 {
			remainingOptions[i-1] = struct{}{}
			longestLen = runLen
		}

		for j := i - 1; j >= 0 && j >= minBackRefAddr; { // TODO If logging is enabled, go past minBackRefAddr to spot missed opportunities
			if D.D[j] != 0 {
				j--
				continue
			}

			currentRunLen := getRunLengthRev(D.D, j)
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

		minBackRefLen = longestLen

	} else {
		if i+minBackRefLen > len(D.D) {
			return -1, -1
		}
		minBackRef := D.D[i : i+minBackRefLen]
		// find backref candidates that satisfy the minimum length requirement

		for j := i - 1; j >= 0 && j >= minBackRefAddr; j-- { // TODO If logging is enabled, go past minBackRefAddr to spot missed opportunities
			if j+minBackRefLen > len(D.D) {
				continue
			}
			if intsEqual(D.D[j:j+minBackRefLen], minBackRef) {
				remainingOptions[j] = struct{}{}
			}
		}
	}

	var toDelete []int
	l := minBackRefLen
	// now find the longest backref among the candidates
	for ; i+l <= len(D.D); l++ {
		for _, j := range toDelete {
			delete(remainingOptions, j)
		}
		toDelete = toDelete[:0]
		for j := range remainingOptions {
			if i+l >= len(D.D) || D.D[j+l] != D.D[i+l] {
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

func min(a ...int) int {
	res := a[0]
	for _, v := range a[1:] {
		if v < res {
			res = v
		}
	}
	return res
}

func intsEqual(a, b []int) bool {
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

func getRunLength(d []int, i int) int {
	j := i + 1
	for j < len(d) && d[j] == d[i] {
		j++
	}
	return j - i
}

func getRunLengthRev(d []int, i int) int {
	j := i - 1
	for j >= 0 && d[j] == d[i] {
		j--
	}
	return i - j
}
