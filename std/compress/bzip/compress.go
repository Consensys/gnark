package bzip

import (
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/std/compress"
	"sort"
)

// bwt is a crude implementation of the Burrows-Wheeler transform.
func bwt(in compress.Stream) compress.Stream {
	order := make([]int, in.Len())
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		for k := range in.D { // sort lexicographically
			iK := in.D[(order[i]+k)%in.Len()]
			jK := in.D[(order[j]+k)%in.Len()]
			if iK != jK {
				return iK < jK
			}
		}
		return false
	})
	out := make([]int, in.Len())
	for i := range out {
		out[i] = in.D[(order[i]+in.Len()-1)%in.Len()] // last column
	}
	return compress.Stream{D: out, NbSymbs: in.NbSymbs}
}

// moveToFront implements a simple algorithm that turns runs of identical symbols into runs of zeros, and generally creates a bias towards numerically small symbols.
func moveToFront(in compress.Stream) compress.Stream {
	symbolsIndexes := make([]int, in.NbSymbs)
	for i := range symbolsIndexes {
		symbolsIndexes[i] = i
	}

	out := make([]int, in.Len())
	for i := range out {
		b := in.D[i]
		out[i] = symbolsIndexes[b]

		for j := range symbolsIndexes {
			if symbolsIndexes[j] < out[i] {
				symbolsIndexes[j]++
			}
		}
		symbolsIndexes[b] = 0
	}
	return compress.Stream{D: out, NbSymbs: in.NbSymbs}
}

// rle0bzip2 implements a simple run-length encoding, only for the zero symbol, and similar to bzip2's RLE.
func rle0bzip2(in compress.Stream) compress.Stream {
	out := make([]int, 0, in.Len())
	for i := 0; i < in.Len(); {
		if in.D[i] == 0 {
			runLen := in.RunLen(i)

			i += runLen

			for runLen++; runLen != 1; runLen /= 2 { // encoding RunLen+1 so that runs of length 1 are encoded as 1
				out = append(out, (runLen%2)*in.NbSymbs)
			}

		} else {
			out = append(out, in.D[i])
			i++
		}
	}
	return compress.Stream{D: out, NbSymbs: in.NbSymbs + 1}
}

func rle0zct(in compress.Stream) compress.Stream {

	out := make([]int, 0, in.Len())
	for i := 0; i < in.Len(); i++ {
		out = append(out, in.D[i])
		if in.D[i] == 0 {
			runLen := utils.Min(in.RunLen(i), in.NbSymbs) - 1

			out = append(out, runLen)

			i += runLen
		}
	}
	return compress.Stream{D: out, NbSymbs: in.NbSymbs}
}
