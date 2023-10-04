package huffman

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"golang.org/x/exp/slices"
	"sort"
)

// Decode input bits according to the given symbol lengths. TODO support symbol lengths as variables
func Decode(api frontend.API, inBits []frontend.Variable, inLen frontend.Variable, symbolLengths []int, out []frontend.Variable) (outLen frontend.Variable, err error) {
	codeLens := logderivlookup.New(api)
	codeSymbs := logderivlookup.New(api)
	{
		symbs, lens := LengthsToTables(symbolLengths)
		for i := range symbolLengths {
			codeLens.Insert(lens[i])
			codeSymbs.Insert(symbs[i])
		}
	}

	in := logderivlookup.New(api)
	for i := range inBits {
		in.Insert(inBits[i])
	}

	outLen = 0
	toLookUp := make([]frontend.Variable, slices.Max(symbolLengths))
	inI := frontend.Variable(0)
	eof := api.IsZero(inLen)
	for outI := range out {
		for i := range toLookUp {
			toLookUp[i] = api.Add(inI, i)
		}
		symbRead := frontend.Variable(0)
		{
			bits := in.Lookup(toLookUp...)
			for i := range bits {
				symbRead = api.MulAcc(bits[len(bits)-i-1], symbRead, symbRead)
			}
		}

		out[outI] = codeSymbs.Lookup(symbRead)[0]
		readSymbLen := codeLens.Lookup(symbRead)[0]
		nextInI := api.Add(inI, readSymbLen)
		eofNow := api.IsZero(api.Sub(inLen, nextInI))
		outLen = api.Select(api.Sub(eofNow, eof), outI+1, outLen)
		eof = eofNow
		inI = api.MulAcc(inI, api.Sub(1, eof), readSymbLen)
	}

	return outLen, nil
}

func LengthsToTables(symbolLengths []int) (symbsTable, lengthsTable []uint64) {
	codes := LengthsToCodes(symbolLengths)
	maxCodeSize := slices.Max(symbolLengths)
	symbsTable = make([]uint64, 1<<(maxCodeSize-1))
	lengthsTable = make([]uint64, 1<<(maxCodeSize-1))
	for i := range codes {
		l := symbolLengths[i]
		base := codes[i] << uint64(maxCodeSize-l)
		for j := uint64(0); j < 1<<uint64(maxCodeSize-l); j++ {
			symbsTable[base+j] = uint64(i)
			lengthsTable[base+j] = uint64(l)
		}
	}
	return
}

func LengthsToCodes(symbolLengths []int) []uint64 {
	symbs := _range(len(symbolLengths))
	sort.Slice(symbs, func(i, j int) bool {
		return symbolLengths[symbs[i]] < symbolLengths[symbs[j]] || (symbolLengths[symbs[i]] == symbolLengths[symbs[j]] && symbs[i] < symbs[j])
	})
	codes := make([]uint64, len(symbolLengths))
	prevLen := 0
	code := -1
	for _, s := range symbs {
		code++
		for prevLen < symbolLengths[s] {
			code <<= 1
			prevLen++
		}
		codes[s] = uint64(code)
	}
	return codes
}

func _range(i int) []int {
	out := make([]int, i)
	for j := range out {
		out[j] = j
	}
	return out
}
