package lzss_v1

import (
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"sort"
)

// Decompress implements the decompression logic implemented in both DecompressPureGo and decompressStateMachine, pretty much identical to the latter.
func Decompress(api frontend.API, c []frontend.Variable, cLength frontend.Variable, d []frontend.Variable, settings Settings) (dLength frontend.Variable, err error) {
	if settings.BackRefSettings.NbBytesLength != 1 {
		return -1, errors.New("currently only byte-long backrefs supported")
	}
	if settings.BackRefSettings.Symbol != 0 {
		return -1, errors.New("currently only 0 is supported as the backreference signifier")
	}

	brLengthRange := 1 << (settings.NbBytesLength * 8)
	isBitTable := newTable(api, brLengthRange, []intPair{{0, 1}, {1, 1}})
	isBit := func(n frontend.Variable) frontend.Variable {
		return isBitTable.Lookup(n)[0]
	}
	var isSymbTable *logderivlookup.Table
	if settings.Symbol != 0 && settings.Symbol != 1 {
		isSymbTable = newTable(api, 256, []intPair{{int(settings.Symbol), 1}})
	}
	isSymb := func(n frontend.Variable) frontend.Variable {
		switch settings.Symbol {
		case 0:
			return api.Mul(isBit(n), api.Sub(1, n)) // TODO Ascertain this is actually more efficient than just having another table
		case 1:
			return api.Mul(isBit(n), n)
		default:
			return isSymbTable.Lookup(n)[0]
		}
	}

	inputExhausted := frontend.Variable(0)

	dTable := newOutputTable(api, settings)
	readD := func(i frontend.Variable) frontend.Variable { // reading from the decompressed stream as we write to it
		return dTable.Lookup(api.Sub(i, brLengthRange))[0]
	}

	cTable := newInputTable(api, c)
	readC := func(start frontend.Variable, length int) []frontend.Variable {
		indices := make([]frontend.Variable, length)
		for i := 0; i < length; i++ {
			indices[i] = api.Add(start, i)
		}
		return cTable.Lookup(indices...)
	}

	readBackRef := func(i frontend.Variable) (offset, length frontend.Variable) { // need some lookahead in case of a backref
		i = api.Add(i, 1)
		offset = api.Add(readLittleEndian(api, readC(i, int(settings.NbBytesAddress))), 1)
		i = api.Add(i, settings.NbBytesAddress)
		length = api.Add(readLittleEndian(api, readC(i, int(settings.NbBytesLength))), 1)
		return
	}
}

func ite(api frontend.API, c, if0, if1 frontend.Variable) frontend.Variable {
	res := api.Mul(if0, 1) // just a copy, refer to MulAcc docs
	return api.MulAcc(res, c,
		api.Sub(if1, if0),
	)
}

// readLittleEndian may change bytes due to its use in MulAcc
func readLittleEndian(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	res := frontend.Variable(0)
	for i := len(bytes) - 1; i >= 0; i-- {
		res = api.MulAcc(bytes[i], res, 256)
	}
	return api.Add(res, 1)
}

func newInputTable(api frontend.API, in []frontend.Variable) *logderivlookup.Table {
	res := logderivlookup.New(api)
	for _, i := range in {
		res.Insert(i)
	}
	return res
}

func newOutputTable(api frontend.API, settings Settings) *logderivlookup.Table {
	res := logderivlookup.New(api)
	for i := 1 << (settings.NbBytesLength * 8); i > 0; i-- {
		res.Insert(settings.Symbol)
	}
	return res
}

type intPair struct{ k, v int }

// the default value is 0
func newTable(api frontend.API, bound int, vals []intPair) *logderivlookup.Table {
	sort.Slice(vals, func(i, j int) bool { return vals[i].k < vals[j].k })
	res := logderivlookup.New(api)
	for i := 0; i < bound; i++ {
		if len(vals) > 0 && vals[0].k == i {
			res.Insert(vals[0].v)
			vals = vals[1:]
		} else {
			res.Insert(0)
		}
	}
	return res
}
