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

	/*isZero := func(n frontend.Variable, nIsBit ...frontend.Variable) frontend.Variable {
		var bit frontend.Variable
		switch len(nIsBit) {
		case 0:
			bit = isBit(n)
		case 1:
			bit = nIsBit[0]
		default:
			panic("at most one isBit allowed")
		}
		return api.Mul(bit, api.Sub(1, n)) // TODO MulAcc
	}

	isOne := func(n frontend.Variable, nIsBit ...frontend.Variable) frontend.Variable {
		var bit frontend.Variable
		switch len(nIsBit) {
		case 0:
			bit = isBit(n)
		case 1:
			bit = nIsBit[0]
		default:
			panic("at most one isBit allowed")
		}
		return api.Mul(bit, n)
	}*/

	inI := frontend.Variable(0)
	copyI := frontend.Variable(0)
	copyLen := frontend.Variable(0) // remaining length of the current copy
	copyLen01 := frontend.Variable(1)
	copying := frontend.Variable(0)

	for outI := range d {

		curr := readC(inI, 1)[0]

		currIsSymb := isSymb(curr)
		brOffset, brLen := readBackRef(inI)

		copying = api.Mul(copying, api.Sub(1, copyLen01)) // still copying from previous iterations TODO MulAcc
		copyI = ite(api, copying, api.Sub(outI, brOffset), api.Add(copyI, 1))
		copyLen = ite(api, copying, api.Mul(currIsSymb, brLen), api.Sub(copyLen, 1))
		copyLen01 = isBit(copyLen)
		copying = api.Add(api.Sub(1, copyLen01), api.Mul(copyLen01, copyLen)) // either from previous iterations or starting a new copy TODO MulAcc
		copyI = api.Mul(copyI, copying)                                       // to keep it in range in case we read nonsensical backref data when not copying TODO may need to also multiply by (1-inputExhausted) to avoid reading past the end of the input, or else keep inI = 0 when inputExhausted
		toCopy := readD(copyI)

		// write to output
		// TODO MulAcc
		d[outI] = api.Add(api.Mul(copying, toCopy), curr) // TODO full-on ite for the case where symb != 0

		inI = api.Add(inI, ite(api, copying, 1,
			ite(api, copyLen01, 0, 1+int(settings.NbBytesAddress+settings.NbBytesLength)),
		))
		inputRemaining := api.Sub(cLength, inI)
		// TODO isBit won't work because the table is small. Use a special EOF symbol (-1 or something) in the input
		inputJustExhausted := api.Mul(api.Sub(1, inputRemaining), isBit(inputRemaining)) // TODO MulAcc
		inputExhausted = api.Add(inputExhausted, inputJustExhausted)                     // TODO Obviate this by forcing inI = 0 when inputExhausted
		inI = ite(api, inputExhausted, inI, cLength)

		dLength = api.Add(dLength, api.Mul(inputJustExhausted, outI+1))
	}

	return
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
