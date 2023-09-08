package lzss_v1

import (
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"sort"
)

const SnarkEofSymbol = 256

// Decompress implements the decompression logic implemented in both DecompressPureGo and decompressStateMachine, pretty much identical to the latter.
// c must be marked with an EOF symbol and a few (NbBytesLength+NbBytesAddress) zeros at the end.
// TODO Add input correctness checks
func Decompress(api frontend.API, c []frontend.Variable, d []frontend.Variable, settings Settings) (dLength frontend.Variable, err error) {
	if settings.BackRefSettings.NbBytesLength != 1 {
		return -1, errors.New("currently only backrefs of length up to 256 supported")
	}
	if settings.BackRefSettings.Symbol != 0 {
		return -1, errors.New("currently only 0 is supported as the backreference signifier")
	}

	// add EOF to one of the tables parasitically
	brLengthRange := 1 << (settings.NbBytesLength * 8)
	tableEntries := []intPair{{0, 1}, {1, 1}}
	if settings.Symbol == 0 || settings.Symbol == 1 {
		tableEntries = append(tableEntries, intPair{brLengthRange + 1, 1})
	}
	isBitTable := newTable(api, brLengthRange+2, tableEntries)
	isBit := func(n frontend.Variable) frontend.Variable {
		return isBitTable.Lookup(n)[0]
	}
	isSymbTable := newTable(api, SnarkEofSymbol+1, []intPair{{int(settings.Symbol), 1}, {SnarkEofSymbol, 1}})
	isSymb := func(n frontend.Variable) frontend.Variable {
		return isSymbTable.Lookup(n)[0]
	}
	eofCoeff := api.Inverse(SnarkEofSymbol - int(settings.Symbol)) // cache for faster compilation
	isEof := func(n frontend.Variable, nIsSymb ...frontend.Variable) frontend.Variable {
		var symb frontend.Variable
		switch len(nIsSymb) {
		case 0:
			symb = isSymb(n)
		case 1:
			symb = nIsSymb[0]
		default:
			panic("at most one isSymb allowed")
		}

		return api.Mul(eofCoeff,
			api.MulAcc(
				api.Mul(symb, -int(settings.Symbol)),
				symb, n,
			))
	}

	dTable := newOutputTable(api, settings)
	readD := func(i frontend.Variable) frontend.Variable { // reading from the decompressed stream as we write to it
		_i := api.Add(i, brLengthRange)
		res := dTable.Lookup(_i)[0]
		api.Println("readD index", i, "real index", _i, "value", res)
		return res
	}

	cTable := newInputTable(api, c)
	readC := func(start frontend.Variable, length int) []frontend.Variable {
		indices := make([]frontend.Variable, length)
		for i := 0; i < length; i++ {
			indices[i] = api.Add(start, i)
		}
		log := append([]frontend.Variable{"readC indices"}, indices...)
		log = append(log, "values")
		res := cTable.Lookup(indices...)
		log = append(log, res...)
		api.Println(log...)
		return res
	}

	readBackRef := func(c []frontend.Variable) (offset, length frontend.Variable) { // need some lookahead in case of a backref
		offset = api.Add(readLittleEndian(api, c[:settings.NbBytesAddress]), 1)
		length = api.Add(readLittleEndian(api, c[settings.NbBytesAddress:]), 1)
		return
	}

	inI := frontend.Variable(0)
	copyI := frontend.Variable(0)
	copyLen := frontend.Variable(0) // remaining length of the current copy
	copyLen01 := frontend.Variable(1)
	copying := frontend.Variable(0)
	eof := frontend.Variable(0)
	dLength = 0

	for outI := range d {

		api.Println("outI, inI", outI, inI, "prior copyLen", copyLen)
		backRef := readC(inI, settings.BackRefSettings.NbBytes())

		curr := backRef[0]
		currIsSymb := isSymb(curr)
		currIsEof := isEof(curr, currIsSymb)
		api.Println("curr, isSymb, isEof", curr, currIsSymb, currIsEof)
		brOffset, brLen := readBackRef(backRef[1:])
		api.Println("backref", brOffset, ":", brLen)

		copying = api.Mul(copying, api.Sub(1, copyLen01)) // still copying from previous iterations TODO MulAcc
		api.Println("prior copying", copying)
		copyI = ite(api, copying, api.Sub(outI, brOffset), api.Add(copyI, 1))
		if outI == 1 {
			api.Println("currIsSymb*brLen", api.Mul(currIsSymb, brLen))
		}
		copyLen = ite(api, copying, api.Mul(currIsSymb, brLen), api.Sub(copyLen, 1))
		api.Println("current copyLen", copyLen)
		copyLen01 = isBit(copyLen)
		copying = api.Add(api.Sub(1, copyLen01), api.Mul(copyLen01, copyLen)) // either from previous iterations or starting a new copy TODO MulAcc
		copyI = api.Mul(copyI, copying)                                       // to keep it in range in case we read nonsensical backref data when not copying TODO may need to also multiply by (1-inputExhausted) to avoid reading past the end of the input, or else keep inI = 0 when inputExhausted
		toCopy := readD(copyI)

		// write to output
		// TODO MulAcc

		d[outI] = api.MulAcc(curr, copying, toCopy) // TODO full-on ite for the case where symb != 0
		dTable.Insert(d[outI])
		api.Println("writing", d[outI])
		// WARNING: curr modified by MulAcc

		inIDelta := ite(api, copying, 1, // if not copying, advance by 1
			ite(api, copyLen01, 0, 1+int(settings.NbBytesAddress+settings.NbBytesLength)), // if copying is done, advance by the backref length. Else stay put.
		)
		inI = api.MulAcc(inI, inIDelta, api.Sub(1, currIsEof))             // if eof, stay put
		dLength = api.Add(dLength, api.Mul(api.Sub(currIsEof, eof), outI)) // if eof, don't advance dLength
		eof = currIsEof
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
	return res
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
