package lzss_v1

import (
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
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
	isBit := func(n frontend.Variable) frontend.Variable { // TODO Replace uses of this
		return api.IsZero(api.MulAcc(api.Neg(n), n, n))
	}

	dTable := newOutputTable(api, settings)
	readD := func(i frontend.Variable) frontend.Variable { // reading from the decompressed stream as we write to it
		_i := api.Add(i, brLengthRange)
		return dTable.Lookup(_i)[0]
	}

	cTable := newInputTable(api, c)
	readC := func(start frontend.Variable, length int) []frontend.Variable {
		indices := make([]frontend.Variable, length)
		for i := 0; i < length; i++ {
			indices[i] = api.Add(start, i)
		}
		return cTable.Lookup(indices...)
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

		backRef := readC(inI, settings.BackRefSettings.NbBytes())

		curr := backRef[0]
		isSymb := api.IsZero(api.Sub(curr, int(settings.Symbol)))
		isEof := api.IsZero(api.Sub(curr, SnarkEofSymbol))
		brOffset, brLen := readBackRef(backRef[1:])

		copying = api.Mul(copying, api.Sub(1, copyLen01))                       // still copying from previous iterations TODO MulAcc
		copyI = api.Select(copying, api.Add(copyI, 1), api.Sub(outI, brOffset)) // TODO replace with copyI = outI + brOffset
		copyLen = api.Select(copying, api.Sub(copyLen, 1), api.Mul(isSymb, brLen))
		copyLen01 = isBit(copyLen)
		copying = api.Add(api.Sub(1, copyLen01), api.Mul(copyLen01, copyLen)) // either from previous iterations or starting a new copy TODO MulAcc
		copyI = api.Select(copying, copyI, -1)                                // to keep it in range in case we read nonsensical backref data when not copying TODO may need to also multiply by (1-inputExhausted) to avoid reading past the end of the input, or else keep inI = 0 when inputExhausted
		// TODO See if copyI = (copyI+1)*copying - 1 is more efficient. It could possibly become a single Plonk constraint if written as Add(MulAcc(copying*1, copying, copyI),-1)

		toCopy := readD(copyI)

		// write to output

		d[outI] = api.MulAcc(curr, copying, toCopy) // TODO full-on ite for the case where symb != 0
		// WARNING: curr modified by MulAcc
		dTable.Insert(d[outI])

		func() { // EOF Logic
			inIDelta := api.Select(copying,
				api.Select(copyLen01, 1+int(settings.NbBytesAddress+settings.NbBytesLength), 0), // if copying is done, advance by the backref length. Else stay put.
				1, // if not copying, advance by 1
			)
			inI = api.MulAcc(inI, inIDelta, api.Sub(1, isEof))             // if eof, stay put
			dLength = api.Add(dLength, api.Mul(api.Sub(isEof, eof), outI)) // if eof, don't advance dLength
			eof = isEof
		}()
	}

	return
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
