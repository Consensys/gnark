package lzss_v1

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

/*
// Decompress a widget that performs DecompressPureGo in a circuit.
// For now c are bytes. TODO: Pack it
// d must be of length cMax * len(c) where cMax is an upper bound on the expected compression ratio
func Decompress(api frontend.API, c []frontend.Variable, d []frontend.Variable, settings Settings) (length frontend.Variable, err error) {

	if settings.BackRefSettings.NbBytesLength != 1 {
		return nil, errors.New("currently only byte-long backrefs supported")
	}
	if settings.BackRefSettings.Symbol != 0 {
		return nil, errors.New("currently only 0 is supported as the backreference signifier")
	}

	var isSymbT *logderivlookup.Table
	if settings.Symbol != 0 {
		isSymbT = newByteIs(api, settings.Symbol)
	}

	isBit := newIsBit(api, 256)

	/*isOne := func(i frontend.Variable) frontend.Variable {
		return api.Mul(isBit.Lookup(i)[0], i)
	}*/ /*

	isZero := func(i frontend.Variable) frontend.Variable {
		b := isBit.Lookup(i)[0]
		return api.MulAcc(b, b, api.Neg(i)) // b - bi = b(1-i)
	}

	isSymb := func(i frontend.Variable) frontend.Variable {
		if settings.Symbol == 0 {
			return isZero(i)
		} else {
			return isSymbT.Lookup(i)[0]
		}
	}

	out := newOutputTable(api, settings)
	_in := newInputTable(api, c)
	brLengthRange := 1 << (settings.NbBytesLength * 8)
	//brAddrRange := 1 << (settings.NbBytesAddress * 8)
	readD := func(i frontend.Variable) frontend.Variable { // reading from the decompressed stream as we write to it
		return out.Lookup(api.Add(i, brLengthRange))[0]
	}
	readBackRef := func(i frontend.Variable) (offset, length frontend.Variable) { // need some lookahead in case of a backref
		nbLookahead := settings.NbBytesAddress + settings.NbBytesLength
		indices := make([]frontend.Variable, nbLookahead)
		for j := range indices {
			indices[j] = api.Add(i, j+1)
		}
		vals := _in.Lookup(indices...)
		offset = readLittleEndian(api, vals[:settings.NbBytesAddress])
		length = readLittleEndian(api, vals[settings.NbBytesAddress:])
		return
	}

	i := frontend.Variable(0)
	copyI := frontend.Variable(0)
	copyLenRemaining := frontend.Variable(0)
	//copying := isSymb(c[0])

	for range d {
		// if we use compressed-offsets, we could combine the reads for toCopy and curr, getting rid of a very expensive read
		// (from a table being written to)

		// read a byte to copy
		copyLen01 := isBit.Lookup(copyLenRemaining)[0]
		copying := api.Sub(1, api.MulAcc(api.Mul(1, copyLen01), copyLen01, api.Neg(copyLenRemaining))) // copying = (copyLengthRemaining != 0)
		copyingLastRound := api.Mul(copying, copyLen01)
		toCopy := readD(copyI)

		// read current input
		curr := _in.Lookup(i)[0]
		currIsSymb := isSymb(curr)
		brOffset, brLen := readBackRef(i)

		// write output
		// WARNING THIS MODIFIES curr
		temp := api.MulAcc(curr, copying, toCopy) // TODO don't assume symb = 0
		out.Insert(temp)

		// update state variables
		copyLenRemaining = ite(api, copying, 0, api.Sub(copyLenRemaining, 1))
		//i = api.MulAcc(i, copyingLastRound)
	}
}*/

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

func newByteIs(api frontend.API, symb byte) *logderivlookup.Table {
	res := logderivlookup.New(api)
	s := int(symb)
	for i := 0; i < 256; i++ {
		if i == s {
			res.Insert(1)
		} else {
			res.Insert(0)
		}
	}
	return res
}

func newIsBit(api frontend.API, bound int) *logderivlookup.Table {
	res := logderivlookup.New(api)
	res.Insert(1)
	res.Insert(1)
	for i := 2; i < bound; i++ {
		res.Insert(0)
	}
	return res
}
