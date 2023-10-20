package lzss_v1

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// Decompress implements the decompression logic implemented in both DecompressPureGo and decompressStateMachine, pretty much identical to the latter.
// TODO Add input correctness checks
func Decompress(api frontend.API, c []frontend.Variable, d []frontend.Variable, cLength frontend.Variable, settings Settings) (dLength frontend.Variable, err error) {
	if settings.BackRefSettings.NbBytesLength != 1 {
		return -1, errors.New("currently only backrefs of length up to 256 supported")
	}

	brLengthRange := 1 << (settings.NbBytesLength * 8)

	isBit := func(n frontend.Variable) frontend.Variable { // TODO Replace uses of this
		return api.IsZero(api.MulAcc(api.Neg(n), n, n))
	}

	dTable := newOutputTable(api, settings)

	cTable := newInputTable(api, c)
	for i := 0; i <= int(settings.NbBytesAddress+settings.NbBytesLength); i++ { // pad it a little
		cTable.Insert(0)
	}
	readC := func(start frontend.Variable, length int) []frontend.Variable {
		indices := make([]frontend.Variable, length)
		for i := 0; i < length; i++ {
			indices[i] = api.Add(start, i)
		}

		return cTable.Lookup(indices...)
	}

	brOffsetTable := logderivlookup.New(api)
	for i := range c {
		if i+int(settings.NbBytesAddress) < len(c) {
			brOffsetTable.Insert(readLittleEndian(api, c[i+1:i+1+int(settings.NbBytesAddress)]))
		} else {
			brOffsetTable.Insert(0)
		}
	}

	inI := frontend.Variable(0)
	copyLen := frontend.Variable(0) // remaining length of the current copy
	copyLen01 := frontend.Variable(1)
	eof := frontend.Variable(0)
	dLength = 0

	for outI := range d {

		if outI%2000 == 0 {
			fmt.Println("compilation at", outI, "out of", len(d), ";", outI*100/len(d), "%")
		}

		curr := readC(inI, 1)[0]
		brLen := api.Add(readLittleEndian(api, readC(api.Add(inI, 1+settings.NbBytesAddress), int(settings.NbBytesLength))), 1)
		brOffsetMinusOne := brOffsetTable.Lookup(inI)[0]

		isSymb := api.IsZero(curr)

		// copyLen01 == 1 iff still copying from previous iterations
		copyI := api.Sub(outI+brLengthRange-1, brOffsetMinusOne)
		copyLen = api.Select(copyLen01, api.Mul(isSymb, brLen), api.Sub(copyLen, 1))
		copyLen01 = isBit(copyLen)
		// copying = copyLen01 ? copyLen==1 : 1			either from previous iterations or starting a new copy
		// copying = copyLen01 ? copyLen : 1
		copying := api.(_scs).NewCombination(copyLen01, copyLen, -1, 0, 1, 1)

		// TODO Remove this if populating the entire negative address space
		copyI = api.Select(copying, copyI, 0) // to keep it in range in case we read nonsensical backref data when not copying

		toCopy := dTable.Lookup(copyI)[0]

		// write to output
		d[outI] = api.MulAcc(curr, copying, toCopy)
		// WARNING: curr modified by MulAcc
		dTable.Insert(d[outI])

		func() { // EOF Logic

			// inIDelta = copying ? (copyLen01? backRefCodeLen: 0) : 1
			// inIDelta = - copying + copying*copyLen01*(backrefCodeLen) + 1
			inIDelta := api.(_scs).NewCombination(copying, copyLen01, -1, 0, 1+int(settings.NbBytesAddress+settings.NbBytesLength), 1)

			// TODO Try removing this check and requiring the user to pad the input with nonzeros
			// TODO Change inner to mulacc once https://github.com/Consensys/gnark/pull/859 is merged
			// inI = inI + inIDelta * (1 - eof)
			if eof == 0 {
				inI = api.Add(inI, inIDelta)
			} else {
				inI = api.Add(inI, api.(_scs).NewCombination(inIDelta, eof, 1, 0, -1, 0)) // if eof, stay put
			}

			eofNow := api.IsZero(api.Sub(inI, cLength))

			dLength = api.Add(dLength, api.Mul(api.Sub(eofNow, eof), outI+1)) // if eof, don't advance dLength
			eof = eofNow
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
		res.Insert(0)
	}
	return res
}

type _scs interface {
	NewCombination(a, b frontend.Variable, aCoeff, bCoeff, mCoeff, oCoeff int) frontend.Variable
}
