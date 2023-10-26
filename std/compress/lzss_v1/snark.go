package lzss_v1

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// Decompress implements the decompression logic implemented in both DecompressPureGo and decompressStateMachine, pretty much identical to the latter.
// TODO Add input correctness checks
func Decompress(api frontend.API, c []frontend.Variable, d []frontend.Variable, cLength frontend.Variable, settings Settings) (dLength frontend.Variable, err error) {

	isBit := func(n frontend.Variable) frontend.Variable { // TODO Replace uses of this
		return api.IsZero(api.MulAcc(api.Neg(n), n, n))
	}

	negTableSize := 1 << settings.NbBitsLength

	dTable := newOutputTable(api, settings)
	currTable, brOffsetTable, brLenTable := createReadTables(api, c, settings)

	inI := frontend.Variable(0)
	copyLen := frontend.Variable(0) // remaining length of the current copy
	copyLen01 := frontend.Variable(1)
	eof := frontend.Variable(0)
	dLength = 0

	for outI := range d {

		if outI%2000 == 0 {
			fmt.Println("compilation at", outI, "out of", len(d), ";", outI*100/len(d), "%")
		}

		curr := currTable.Lookup(inI)[0]
		brLen := api.Add(1, brLenTable.Lookup(inI)[0]) // TODO Get rid of the +1
		brOffsetMinusOne := brOffsetTable.Lookup(inI)[0]

		isSymb := api.IsZero(curr)

		// copyLen01 == 1 iff still copying from previous iterations
		copyI := api.Sub(outI+negTableSize-1, brOffsetMinusOne)
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
			inIDelta := api.(_scs).NewCombination(copying, copyLen01, -1, 0, 1+int(settings.NbBitsAddress+settings.NbBitsLength), 1)

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

func createReadTable(api frontend.API, c []frontend.Variable, nbBitsPerWord, nbWordsPerEntry, offset int) *logderivlookup.Table {
	res := logderivlookup.New(api)
	for i := range c {
		entry := frontend.Variable(0)
		if i+offset+nbWordsPerEntry <= len(c) {
			coeff := frontend.Variable(1)
			for j := 0; j < nbWordsPerEntry; j++ {
				entry = api.Add(entry, api.Mul(coeff, c[i+offset+j]))
				coeff = api.Mul(coeff, 1<<nbBitsPerWord)
			}
		}
		res.Insert(entry)
	}
	return res
}

func createReadTables(api frontend.API, c []frontend.Variable, settings Settings) (currTable, brOffsetTable, brLenTable *logderivlookup.Table) {

	nbBitsPerWord := settings.WordNbBits()

	offset := 0
	length := 8 / nbBitsPerWord
	currTable = createReadTable(api, c, nbBitsPerWord, length, offset)

	offset += length
	length = int(settings.NbBitsAddress) / nbBitsPerWord
	brOffsetTable = createReadTable(api, c, nbBitsPerWord, length, offset)

	offset += length
	length = int(settings.NbBitsLength) / nbBitsPerWord
	brLenTable = createReadTable(api, c, nbBitsPerWord, length, offset)

	return
}

func newOutputTable(api frontend.API, settings Settings) *logderivlookup.Table {
	res := logderivlookup.New(api)
	for i := 1 << settings.NbBitsLength; i > 0; i-- {
		res.Insert(0)
	}
	return res
}

type _scs interface {
	NewCombination(a, b frontend.Variable, aCoeff, bCoeff, mCoeff, oCoeff int) frontend.Variable
}
