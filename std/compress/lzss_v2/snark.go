package lzss_v2

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// bite size of c needs to be the greatest common denominator of all backref types and 8
// d consists of bytes
func Decompress(api frontend.API, c []frontend.Variable, cLength frontend.Variable, d []frontend.Variable, dict []byte) (dLength frontend.Variable, err error) {

	dict = augmentDict(dict)
	dictBackRefType := initDictBackref(dict) // only using the bit len

	wordLen := compress.Gcd(8,
		longBackRefType.nbBitsAddress, longBackRefType.nbBitsLength,
		shortBackRefType.nbBitsAddress, shortBackRefType.nbBitsLength,
		dictBackRefType.nbBitsAddress, dictBackRefType.nbBitsLength)

	longBrNbWords := longBackRefType.nbBitsBackRef / wordLen
	shortBrNbWords := shortBackRefType.nbBitsBackRef / wordLen
	dictBrNbWords := dictBackRefType.nbBitsBackRef / wordLen
	byteNbWords := 8 / wordLen

	// assert that c are within range
	cRangeTable := logderivlookup.New(api)
	for i := 0; i < 1<<wordLen; i++ {
		cRangeTable.Insert(0)
	}
	_ = cRangeTable.Lookup(c...)

	outTable := logderivlookup.New(api)
	for i := range dict {
		outTable.Insert(dict[i])
	}

	// formatted input
	bytes := combineIntoBytes(api, c, int(wordLen))
	bytesTable := sliceToTable(api, bytes)
	bytesTable.Insert(0) // just because we use this table for looking up backref lengths as well
	//lenTable := createLengthTables(api, c, int(wordLen), []backrefType{longBackRefType, shortBackRefType, dictBackRefType})
	addrTable := initAddrTable(api, bytes, c, int(wordLen), []backrefType{longBackRefType, shortBackRefType, dictBackRefType})

	// state variables
	inI := frontend.Variable(0)
	copyLen := frontend.Variable(0) // remaining length of the current copy
	copyLen01 := frontend.Variable(1)
	eof := frontend.Variable(0)
	dLength = 0

	for outI := range d {

		curr := bytesTable.Lookup(inI)[0]

		currIndicatesLongBr := api.IsZero(api.Sub(curr, longBackRefType.delimiter))
		currIndicatesShortBr := api.IsZero(api.Sub(curr, shortBackRefType.delimiter))
		currIndicatesDr := api.IsZero(api.Sub(curr, dictBackRefType.delimiter))
		currIndicatesBr := api.Add(currIndicatesLongBr, currIndicatesShortBr)
		currIndicatesCp := api.Add(currIndicatesBr, currIndicatesDr)

		//currIndicatedCpLen := api.Add(1, lenTable.Lookup(inI)[0]) // TODO Get rid of the +1
		currIndicatedCpLen := api.Add(1, bytesTable.Lookup(api.Add(inI, byteNbWords))[0]) // TODO Get rid of the +1
		currIndicatedCpAddr := addrTable.Lookup(inI)[0]

		copyLen = api.Select(copyLen01, api.Mul(currIndicatesCp, currIndicatedCpLen), api.Sub(copyLen, 1))
		copyLen01 = api.IsZero(api.MulAcc(api.Neg(copyLen), copyLen, copyLen))

		// copying = copyLen01 ? copyLen==1 : 1			either from previous iterations or starting a new copy
		// copying = copyLen01 ? copyLen : 1
		copying := api.(_scs).NewCombination(copyLen01, copyLen, -1, 0, 1, 1)

		copyAddr := api.Mul(api.Sub(outI+len(dict)-1, currIndicatedCpAddr), currIndicatesBr)
		dictCopyAddr := api.Add(currIndicatedCpAddr, api.Sub(currIndicatedCpLen, copyLen))
		copyAddr = api.MulAcc(copyAddr, currIndicatesDr, dictCopyAddr)
		toCopy := outTable.Lookup(copyAddr)[0]

		// write to output
		d[outI] = api.Select(copying, toCopy, curr)
		// WARNING: curr modified by MulAcc
		outTable.Insert(d[outI])

		func() { // EOF Logic

			inIDelta := api.Add(api.Mul(currIndicatesLongBr, longBrNbWords), api.Mul(currIndicatesShortBr, shortBrNbWords))
			inIDelta = api.MulAcc(inIDelta, currIndicatesDr, dictBrNbWords)
			inIDelta = api.Select(copying, api.Mul(inIDelta, copyLen01), byteNbWords)

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
	return dLength, nil
}

func sliceToTable(api frontend.API, slice []frontend.Variable) *logderivlookup.Table {
	table := logderivlookup.New(api)
	for i := range slice {
		table.Insert(slice[i])
	}
	return table
}

func combineIntoBytes(api frontend.API, c []frontend.Variable, wordNbBits int) []frontend.Variable {
	reader := newNumReader(api, c, 8, wordNbBits)
	res := make([]frontend.Variable, len(c))
	prevPct := -1
	for i := range res {
		pct := i * 100 / len(res)
		if pct != prevPct {
			prevPct = pct
			fmt.Println("bytes compilation at", pct, "%")
		}
		res[i] = reader.next()
	}
	return res
}

func initAddrTable(api frontend.API, bytes, c []frontend.Variable, wordNbBits int, backrefs []backrefType) *logderivlookup.Table {
	for i := range backrefs {
		if backrefs[i].nbBitsLength != backrefs[0].nbBitsLength {
			panic("all backref types must have the same length size")
		}
	}
	readers := make([]*numReader, len(backrefs))
	delimAndLenNbWords := int(8+backrefs[0].nbBitsLength) / wordNbBits
	for i := range backrefs {
		var readerC []frontend.Variable
		if len(c) >= delimAndLenNbWords {
			readerC = c[delimAndLenNbWords:]
		}

		readers[i] = newNumReader(api, readerC, int(backrefs[i].nbBitsAddress), wordNbBits)
	}

	res := logderivlookup.New(api)

	prevPct := -1
	for i := range c {
		pct := i * 100 / len(c)
		if pct != prevPct {
			prevPct = pct
			fmt.Println("addr table compilation at", pct, "%")
		}

		entry := frontend.Variable(0)
		for j := range backrefs {
			isSymb := api.IsZero(api.Sub(bytes[i], backrefs[j].delimiter))
			entry = api.MulAcc(entry, isSymb, readers[j].next())
		}
		res.Insert(entry)
	}

	return res
}

type numReader struct {
	api       frontend.API
	c         []frontend.Variable
	stepCoeff int
	nbWords   int
	nxt       frontend.Variable
}

func newNumReader(api frontend.API, c []frontend.Variable, numNbBits, wordNbBits int) *numReader {
	nbWords := numNbBits / wordNbBits
	stepCoeff := 1 << wordNbBits
	nxt := frontend.Variable(0)
	coeff := frontend.Variable(1)
	if len(c) >= nbWords {
		for i := 0; i < nbWords; i++ {
			nxt = api.MulAcc(nxt, coeff, c[i])
			coeff = api.Mul(coeff, stepCoeff)
		}
	}
	return &numReader{
		api:       api,
		c:         c,
		stepCoeff: stepCoeff,
		nxt:       nxt,
		nbWords:   nbWords,
	}
}

// next returns the next number in the sequence. returns 0 upon EOF
func (nr *numReader) next() frontend.Variable {
	res := nr.nxt
	if len(nr.c) <= nr.nbWords {
		nr.nxt = 0
		return res
	}
	lastSummand := frontend.Variable(0)
	if nr.nbWords > 0 {
		lastSummand = nr.c[nr.nbWords]
	}
	for i := 1; i < nr.nbWords; i++ { // TODO Cache stepCoeff^nbWords
		lastSummand = nr.api.Mul(lastSummand, nr.stepCoeff)
	}

	nr.nxt = nr.api.Add(nr.api.DivUnchecked(nr.api.Sub(res, nr.c[0]), nr.stepCoeff), lastSummand)

	nr.c = nr.c[1:]
	return res
}

type _scs interface {
	NewCombination(a, b frontend.Variable, aCoeff, bCoeff, mCoeff, oCoeff int) frontend.Variable
}
