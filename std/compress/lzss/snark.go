package lzss

import (
	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// Decompress decompresses c into d using dict as the dictionary
// It returns the length of d as a frontend.Variable
func Decompress(api frontend.API, c []frontend.Variable, cLength frontend.Variable, d []frontend.Variable, dict []byte, level lzss.Level) (dLength frontend.Variable, err error) {

	wordNbBits := int(level)

	// ensure input is in range
	checkInputRange(api, c, wordNbBits)

	// init the dictionary and backref types
	dict = lzss.AugmentDict(dict)
	shortBackRefType, longBackRefType, dictBackRefType := lzss.InitBackRefTypes(len(dict), level)

	shortBrNbWords := int(shortBackRefType.NbBitsBackRef) / wordNbBits
	longBrNbWords := int(longBackRefType.NbBitsBackRef) / wordNbBits
	dictBrNbWords := int(dictBackRefType.NbBitsBackRef) / wordNbBits
	byteNbWords := 8 / wordNbBits

	api.AssertIsEqual(compress.ReadNum(api, c, byteNbWords, wordNbBits), 0) // compressor version TODO @tabaie @gbotrel Handle this outside the circuit instead?
	fileCompressionMode := compress.ReadNum(api, c[byteNbWords:], byteNbWords, wordNbBits)
	api.AssertIsEqual(api.Mul(fileCompressionMode, fileCompressionMode), api.Mul(fileCompressionMode, wordNbBits)) // if fcm!=0, then fcm=wordNbBits
	decompressionNotBypassed := api.Sub(1, api.IsZero(fileCompressionMode))

	c = c[2*byteNbWords:]
	cLength = api.Sub(cLength, 2*byteNbWords)

	outTable := logderivlookup.New(api)
	for i := range dict {
		outTable.Insert(dict[i])
	}

	// formatted input
	bytes := combineIntoBytes(api, c, wordNbBits)
	bytesTable := sliceToTable(api, bytes)
	bytesTable.Insert(0) // just because we use this table for looking up backref lengths as well
	addrTable := initAddrTable(api, bytes, c, wordNbBits, []lzss.BackrefType{shortBackRefType, longBackRefType, dictBackRefType})

	// state variables
	inI := frontend.Variable(0)
	copyLen := frontend.Variable(0) // remaining length of the current copy
	copyLen01 := frontend.Variable(1)
	eof := frontend.Variable(0)
	dLength = 0

	for outI := range d {

		curr := bytesTable.Lookup(inI)[0]

		currMinusLong := api.Sub(api.Mul(curr, decompressionNotBypassed), lzss.SymbolLong) // if bypassing decompression, currIndicatesXX = 0
		currIndicatesLongBr := api.IsZero(currMinusLong)
		currIndicatesShortBr := api.IsZero(api.Sub(currMinusLong, lzss.SymbolShort-lzss.SymbolLong))
		currIndicatesDr := api.IsZero(api.Sub(currMinusLong, lzss.SymbolDict-lzss.SymbolLong))
		currIndicatesBr := api.Add(currIndicatesLongBr, currIndicatesShortBr)
		currIndicatesCp := api.Add(currIndicatesBr, currIndicatesDr)

		//currIndicatedCpLen := api.Add(1, lenTable.Lookup(inI)[0]) // TODO Get rid of the +1
		currIndicatedCpLen := api.Add(1, bytesTable.Lookup(api.Add(inI, byteNbWords))[0]) // TODO Get rid of the +1
		currIndicatedCpAddr := addrTable.Lookup(inI)[0]

		copyLen = api.Select(copyLen01, api.Mul(currIndicatesCp, currIndicatedCpLen), api.Sub(copyLen, 1))
		copyLen01 = api.IsZero(api.MulAcc(api.Neg(copyLen), copyLen, copyLen))

		// copying = copyLen01 ? copyLen==1 : 1			either from previous iterations or starting a new copy
		// copying = copyLen01 ? copyLen : 1
		copying := evaluatePlonkExpression(api, copyLen01, copyLen, -1, 0, 1, 1)

		copyAddr := api.Mul(api.Sub(outI+len(dict)-1, currIndicatedCpAddr), currIndicatesBr)
		dictCopyAddr := api.Add(currIndicatedCpAddr, api.Sub(currIndicatedCpLen, copyLen))
		copyAddr = api.MulAcc(copyAddr, currIndicatesDr, dictCopyAddr)
		toCopy := outTable.Lookup(copyAddr)[0]

		// write to output
		d[outI] = api.Select(copying, toCopy, curr)
		// WARNING: curr modified by MulAcc
		outTable.Insert(d[outI])

		// EOF Logic
		inIDelta := api.Add(api.Mul(currIndicatesLongBr, longBrNbWords), api.Mul(currIndicatesShortBr, shortBrNbWords))
		inIDelta = api.MulAcc(inIDelta, currIndicatesDr, dictBrNbWords)
		inIDelta = api.Select(copying, api.Mul(inIDelta, copyLen01), byteNbWords)

		// TODO Try removing this check and requiring the user to pad the input with nonzeros
		// TODO Change inner to mulacc once https://github.com/Consensys/gnark/pull/859 is merged
		// inI = inI + inIDelta * (1 - eof)
		if eof == 0 {
			inI = api.Add(inI, inIDelta)
		} else {
			inI = api.Add(inI, evaluatePlonkExpression(api, inIDelta, eof, 1, 0, -1, 0)) // if eof, stay put
		}

		eofNow := api.IsZero(api.Sub(inI, cLength))

		dLength = api.Add(dLength, api.Mul(api.Sub(eofNow, eof), outI+1)) // if eof, don't advance dLength
		eof = eofNow

	}
	return dLength, nil
}

func checkInputRange(api frontend.API, c []frontend.Variable, wordNbBits int) {
	if wordNbBits > 2 {
		cRangeTable := logderivlookup.New(api)
		for i := 0; i < 1<<wordNbBits; i++ {
			cRangeTable.Insert(0)
		}
		_ = cRangeTable.Lookup(c...)
		return
	}
	var check func(frontend.Variable)
	switch wordNbBits {
	case 1:
		check = api.AssertIsBoolean
	case 2:
		check = api.AssertIsCrumb
	default:
		panic("wordNbBits must be positive")
	}
	for i := range c {
		check(c[i])
	}
}

func sliceToTable(api frontend.API, slice []frontend.Variable) *logderivlookup.Table {
	table := logderivlookup.New(api)
	for i := range slice {
		table.Insert(slice[i])
	}
	return table
}

func combineIntoBytes(api frontend.API, c []frontend.Variable, wordNbBits int) []frontend.Variable {
	reader := compress.NewNumReader(api, c, 8, wordNbBits)
	res := make([]frontend.Variable, len(c))
	for i := range res {
		res[i] = reader.Next()
	}
	return res
}

func initAddrTable(api frontend.API, bytes, c []frontend.Variable, wordNbBits int, backrefs []lzss.BackrefType) *logderivlookup.Table {
	for i := range backrefs {
		if backrefs[i].NbBitsLength != backrefs[0].NbBitsLength {
			panic("all backref types must have the same length size")
		}
	}
	readers := make([]*compress.NumReader, len(backrefs))
	delimAndLenNbWords := int(8+backrefs[0].NbBitsLength) / wordNbBits
	for i := range backrefs {
		var readerC []frontend.Variable
		if len(c) >= delimAndLenNbWords {
			readerC = c[delimAndLenNbWords:]
		}

		readers[i] = compress.NewNumReader(api, readerC, int(backrefs[i].NbBitsAddress), wordNbBits)
	}

	res := logderivlookup.New(api)

	for i := range c {
		entry := frontend.Variable(0)
		for j := range backrefs {
			isSymb := api.IsZero(api.Sub(bytes[i], backrefs[j].Delimiter))
			entry = api.MulAcc(entry, isSymb, readers[j].Next())
		}
		res.Insert(entry)
	}

	return res
}

func evaluatePlonkExpression(api frontend.API, a, b frontend.Variable, aCoeff, bCoeff, mCoeff, constant int) frontend.Variable {
	if plonkAPI, ok := api.(frontend.PlonkAPI); ok {
		return plonkAPI.EvaluatePlonkExpression(a, b, aCoeff, bCoeff, mCoeff, constant)
	}
	return api.Add(api.Mul(a, aCoeff), api.Mul(b, bCoeff), api.Mul(mCoeff, a, b), constant)
}
