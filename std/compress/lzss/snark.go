package lzss

import (
	"github.com/consensys/compress/lzss"
	hint "github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/internal"
	"github.com/consensys/gnark/std/compress/internal/plonk"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// TODO Provide option for c to be in sizes other than bytes

// Decompress decompresses c into d using dict as the dictionary
// which must come pre "augmented"
// it is on the caller to ensure that the dictionary is correct; in particular it must consist of bytes. Decompress does not check this.
// it is recommended to pack the dictionary using compress.Pack and take a MiMC checksum of it.
// d will consist of bytes
// It returns the length of d as a frontend.Variable; if the decompressed stream doesn't fit in d, dLength will be "-1"
func Decompress(api frontend.API, c []frontend.Variable, cLength frontend.Variable, d, dict []frontend.Variable) (dLength frontend.Variable, err error) {

	api.AssertIsLessOrEqual(cLength, len(c)) // sanity check

	// size-related "constants"
	shortBackRefType := lzss.NewShortBackrefType()
	dynamicBackRefType := lzss.NewDynamicBackrefType(len(dict), 0)

	// check header: version and compression level
	const (
		sizeHeader = 3
		version    = 1
	)
	api.AssertIsEqual(c[0], version/256)
	api.AssertIsEqual(c[1], version%256)
	decompressionBypassed := c[2]
	api.AssertIsBoolean(decompressionBypassed)

	// check that the input is in range and convert into small words
	rangeChecker := internal.NewRangeChecker(api)

	bytes := make([]frontend.Variable, len(c)-sizeHeader+1)
	copy(bytes, c[sizeHeader:])
	bytes[len(bytes)-1] = 0                                    // pad with a zero to avoid out of range errors
	c, bytes = rangeChecker.BreakUpBytesIntoWords(1, bytes...) // from this point on c is in bits
	cLength = api.Mul(api.Sub(cLength, sizeHeader), 8)         // one constraint; insignificant impact anyway

	// create a random-access table to be referenced
	outTable := logderivlookup.New(api)
	for i := range dict {
		outTable.Insert(dict[i])
	}

	// formatted input
	bytesTable := sliceToTable(api, bytes)

	addrTable := initAddrTable(api, bytes, c, shortBackRefType, dynamicBackRefType)

	// state variables
	inI := frontend.Variable(0)
	copyLen := frontend.Variable(0) // remaining length of the current copy
	copyLen01 := frontend.Variable(1)
	eof := frontend.Variable(0)
	dLength = -1 // if the following loop ends before hitting eof, we will get the "error" value -1 for dLength

	for outI := range d {

		curr := bytesTable.Lookup(inI)[0]

		dynamicBackRefType = lzss.NewDynamicBackrefType(len(dict), outI)
		// ASSUMPTION: 0 is not a backref indicator
		// TODO Make sure this is one constraint only
		currMinusShort := api.Add(api.MulAcc(api.Neg(curr), curr, decompressionBypassed), lzss.SymbolShort)
		// if bypassing decompression, currIndicatesXX = 0
		// ( - curr + bypassed * curr + symbolXX == 0 ) == currIndicatesXX
		currIndicatesShortBr := api.IsZero(currMinusShort)

		currMinusDyn := api.Add(api.MulAcc(api.Neg(curr), curr, decompressionBypassed), lzss.SymbolDynamic)
		currIndicatesDynBr := api.IsZero(currMinusDyn)

		currIndicatesBr := api.Add(currIndicatesShortBr, currIndicatesDynBr)

		currIndicatedBrLen := api.Add(1, bytesTable.Lookup(api.Add(inI, 8))[0]) // TODO Get rid of the +1
		currIndicatedBrAddr := addrTable.Lookup(inI)[0]

		copyLen = api.Select(copyLen01, api.Mul(currIndicatesBr, currIndicatedBrLen), api.Sub(copyLen, 1))
		copyLen01 = api.IsZero(api.MulAcc(api.Neg(copyLen), copyLen, copyLen)) // - copyLen + copyLen^2 == 0?

		// copying = copyLen01 ? copyLen==1 : 1			either from previous iterations or starting a new copy
		// copying = copyLen01 ? copyLen : 1
		copying := plonk.EvaluateExpression(api, copyLen01, copyLen, -1, 0, 1, 1)

		copyAddr := api.Mul(api.Sub(outI+len(dict)-1, currIndicatedBrAddr), currIndicatesBr) // if no backref, don't read to avoid out of range TODO for expected compression ratio > 8, move the "check" to initAddrTable
		toCopy := outTable.Lookup(copyAddr)[0]

		// write to output
		outVal := api.Select(copying, toCopy, curr)
		// TODO previously the last byte of the output kept getting repeated. That can be worked with. If there was a reason to save some 600K constraints in the zkEVM decompressor, take this out again
		d[outI] = plonk.EvaluateExpression(api, outVal, eof, 1, 0, -1, 0) // write zeros past eof
		// WARNING: curr modified by MulAcc
		outTable.Insert(d[outI])

		// advancing inI and EOF
		// advance by byte or backref length
		inIDelta := api.Add(8, api.Mul(currIndicatesDynBr, dynamicBackRefType.NbBitsLength-8), api.Mul(currIndicatesShortBr, shortBackRefType.NbBitsLength-8))
		// ... unless we're in the middle of a copy
		inIDelta = api.MulAcc(api.Mul(1, inIDelta), api.Neg(copying), inIDelta)

		// TODO Try removing this check and requiring the user to pad the input with nonzeros
		// TODO Change inner to mulacc once https://github.com/Consensys/gnark/pull/859 is merged
		// inI = inI + inIDelta * (1 - eof)
		if eof == 0 {
			inI = api.Add(inI, inIDelta)
		} else {
			inI = api.Add(inI, plonk.EvaluateExpression(api, inIDelta, eof, 1, 0, -1, 0)) // if eof, stay put
		}

		eofNow := rangeChecker.IsLessThan(8, api.Sub(cLength, inI)) // less than a byte left; meaning we are at the end of the input

		// if eof, don't advance dLength
		// if eof was JUST hit, dLength += outI + 2; so dLength = -1 + outI + 2 = outI + 1 which is the current output length
		dLength = api.Add(dLength, api.Mul(api.Sub(eofNow, eof), outI+2))
		eof = eofNow

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

func initAddrTable(api frontend.API, bytes, c []frontend.Variable, backRefs ...lzss.BackrefType) *logderivlookup.Table {
	for i := range backRefs {
		if backRefs[i].NbBitsLength != backRefs[0].NbBitsLength {
			panic("all backref types must have the same length size")
		}
	}

	readers := make([]*compress.NumReader, len(backRefs))
	delimAndLenNbWords := int(8 + backRefs[0].NbBitsLength)
	for i := range backRefs {
		var readerC []frontend.Variable
		if len(c) >= delimAndLenNbWords {
			readerC = c[delimAndLenNbWords:]
		}

		readers[i] = compress.NewNumReader(api, readerC, int(backRefs[i].NbBitsAddress), 1)
	}

	res := logderivlookup.New(api)

	for i := range c {
		entry := frontend.Variable(0)
		for j := range backRefs {
			if backRefs[j].DictLen != 0 {
				backRefs[j] = lzss.NewDynamicBackrefType(backRefs[j].DictLen, i)
				readers[j].SetNumNbBits(int(backRefs[j].NbBitsAddress))
			}
			isSymb := api.IsZero(api.Sub(bytes[i], backRefs[j].Delimiter))
			entry = api.MulAcc(entry, isSymb, readers[j].Next())
		}
		res.Insert(entry)
	}

	return res
}

func RegisterHints() {
	hint.RegisterHint(internal.BreakUpBytesIntoBitsHint)
	hint.RegisterHint(internal.BreakUpBytesIntoCrumbsHint)
	hint.RegisterHint(internal.BreakUpBytesIntoHalfHint)
	hint.RegisterHint(compress.UnpackIntoBytesHint)
}
