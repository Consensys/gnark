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
func Decompress(api frontend.API, c []frontend.Variable, cLength frontend.Variable, d, dict []frontend.Variable, options ...DecompressionOption) (dLength frontend.Variable, err error) {

	var aux decompressionAux
	for _, opt := range options {
		opt(&aux)
	}

	api.AssertIsLessOrEqual(cLength, len(c)) // sanity check

	// size-related "constants"
	shortBackRefType := lzss.NewShortBackrefType()
	dynamicBackRefType := lzss.NewDynamicBackrefType(len(dict), 0)

	// check header: version and compression level
	const (
		sizeHeader = 3
		version    = 1
	)
	api.AssertIsLessOrEqual(sizeHeader, len(c))
	api.AssertIsEqual(c[0], version/256)
	api.AssertIsEqual(c[1], version%256)
	decompressionBypassed := c[2]
	api.AssertIsBoolean(decompressionBypassed)
	if len(c) == 3 {
		return 0, nil
	}

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
	eof := api.IsZero(cLength)
	dLength = api.Add(-1, eof) // if the following loop ends before hitting eof, we will get the "error" value -1 for dLength

	for outI := range d {

		curr := bytesTable.Lookup(inI)[0]

		dynamicBackRefType = lzss.NewDynamicBackrefType(len(dict), outI)
		// ASSUMPTION: 0 is not a backref indicator

		// if bypassing decompression, currIndicatesXX = 0
		// ( - curr + bypassed * curr + symbolXX == 0 ) == currIndicatesXX
		currMinusShort := plonk.EvaluateExpression(api, curr, decompressionBypassed, -1, 0, 1, int(lzss.SymbolShort))
		currIndicatesShortBr := api.IsZero(currMinusShort)

		currMinusDyn := plonk.EvaluateExpression(api, curr, decompressionBypassed, -1, 0, 1, int(lzss.SymbolDynamic))
		currIndicatesDynBr := api.IsZero(currMinusDyn)

		currIndicatesBr := api.Add(currIndicatesShortBr, currIndicatesDynBr)

		currIndicatedBrLen := bytesTable.Lookup(api.Add(inI, 8))[0]                                         // this is too small by 1
		currIndicatedBrLen = plonk.EvaluateExpression(api, currIndicatesBr, currIndicatedBrLen, 1, 0, 1, 0) // if not at a br, len is guaranteed to be 0
		currIndicatedBrAddr := addrTable.Lookup(inI)[0]                                                     // unlike len, addr can be non-zero even if we're not at a br

		copyLen = api.Select(copyLen01, currIndicatedBrLen, api.Sub(copyLen, 1))
		copyLen01 = api.IsZero(api.MulAcc(api.Neg(copyLen), copyLen, copyLen)) // - copyLen + copyLen² == 0?

		// copying = copyLen01 ? copyLen==1 : 1			either from previous iterations or starting a new copy
		// copying = copyLen01 ? copyLen : 1
		copying := plonk.EvaluateExpression(api, copyLen01, copyLen, -1, 0, 1, 1)

		copyAddr := api.Mul(api.Sub(outI+len(dict)-1, currIndicatedBrAddr), currIndicatesBr) // if no backref, don't read to avoid out of range TODO for expected compression ratio > 8, just zero out the input past cLen
		toCopy := outTable.Lookup(copyAddr)[0]

		// write to output
		outVal := api.Select(copying, toCopy, curr)
		if aux.noZeroPaddingOutput {
			d[outI] = outVal
		} else {
			d[outI] = plonk.EvaluateExpression(api, outVal, eof, 1, 0, -1, 0) // write zeros past eof
		}
		// WARNING: curr modified by MulAcc
		outTable.Insert(d[outI])

		// advancing inI and EOF
		// advance by byte or backref length
		inIDelta := api.Add(8, api.Mul(currIndicatesDynBr, dynamicBackRefType.NbBitsBackRef-8), api.Mul(currIndicatesShortBr, shortBackRefType.NbBitsBackRef-8))
		// ... unless we're IN THE MIDDLE OF a copy
		inIDelta = api.Mul(inIDelta, copyLen01)

		// TODO Try removing this check and requiring the user to pad the input with nonzeros
		// TODO Change inner to mulacc once https://github.com/Consensys/gnark/pull/859 is merged
		// inI = inI + inIDelta * (1 - eof)

		inI = api.Add(inI, plonk.EvaluateExpression(api, inIDelta, eof, 1, 0, -1, 0)) // if eof, stay put

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

// the "address" is zero when we don't have a backref delimiter
func initAddrTable(api frontend.API, bytes, _bits []frontend.Variable, backRefs ...lzss.BackrefType) *logderivlookup.Table {
	if len(backRefs) != 2 {
		panic("two backref types are expected, due to opts at the end of the function")
	}

	for i := range backRefs {
		if backRefs[i].NbBitsLength != backRefs[0].NbBitsLength {
			panic("all backref types must have the same length size")
		}
	}

	readers := make([]*compress.NumReader, len(backRefs))
	delimAndLenNbWords := int(8 + backRefs[0].NbBitsLength)
	for i := range backRefs {
		var readerC []frontend.Variable
		if len(_bits) >= delimAndLenNbWords {
			readerC = _bits[delimAndLenNbWords:]
		}

		readers[i] = compress.NewNumReader(api, readerC, int(backRefs[i].NbBitsAddress), 1)
	}

	res := logderivlookup.New(api)

	for i := range _bits {
		is0 := api.IsZero(api.Sub(bytes[i], backRefs[0].Delimiter))
		entry := api.Select(is0, readers[0].Next(), readers[1].Next())
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

// options and other auxiliary input
type decompressionAux struct {
	noZeroPaddingOutput bool
}

type DecompressionOption func(*decompressionAux)

// WithoutZeroPaddingOutput disables the feature where all decompressor output past the end is zeroed out
// It saves one constraint per byte of output but necessitates more assignment work
// If using this option, the output will be padded by the first byte of the input past the end
// If further the input is not padded, the output still will be padded with zeros
func WithoutZeroPaddingOutput(aux *decompressionAux) {
	aux.noZeroPaddingOutput = true
}
