package lzss_v2

import (
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

	bytes := combineIntoBytes(api, c, int(wordLen))
	bytesTable := sliceToTable(api, bytes)

	lenTable := createLengthTables(api, c, int(wordLen), []backrefType{longBackRefType, shortBackRefType, dictBackRefType})

	for outI := range d {

	}

}

func createLengthTables(api frontend.API, c []frontend.Variable, wordNbBits int, backrefs []backrefType) *logderivlookup.Table {
	for i := range backrefs {
		if backrefs[i].nbBitsLength != backrefs[0].nbBitsLength {
			panic("all backref types must have the same length")
		}
	}

	nbWordsPerEntry := int(backrefs[0].nbBitsLength) / wordNbBits
	stepCoeff := 1 << wordNbBits
	res := logderivlookup.New(api)
	prev := readNum(api, c, int(backrefs[0].nbBitsLength), wordNbBits)
	res.Insert(prev)

	for i := 1; i < len(c); i++ {
		entry := api.Add(api.Mul(api.Sub(prev, c[i-1]), stepCoeff), c[i+nbWordsPerEntry-1])
		res.Insert(entry)
		prev = entry
	}

	return res
}

func sliceToTable(api frontend.API, slice []frontend.Variable) *logderivlookup.Table {
	table := logderivlookup.New(api)
	for i := range slice {
		table.Insert(slice[i])
	}
	return table
}

func combineIntoBytes(api frontend.API, c []frontend.Variable, wordNbBits int) []frontend.Variable {
	wordPerByte := 8 / wordNbBits
	slice := make([]frontend.Variable, len(c))
	stepCoeff := 1 << wordNbBits
	for i := range c {
		slice[i] = c[i]
		coeff := frontend.Variable(stepCoeff)
		for j := 1; j < wordPerByte && i+j < len(c); j++ {
			slice[i] = api.Add(slice[i], api.Mul(coeff, c[i+j]))
			coeff = api.Mul(coeff, stepCoeff)
		}
	}
	return slice
}

func initOffsTable(api frontend.API, bytes []frontend.Variable, wordNbBits int, backrefs []backrefType) *logderivlookup.Table {
	for i := range backrefs {
		if backrefs[i].nbBitsLength != backrefs[0].nbBitsLength {
			panic("all backref types must have the same length size")
		}
	}
	lenNbWords := int(backrefs[0].nbBitsLength) / wordNbBits
	entryNbWords := make([]int, len(backrefs))
	for i := range backrefs {
		entryNbWords[i] = int(backrefs[i].nbBitsAddress) / wordNbBits
	}
	stepCoeff := 1 << wordNbBits
	res := logderivlookup.New(api)

	for i := range bytes {
		entry := frontend.Variable(0)
		coeff := frontend.Variable(1)
		for j := 0; j < entryNbWords && i+j < len(bytes); j++ {
			entry = api.Add(entry, api.Mul(coeff, bytes[i+j]))
			coeff = api.Mul(coeff, stepCoeff)
		}
		res.Insert(entry)
	}

	return res
}

func initOffsTables(api frontend.API, c []frontend.Variable, wordNbBits int, backrefs []backrefType) []*logderivlookup.Table {

	entryNbWords := make([]int, len(backrefs))
	for i := range backrefs {
		entryNbWords[i] = int(backrefs[i].nbBitsAddress) / wordNbBits
	}

	stepCoeff := 1 << wordNbBits
	res := make([]*logderivlookup.Table, len(backrefs))

	// TODO Some kind of dynamic programming to reduce the number of constraints; there is much overlapping computation here
	for br := range backrefs {
		res[br] = logderivlookup.New(api)
		for i := range c {
			entry := frontend.Variable(0)

			if i+entryNbWords[br] <= len(c) {
				coeff := frontend.Variable(1)
				for j := 0; j < entryNbWords[br] && i+j+lenNbWords < len(c); j++ {
					entry = api.Add(entry, api.Mul(coeff, c[i+j+lenNbWords]))
					coeff = api.Mul(coeff, stepCoeff)
				}
			}

			res[br].Insert(entry)
		}
	}

	return res
}

func readNum(api frontend.API, c []frontend.Variable, numNbBits, wordNbBits int) frontend.Variable {
	res := frontend.Variable(0)
	coeff := frontend.Variable(1)
	for i := 0; i < numNbBits/wordNbBits; i++ {
		res = api.Add(res, api.Mul(coeff, c[i]))
		coeff = api.Mul(coeff, 1<<wordNbBits)
	}
	return res
}
