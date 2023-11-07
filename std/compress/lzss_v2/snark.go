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
	addrTable := initAddrTable(api, bytes, c, int(wordLen), []backrefType{longBackRefType, shortBackRefType, dictBackRefType})

	for outI := range d {

	}

}

func createLengthTables(api frontend.API, c []frontend.Variable, wordNbBits int, backrefs []backrefType) *logderivlookup.Table {
	for i := range backrefs {
		if backrefs[i].nbBitsLength != backrefs[0].nbBitsLength {
			panic("all backref types must have the same length")
		}
	}

	res := logderivlookup.New(api)
	reader := newNumReader(api, c, int(backrefs[0].nbBitsLength), wordNbBits)

	for i := 0; i < len(c); i++ {
		res.Insert(reader.next())
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
	reader := newNumReader(api, c, 8, wordNbBits)
	res := make([]frontend.Variable, len(c))
	for i := range res {
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
	for i := range backrefs {
		readers[i] = newNumReader(api, c[int(8+backrefs[0].nbBitsLength)/wordNbBits:], int(backrefs[i].nbBitsAddress), wordNbBits)
	}

	res := logderivlookup.New(api)

	for i := range c {
		entry := frontend.Variable(0)
		for j := range backrefs {
			isSymb := api.IsZero(api.Sub(bytes[i], backrefs[j].delimiter))
			entry = api.MulAcc(entry, isSymb, readers[j].next())
		}
		res.Insert(entry)
	}

	return res
}

// WARNING undefined EOF behavior
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
	for i := 0; i < nbWords; i++ {
		nxt = api.MulAcc(nxt, coeff, c[i])
		coeff = api.Mul(coeff, stepCoeff)
	}
	return &numReader{
		api:       api,
		c:         c,
		stepCoeff: stepCoeff,
		nxt:       nxt,
		nbWords:   nbWords,
	}
}

func (nr *numReader) next() frontend.Variable {

	lastSummand := frontend.Variable(0)
	if nr.nbWords > 0 {
		lastSummand = nr.c[nr.nbWords]
	}
	for i := 0; i < nr.nbWords; i++ { // TODO Cache stepCoeff^nbWords
		lastSummand = nr.api.Mul(lastSummand, nr.stepCoeff)
	}

	res := nr.nxt
	nr.nxt = nr.api.Add(nr.api.DivUnchecked(nr.api.Sub(res, nr.c[0]), nr.stepCoeff), lastSummand)

	nr.c = nr.c[1:]
	return res
}
