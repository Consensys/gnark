package lzss_v1

import "errors"

// decompressStateMachine is a model for the in-snark decompressor
func decompressStateMachine(c []byte, cLength int, d []byte, settings Settings) (dLength int, err error) {
	if settings.BackRefSettings.NbBytesLength != 1 {
		return -1, errors.New("currently only byte-long backrefs supported")
	}
	if settings.BackRefSettings.Symbol != 0 {
		return -1, errors.New("currently only 0 is supported as the backreference signifier")
	}

	isSymb := func(n byte) int {
		return boolToInt(n == settings.BackRefSettings.Symbol)
	}

	isBit := func(n int) int {
		return boolToInt(n == 0 || n == 1)
	}

	brLengthRange := 1 << (settings.NbBytesLength * 8)

	inputExhausted := 0

	readD := func(i int) byte { // reading from the decompressed stream as we write to it
		if i < 0 {
			if i >= -brLengthRange {
				return settings.BackRefSettings.Symbol
			}
			panic("out of range")
		}
		return d[i]
	}

	// in the snark we'll never read more than one backref past the end of the input, so we can just append a trivial backref
	readC := func(start, end int) []byte {
		res := make([]byte, end-start)
		for i := start; i < end && i < len(c); i++ {
			res[i-start] = c[i]
		}
		return res
	}

	readBackRef := func(i int) (offset, length int) { // need some lookahead in case of a backref
		offset = readNum(readC(i+1, i+1+int(settings.NbBytesAddress))) + 1
		length = readNum(readC(i+1+int(settings.NbBytesAddress), i+1+int(settings.NbBytesAddress+settings.NbBytesLength))) + 1
		return
	}

	inI := 0
	copyI := 0
	copyLen := 0 // remaining length of the current copy
	copyLen01 := 1
	copying := 0
	//currIsSymb := isSymb(int(c[0]))
	//brOffset, brLen := readBackRef(0)

	for outI := range d {

		curr := readC(inI, inI+1)[0]

		currIsSymb := isSymb(curr)
		brOffset, brLen := readBackRef(inI)

		copying *= 1 - copyLen01 // still copying from previous iterations
		copyI = intIte(copying, outI-brOffset, copyI+1)
		copyLen = intIte(copying, currIsSymb*brLen, copyLen-1)
		copyLen01 = isBit(copyLen)
		copying = 1 - copyLen01 + copyLen01*copyLen // either from previous iterations or starting a new copy
		copyI *= copying                            // to keep it in range in case we read nonsensical backref data when not copying TODO may need to also multiply by (1-inputExhausted) to avoid reading past the end of the input, or else keep inI = 0 when inputExhausted
		toCopy := readD(copyI)

		// write to output
		d[outI] = byte(copying)*toCopy + curr // TODO full-on ite for the case where symb != 0

		inI = inI + intIte(copying, 1, intIte(copyLen01, 0, 1+int(settings.NbBytesAddress+settings.NbBytesLength)))
		inputJustExhausted := (1 - cLength + inI) * isBit(cLength-inI)
		inputExhausted += inputJustExhausted
		inI = intIte(inputExhausted, inI, cLength)

		dLength = dLength + inputJustExhausted*(outI+1)
	}

	return
}

func intIte(cond, if0, if1 int) int {
	return (1-cond)*if0 + cond*if1
}

func boolToInt(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}
