package lzss_v1

import (
	"bytes"
	"errors"
	"github.com/consensys/gnark/std/compress"
)

func DecompressPureGo(c compress.Stream, settings Settings) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	if c.NbSymbs != 1<<settings.WordNbBits() {
		return nil, errors.New("invalid number of symbols")
	}

	var out bytes.Buffer

	outAt := func(i int) byte {
		if i < 0 {
			return 0
		}
		return out.Bytes()[i]
	}

	wordsPerByte := 8 / settings.WordNbBits()
	wordsPerAddr := int(settings.NbBitsAddress) / settings.WordNbBits()
	wordsPerLen := int(settings.NbBitsLength) / settings.WordNbBits()

	for cI := 0; cI < c.Len(); {
		if curr := c.ReadNum(cI, wordsPerByte); curr == 0 {
			offset := c.ReadNum(cI+wordsPerByte, wordsPerAddr)
			length := c.ReadNum(cI+wordsPerByte+wordsPerAddr, wordsPerLen)

			cI += wordsPerByte + wordsPerAddr + wordsPerLen

			offset++
			for i := 0; i <= length; i++ {
				out.WriteByte(outAt(out.Len() - offset))
			}
		} else {
			out.WriteByte(byte(curr))
			cI += wordsPerByte
		}
	}

	return out.Bytes(), nil
}
