package lzss_v1

import (
	"bytes"
	"errors"
)

func Decompress(c []byte, settings Settings) (d []byte, err error) {
	// d[i < 0] = settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	in := bytes.NewReader(c)
	copyBuf := make([]byte, settings.NbBytesAddress+settings.NbBytesLength)

	if settings.ReferenceTo == Compressed {
		return nil, errors.New("compressed ref not implemented")
	}
	if settings.AddressingMode == Absolute {
		return nil, errors.New("absolute addressing not implemented")
	}
	if settings.Logger != nil {
		return nil, errors.New("logging not implemented")
	}

	outAt := func(i int) byte {
		if i < 0 {
			return settings.Symbol
		}
		return out.Bytes()[i]
	}

	readBackRef := func() (offset, length int) {
		_, err = in.Read(copyBuf)
		offset = readNum(copyBuf[:settings.NbBytesAddress]) + 1
		length = readNum(copyBuf[settings.NbBytesAddress:settings.NbBytesAddress+settings.NbBytesLength]) + 1
		return
	}

	s, err := in.ReadByte()
	for err == nil {
		if s == settings.BackRefSettings.Symbol {
			offset, length := readBackRef()
			if err != nil {
				return nil, err
			}
			for i := 0; i < length; i++ {
				out.WriteByte(outAt(out.Len() - offset))
			}
		} else {
			out.WriteByte(s)
		}
		s, err = in.ReadByte()
	}

	return out.Bytes(), nil
}

func readNum(bytes []byte) int { //little endian
	var res int
	for i := len(bytes) - 1; i >= 0; i-- {
		res <<= 8
		res |= int(bytes[i])
	}
	return res
}
