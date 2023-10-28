package lzss_v1

import (
	"bytes"
)

func Decompress(data, dict []byte) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	out.Grow(len(data)*6 + len(dict))
	in := bytes.NewReader(data)
	var copyBuf [nbBytesAddress + nbBytesLength]byte

	outAt := func(i int) byte {
		if i < 0 {
			panic("shouldn't happen")
		}
		return out.Bytes()[i]
	}

	readBackRef := func() (offset, length int) {
		_, err = in.Read(copyBuf[:])
		offset = readNum(copyBuf[:nbBytesAddress]) + 1
		length = readNum(copyBuf[nbBytesAddress:nbBytesAddress+nbBytesLength]) + 1
		return
	}

	// read until startAt and write bytes as is
	out.Write(dict)

	s, err := in.ReadByte()
	for err == nil {
		if s == 0 {
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

	return out.Bytes()[len(dict):], nil
}

func readNum(bytes []byte) int { //little endian
	var res int
	for i := len(bytes) - 1; i >= 0; i-- {
		res <<= 8
		res |= int(bytes[i])
	}
	return res
}
