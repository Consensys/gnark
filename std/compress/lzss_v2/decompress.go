package lzss_v2

import (
	"bytes"

	"github.com/icza/bitio"
)

func Decompress(data, dict []byte) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	out.Grow(len(data)*6 + len(dict))
	in := bitio.NewReader(bytes.NewReader(data))

	outAt := func(i int) byte {
		if i < 0 {
			panic("shouldn't happen")
		}
		return out.Bytes()[i]
	}

	readBackRef := func() (offset, length int) {
		offset = int(in.TryReadBits(nbBitsAddress)) + 1
		length = int(in.TryReadBits(nbBitsLength)) + 1
		if in.TryError != nil {
			err = in.TryError
			return
		}
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
