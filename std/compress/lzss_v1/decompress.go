package lzss_v1

import (
	"bytes"
)

func DecompressPureGo(c []byte, settings Settings) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	in := bytes.NewReader(c)
	copyBuf := make([]byte, settings.NbBytesAddress+settings.NbBytesLength)

	outAt := func(i int) byte {
		if i < 0 {
			return 0
		}
		return out.Bytes()[i]
	}

	readBackRef := func() (offset, length int) {
		_, err = in.Read(copyBuf)
		offset = readNum(copyBuf[:settings.NbBytesAddress]) + 1
		length = readNum(copyBuf[settings.NbBytesAddress:settings.NbBytesAddress+settings.NbBytesLength]) + 1
		return
	}

	// read until startAt and write bytes as is
	tmpBuf := make([]byte, settings.StartAt)
	_, err = in.Read(tmpBuf)
	if err != nil {
		return nil, err
	}
	out.Write(tmpBuf)

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

	return out.Bytes()[settings.StartAt:], nil
}

func readNum(bytes []byte) int { //little endian
	var res int
	for i := len(bytes) - 1; i >= 0; i-- {
		res <<= 8
		res |= int(bytes[i])
	}
	return res
}
