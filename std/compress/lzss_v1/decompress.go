package lzss_v1

import (
	"bytes"
	"github.com/consensys/gnark/std/compress"
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
		offset = compress.ReadNum(copyBuf[:settings.NbBytesAddress]) + 1
		length = compress.ReadNum(copyBuf[settings.NbBytesAddress:settings.NbBytesAddress+settings.NbBytesLength]) + 1
		return
	}

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

	return out.Bytes(), nil
}
