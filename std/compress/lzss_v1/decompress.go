package lzss_v1

import (
	"bytes"
	"github.com/consensys/gnark/std/compress"
)

func DecompressPureGo(c compress.Stream, settings Settings) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer

	outAt := func(i int) byte {
		if i < 0 {
			return 0
		}
		return out.Bytes()[i]
	}

	readBackRef := func() (offset, length int) {
		offset = c.ReadNum(1, int(settings.NbBytesAddress)) + 1
		length = c.ReadNum(1+int(settings.NbBytesAddress), int(settings.NbBytesLength)) + 1
		return
	}

	for len(c.D) != 0 {
		if c.D[0] == 256 {
			offset, length := readBackRef()
			if err != nil {
				return nil, err
			}
			for i := 0; i < length; i++ {
				out.WriteByte(outAt(out.Len() - offset))
			}
			c.D = c.D[settings.NbBytesAddress+settings.NbBytesLength+1:]
		} else {
			out.WriteByte(byte(c.D[0]))
			c.D = c.D[1:]
		}
	}

	return out.Bytes(), nil
}
