package lzss_v1

import (
	"bytes"
	"github.com/icza/bitio"
)

func DecompressPureGo(c []byte, settings Settings) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	in := bitio.NewReader(bytes.NewReader(c))

	outAt := func(i int) byte {
		if i < 0 {
			return 0
		}
		return out.Bytes()[i]
	}

	var offset, length uint64
	s, err := in.ReadByte()

	for err == nil {
		if s == 0 {
			if offset, err = in.ReadBits(uint8(settings.NbBitsAddress)); err != nil {
				return nil, err
			}
			if length, err = in.ReadBits(uint8(settings.NbBitsLength)); err != nil {
				return nil, err
			}

			offset++
			for i := 0; i <= int(length); i++ {
				out.WriteByte(outAt(out.Len() - int(offset)))
			}
		} else {
			out.WriteByte(s)
		}
		s, err = in.ReadByte()
	}

	return out.Bytes(), nil
}
