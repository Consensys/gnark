package lzss_v1

import (
	"fmt"
	"github.com/consensys/gnark/std/compress"
)

func DecompressPureGo(c compress.Stream, settings Settings) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	d = make([]byte, settings.StartAt)

	readBackRef := func() (offset, length int) {
		offset = c.ReadNum(1, int(settings.NbBytesAddress)) + 1
		length = c.ReadNum(1+int(settings.NbBytesAddress), int(settings.NbBytesLength)) + 1
		return
	}

	for len(c.D) != 0 {
		if len(d) == 325 {
			fmt.Println("trouble ahead")
		}
		if c.D[0] == 256 {
			offset, length := readBackRef()
			if err != nil {
				return nil, err
			}
			for ; length > 0; length-- {
				d = append(d, d[len(d)-offset])
			}
			c.D = c.D[settings.NbBytesAddress+settings.NbBytesLength+1:]
		} else {
			d = append(d, byte(c.D[0]))
			c.D = c.D[1:]
		}
	}

	return d[settings.StartAt:], nil
}
