package lzss_v2

import (
	"github.com/consensys/gnark/std/compress"
)

func DecompressPureGo(c compress.Stream, brAdrNbBits int) (d compress.Stream, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	d.NbSymbs = c.NbSymbs

	outAt := func(i int) int {
		if i < 0 {
			return 0
		}
		return d.D[i]
	}

	brAdrMask := 1<<brAdrNbBits - 1

	for len(c.D) > 0 {
		if c.D[0] == 0 {
			offset := (c.D[1] & brAdrMask) + 1
			length := (c.D[1] >> brAdrNbBits) + 1

			for i := 0; i < length; i++ {
				d.D = append(d.D, outAt(len(d.D)-offset))
			}

			c.D = c.D[2:]
		} else {
			d.D = append(d.D, c.D[0])

			c.D = c.D[1:]
		}

	}
	return
}
