package lzss_v1

import "github.com/consensys/gnark/std/compress"

type BackRefSettings struct {
	NbBitsAddress uint
	NbBitsLength  uint
}

type Settings struct {
	BackRefSettings
	StartAt uint
}

func (s BackRefSettings) WordNbBits() int {
	return compress.Gcd(8, int(s.NbBitsAddress), int(s.NbBitsLength))
}
