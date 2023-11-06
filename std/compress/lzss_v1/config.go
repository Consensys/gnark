package lzss_v1

type BackRefSettings struct {
	NbBitsAddress uint
	NbBitsLength  uint
}

type Settings struct {
	BackRefSettings
	StartAt uint
}

func (s BackRefSettings) WordNbBits() int {
	return Gcd(8, int(s.NbBitsAddress), int(s.NbBitsLength))
}
