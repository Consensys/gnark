package lzss_v1

type BackRefSettings struct {
	NbBitsAddress uint
	NbBitsLength  uint
}

func (s BackRefSettings) NbBytes() int {
	return int(8 + s.NbBitsAddress + s.NbBitsLength)
}

type Settings struct {
	BackRefSettings
}
