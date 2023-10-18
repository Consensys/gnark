package lzss_v1

type BackRefSettings struct {
	NbBytesAddress uint
	NbBytesLength  uint
}

func (s BackRefSettings) NbBytes() int {
	return int(1 + s.NbBytesAddress + s.NbBytesLength)
}

type Settings struct {
	BackRefSettings
	StartAt uint
}
