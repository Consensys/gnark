package lzss_v1

type BackRefSettings struct {
	NbBytesAddress uint
}

func (s BackRefSettings) NbWords() int {
	return int(1 + s.NbBytesAddress)
}

type Settings struct {
	BackRefSettings
	StartAt uint
}
