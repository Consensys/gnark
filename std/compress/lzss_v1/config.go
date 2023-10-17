package lzss_v1

type ReferenceTo bool
type AddressingMode bool

const (

	// Compressed can achieve better compression TODO Verify that.
	// and simpler use of lookup tables during in-SNARK decompression.
	// However the logic of decompression is much more complex, requiring the implementation of a call-stack
	Compressed ReferenceTo = true

	Absolute AddressingMode = true
)

type BackRefSettings struct {
	NbBytesAddress uint
	NbBytesLength  uint
}

func (s BackRefSettings) NbBytes() int {
	return int(1 + s.NbBytesAddress + s.NbBytesLength)
}

type LogHeads struct {
	Compressed, Decompressed int
}

type Settings struct {
	BackRefSettings
}
