package lzss_v1

type ReferenceTo bool
type AddressingMode bool

const (
	// Decompressed referencing is used by the original LZSS algorithm.
	// Its advantage in the SNARK world is a lack of recursive calls, which can be a headache to implement in a SNARK.
	// Its disadvantage as to compression is a need for longer back reference offsets, meaning more bits to represent them.
	// Another disadvantage during in-SNARK decompression is having to read from a lookup table as it is being written to, incurring another performance penalty.
	Decompressed ReferenceTo = false

	// Compressed can achieve better compression TODO Verify that.
	// and simpler use of lookup tables during in-SNARK decompression.
	// However the logic of decompression is much more complex, requiring the implementation of a call-stack
	Compressed ReferenceTo = true

	// Relative addressing is used by the original LZSS algorithm.
	// Its advantage is short back reference offsets, meaning few bits to represent them, and being able to refer to "negative" indices.
	// Its disadvantage is more addition constraints. Probably insignificant.
	Relative AddressingMode = false
	Absolute AddressingMode = true
)

type BackRefSettings struct {
	NbBytesAddress uint
	NbBytesLength  uint
	Symbol         byte
	ReferenceTo    ReferenceTo
	AddressingMode AddressingMode
}

type LogHeads struct {
	Compressed, Decompressed int
}

type Settings struct {
	BackRefSettings
	Log      bool
	LogHeads *[]LogHeads
}
