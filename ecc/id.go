package ecc

// do not modify the order of this enum
const (
	UNKNOWN ID = iota
	BLS377
	BLS381
	BN256
)

// ID represent a unique ID for a curve
// (used in serialization checks)
type ID uint16

func (id ID) String() string {
	switch id {
	case BLS377:
		return "bls377"
	case BLS381:
		return "bls381"
	case BN256:
		return "bn256"
	default:
		panic("unimplemented curve ID")
	}
}
