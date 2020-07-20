package term

// Term lightweight version of a term, no pointers
// first 4 bits are reserved
// next 30 bits represented the coefficient idx (in r1cs.Coefficients) by which the wire is multiplied
// next 30 bits represent the constraint used to compute the wire
// if we support more than 1 billion constraints, this breaks (not so soon.)
type Term uint64

// String helper for Term
func (t Term) String() string {
	// res := ""
	// res = res + t.Coeff.String() + "*:" + strconv.Itoa(int(t.ID))
	return "unimplemented"
}

const (
	_                    uint64 = 0b0000
	specialValueMinusOne uint64 = 0b0001
	specialValueZero     uint64 = 0b0010
	specialValueOne      uint64 = 0b0011
	specialValueTwo      uint64 = 0b0100
	specialValueDiv      uint64 = 0x8000000000000000
)

func NewTerm(constraintID, coeffID, specialValue int, isDivision ...bool) Term {
	_constraintID := uint64(constraintID)
	_coeffID := uint64(coeffID)
	_coeffID <<= 34
	_coeffID >>= 4
	if (_coeffID >> 30) != uint64(coeffID) {
		panic("coeffID is > 2^30, unsupported")
	}
	if ((_constraintID << 34) >> 34) != uint64(constraintID) {
		panic("constraintID is > 2^30, unsupported")
	}
	reserved := uint64(0)
	switch specialValue {
	case -1:
		reserved = specialValueMinusOne
		reserved <<= 60
	case 0:
		reserved = specialValueZero
		reserved <<= 60
	case 1:
		reserved = specialValueOne
		reserved <<= 60
	case 2:
		reserved = specialValueTwo
		reserved <<= 60
	}
	if len(isDivision) == 1 && isDivision[0] {
		reserved |= specialValueDiv
	}

	return Term(reserved | _constraintID | _coeffID)

}

const maxInt = int(^uint(0) >> 1)

func (t Term) SpecialValueInt() int {
	specialValue := uint64(t<<1) >> 61
	switch specialValue {
	case specialValueOne:
		return 1
	case specialValueMinusOne:
		return -1
	case specialValueZero:
		return 0
	case specialValueTwo:
		return 2
	default:
		return maxInt
	}
}
func (t *Term) SetConstraintID(cID int) {
	_constraintID := uint64(cID)
	if ((_constraintID << 34) >> 34) != uint64(cID) {
		panic("constraintID is > 2^30, unsupported")
	}
	const mask uint64 = 0xFFFFFFFC0000000
	*t = Term((uint64(*t) | mask) | _constraintID)
}

// ID returns the index of the constraint used to compute this wire
func (t Term) ConstraintID() int {
	const mask uint64 = 0x3FFFFFFF
	return int(uint64(t) & mask)
}

func (t Term) CoeffID() int {
	const mask uint64 = 0xFFFFFFFC0000000
	return int((uint64(t) & mask) >> 30)
}

func (t Term) IsDivision() bool {
	return (uint64(t) >> 63) != 0
}
