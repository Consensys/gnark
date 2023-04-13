package constraint

import (
	"math/big"
)

// Element represents a term coefficient data. It is instantiated by the concrete
// constraint system implementation.
// Most of the scalar field used in gnark are on 4 uint64, so we have a clear memory overhead here.
type Element [6]uint64

// IsZero returns true if coefficient == 0
func (z *Element) IsZero() bool {
	return (z[5] | z[4] | z[3] | z[2] | z[1] | z[0]) == 0
}

// Field capability to perform arithmetic on Coeff
type Field interface {
	FromInterface(interface{}) Element
	ToBigInt(Element) *big.Int
	Mul(a, b Element) Element
	Add(a, b Element) Element
	Sub(a, b Element) Element
	Neg(a Element) Element
	Inverse(a Element) Element
	One() Element
	IsOne(Element) bool
	String(Element) string
}
