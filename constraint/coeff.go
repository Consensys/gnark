package constraint

import (
	"math/big"
)

// Coeff represents a term coefficient data. It is instantiated by the concrete
// constraint system implementation.
// Most of the scalar field used in gnark are on 4 uint64, so we have a clear memory overhead here.
type Coeff [6]uint64

// IsZero returns true if coefficient == 0
func (z *Coeff) IsZero() bool {
	return (z[5] | z[4] | z[3] | z[2] | z[1] | z[0]) == 0
}

// CoeffEngine capability to perform arithmetic on Coeff
type CoeffEngine interface {
	FromInterface(interface{}) Coeff
	ToBigInt(*Coeff) *big.Int
	Mul(a, b *Coeff)
	Add(a, b *Coeff)
	Sub(a, b *Coeff)
	Neg(a *Coeff)
	Inverse(a *Coeff)
	One() Coeff
	IsOne(*Coeff) bool
	String(*Coeff) string
}

// type Formatter interface {
// 	LinearExpressionToString(l LinearExpression) string
// 	TermToString(t Term) string

// 	WriteLinearExpression(l LinearExpression)
// 	WriteTerm(t Term)

// 	String()
// }

// R1C.String(formatter) {
// 	formatter.WriteTerm()
// 	formater.String()
// }

// type R1CFormatter interface {

// }

// constraints := getConstraints()

// formatter := newFormatter(resolver)

// formatter.

// for c := range constraints {
// 	c.String()
// 	c.L.String()

// }

// ids of the coefficients with simple values in any cs.coeffs slice.
// TODO @gbotrel let's keep that here for the refactoring -- and move it to concrete cs package after
const (
	CoeffIdZero     = 0
	CoeffIdOne      = 1
	CoeffIdTwo      = 2
	CoeffIdMinusOne = 3
	CoeffIdMinusTwo = 4
)
