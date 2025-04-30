package internal

import (
	"fmt"
)

const (
	Pow2GateName      = "pow2"
	Pow4GateName      = "pow4"
	Pow2TimesGateName = "pow2Times"
	Pow4TimesGateName = "pow4Times"
)

type roundGateNamer[T ~string] string

// RoundGateNamer returns an object that returns standardized names for gates in the GKR circuit
func RoundGateNamer[T ~string](p fmt.Stringer) roundGateNamer[T] {
	return roundGateNamer[T](p.String())
}

// Linear is the name of a gate where a polynomial of total degree 1 is applied to the input
func (n roundGateNamer[T]) Linear(varIndex, round int) T {
	return T(fmt.Sprintf("x%d-l-op-round=%d;%s", varIndex, round, n))
}

// Integrated is the name of a gate where a polynomial of total degree 1 is applied to the input, followed by an S-box
func (n roundGateNamer[T]) Integrated(varIndex, round int) T {
	return T(fmt.Sprintf("x%d-i-op-round=%d;%s", varIndex, round, n))
}
