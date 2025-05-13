package internal

import (
	"fmt"

	"github.com/consensys/gnark/std/gkr"
)

const (
	Pow2GateName      = "pow2"
	Pow4GateName      = "pow4"
	Pow2TimesGateName = "pow2Times"
	Pow4TimesGateName = "pow4Times"
)

type roundGateNamer string

// RoundGateNamer returns an object that returns standardized names for gates in the GKR circuit
func RoundGateNamer(p fmt.Stringer) roundGateNamer {
	return roundGateNamer(p.String())
}

// Linear is the name of a gate where a polynomial of total degree 1 is applied to the input
func (n roundGateNamer) Linear(varIndex, round int) gkr.GateName {
	return gkr.GateName(fmt.Sprintf("x%d-l-op-round=%d;%s", varIndex, round, n))
}

// Integrated is the name of a gate where a polynomial of total degree 1 is applied to the input, followed by an S-box
func (n roundGateNamer) Integrated(varIndex, round int) gkr.GateName {
	return gkr.GateName(fmt.Sprintf("x%d-i-op-round=%d;%s", varIndex, round, n))
}
