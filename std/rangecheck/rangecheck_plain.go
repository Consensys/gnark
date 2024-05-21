package rangecheck

import (
	"github.com/irfanbozkurt/gnark/frontend"
	"github.com/irfanbozkurt/gnark/std/math/bits"
)

type plainChecker struct {
	api frontend.API
}

func (pl plainChecker) Check(v frontend.Variable, nbBits int) {
	bits.ToBinary(pl.api, v, bits.WithNbDigits(nbBits))
}
