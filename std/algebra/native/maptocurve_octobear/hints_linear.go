package maptocurve_octobear

import (
	"fmt"
	"math/big"

	multisethash "github.com/consensys/gnark-crypto/ecc/octobear/multiset-hash"
)

// yIncrementLinearHint maps msg to LinearN points natively (using gnark-crypto's
// MapLinear) and writes (k_i, x_i.coeffs[8]) for each coordinate, in order.
// 9 outputs per coordinate * LinearN coordinates.
func yIncrementLinearHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("yIncrementLinearHint: expected 1 input, got %d", len(inputs))
	}
	const coeffsPerCoord = 9
	if len(outputs) != LinearN*coeffsPerCoord {
		return fmt.Errorf("yIncrementLinearHint: expected %d outputs, got %d", LinearN*coeffsPerCoord, len(outputs))
	}
	if !inputs[0].IsUint64() {
		return fmt.Errorf("yIncrementLinearHint: input does not fit in uint64")
	}
	msg := inputs[0].Uint64()
	if msg >= LinearM {
		return fmt.Errorf("yIncrementLinearHint: input %d exceeds LinearM = %d", msg, LinearM)
	}

	pts, ks, err := multisethash.MapLinear(uint32(msg))
	if err != nil {
		return err
	}
	for i := 0; i < LinearN; i++ {
		base := outputs[i*coeffsPerCoord:]
		base[0].SetUint64(uint64(ks[i]))
		getNativeE8(&pts[i].X, base[1:coeffsPerCoord])
	}
	return nil
}
