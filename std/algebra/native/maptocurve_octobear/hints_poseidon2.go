package maptocurve_octobear

import (
	"fmt"
	"math/big"

	multisethash "github.com/consensys/gnark-crypto/ecc/octobear/multiset-hash"
)

// yIncrementPoseidon2Hint, given the PqN squeezed koalabear elements (already
// computed in-circuit by the Poseidon2 sponge), produces per-coordinate
// (q, s, k, x_coeffs[8]) where:
//   - q*B + s = squeezed[i] with s < B = ⌊p/(2T)⌋
//   - k < PqT and y = PqT*s + k yields a valid octobear point with abscissa x.
//
// The cubic solve runs natively via gnark-crypto's MapAtSlot helper.
func yIncrementPoseidon2Hint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != PqN {
		return fmt.Errorf("yIncrementPoseidon2Hint: expected %d inputs, got %d", PqN, len(inputs))
	}
	if len(outputs) != PqN*pqOutputsPerCoord {
		return fmt.Errorf("yIncrementPoseidon2Hint: expected %d outputs, got %d", PqN*pqOutputsPerCoord, len(outputs))
	}

	bound := multisethash.PqReducerBound()
	var q, s big.Int
	for i := 0; i < PqN; i++ {
		u := new(big.Int).Set(inputs[i])
		q.DivMod(u, bound, &s)
		if !s.IsUint64() {
			return fmt.Errorf("yIncrementPoseidon2Hint: slot for coord %d does not fit in uint64", i)
		}

		pt, k, err := multisethash.MapAtSlot(s.Uint64())
		if err != nil {
			return err
		}

		base := outputs[i*pqOutputsPerCoord:]
		base[0].Set(&q)
		base[1].Set(&s)
		base[2].SetUint64(uint64(k))
		getNativeE8(&pt.X, base[3:pqOutputsPerCoord])
	}
	return nil
}
