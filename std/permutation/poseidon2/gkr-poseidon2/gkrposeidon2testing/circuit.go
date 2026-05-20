// Package gkrposeidon2testing exposes a validator circuit that asserts the
// GKR-backed Poseidon2 compressor agrees with the direct in-circuit Poseidon2
// compressor. It is intended for test and test-vector generation code; importing
// it transitively brings in gkrapi, so consumers should be limited to the builder
// side of the pipeline (compilation, witness generation).
package gkrposeidon2testing

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	gkr_poseidon2 "github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2"
)

// Circuit hashes pairs of inputs twice — once through the GKR-backed Poseidon2
// compressor and once through the direct in-circuit Poseidon2 — and asserts they
// agree. Compiling it produces a GKR schedule with all three level variants
// (GkrSkipLevel, GkrSumcheckLevel, GkrSingleSourceZeroCheckLevel), which makes
// it useful for exercising the full GKR proving path after CBOR round-trip.
//
// When SkipCheck is true the equality assertion is skipped; this is only useful
// for benchmarks that want to measure the cost of the GKR proof only.
type Circuit struct {
	Ins       [][2]frontend.Variable
	SkipCheck bool `gnark:"-"`
}

func (c *Circuit) Define(api frontend.API) error {
	gkr, err := gkr_poseidon2.NewCompressor(api)
	if err != nil {
		return err
	}
	pos2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	for i := range c.Ins {
		fromGkr := gkr.Compress(c.Ins[i][0], c.Ins[i][1])
		if !c.SkipCheck {
			api.AssertIsEqual(pos2.Compress(c.Ins[i][0], c.Ins[i][1]), fromGkr)
		}
	}
	return nil
}
