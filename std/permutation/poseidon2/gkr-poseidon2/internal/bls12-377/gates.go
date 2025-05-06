package bls12_377

import (
	"sync"

	"github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2/internal"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	gkr "github.com/consensys/gnark/internal/gkr/bls12-377"
)

// The GKR gates needed for proving Poseidon2 permutations

// extKeySBoxGate applies the external matrix mul, then adds the round key, then applies the sBox
// because of its symmetry, we don't need to define distinct x1 and x2 versions of it
func extKeySBoxGate(roundKey *fr.Element) gkr.GateFunction {
	return func(x ...fr.Element) fr.Element {
		x[0].
			Double(&x[0]).
			Add(&x[0], &x[1]).
			Add(&x[0], roundKey)
		return sBox2(x[0])
	}
}

// intKeySBoxGate2 applies the second row of internal matrix mul, then adds the round key, then applies the sBox, returning the second element
func intKeySBoxGate2(roundKey *fr.Element) gkr.GateFunction {
	return func(x ...fr.Element) fr.Element {
		x[0].Add(&x[0], &x[1])
		x[1].
			Double(&x[1]).
			Add(&x[1], &x[0]).
			Add(&x[1], roundKey)

		return sBox2(x[1])
	}
}

// extAddGate (x,y,z) -> Ext . (x,y) + z
func extAddGate(x ...fr.Element) fr.Element {
	x[0].
		Double(&x[0]).
		Add(&x[0], &x[1]).
		Add(&x[0], &x[2])
	return x[0]
}

// sBox2 is Permutation.sBox for t=2
func sBox2(x fr.Element) fr.Element {
	var y fr.Element
	y.Square(&x).Square(&y).Square(&y).Square(&y).Mul(&x, &y)
	return y
}

// extKeyGate applies the external matrix mul, then adds the round key, then applies the sBox
// because of its symmetry, we don't need to define distinct x1 and x2 versions of it
func extKeyGate(roundKey *fr.Element) func(...fr.Element) fr.Element {
	return func(x ...fr.Element) fr.Element {
		x[0].
			Double(&x[0]).
			Add(&x[0], &x[1]).
			Add(&x[0], roundKey)
		return x[0]
	}
}

// for x1, the partial round gates are identical to full round gates
// for x2, the partial round gates are just a linear combination

// extGate2 applies the external matrix mul, outputting the second element of the result
func extGate2(x ...fr.Element) fr.Element {
	x[1].
		Double(&x[1]).
		Add(&x[1], &x[0])
	return x[1]
}

// intGate2 applies the internal matrix mul, returning the second element
func intGate2(x ...fr.Element) fr.Element {
	x[0].Add(&x[0], &x[1])
	x[1].
		Double(&x[1]).
		Add(&x[1], &x[0])
	return x[1]
}

// intKeyGate2 applies the second row of internal matrix mul, then adds the round key
func intKeyGate2(roundKey *fr.Element) gkr.GateFunction {
	return func(x ...fr.Element) fr.Element {
		x[0].Add(&x[0], &x[1])
		x[1].
			Double(&x[1]).
			Add(&x[1], &x[0]).
			Add(&x[1], roundKey)

		return x[1]
	}
}

// powGate4 x -> x⁴
func pow4Gate(x ...fr.Element) fr.Element {
	x[0].Square(&x[0]).Square(&x[0])
	return x[0]
}

// pow4TimesGate x,y -> x⁴ * y
func pow4TimesGate(x ...fr.Element) fr.Element {
	x[0].Square(&x[0]).Square(&x[0]).Mul(&x[0], &x[1])
	return x[0]
}

// pow2Gate x -> x²
func pow2Gate(x ...fr.Element) fr.Element {
	x[0].Square(&x[0])
	return x[0]
}

// pow2TimesGate x,y -> x² * y
func pow2TimesGate(x ...fr.Element) fr.Element {
	x[0].Square(&x[0]).Mul(&x[0], &x[1])
	return x[0]
}

var initOnce sync.Once

// RegisterGkrGates registers the Poseidon2 compression gates for GKR
func RegisterGkrGates() error {
	const (
		x = iota
		y
	)
	var err error
	initOnce.Do(
		func() {
			p := poseidon2.GetDefaultParameters()
			halfRf := p.NbFullRounds / 2
			gateNames := internal.RoundGateNamer[gkr.GateName](p)

			if err = gkr.RegisterGate(internal.Pow2GateName, pow2Gate, 1, gkr.WithUnverifiedDegree(2), gkr.WithNoSolvableVar()); err != nil {
				return
			}
			if err = gkr.RegisterGate(internal.Pow4GateName, pow4Gate, 1, gkr.WithUnverifiedDegree(4), gkr.WithNoSolvableVar()); err != nil {
				return
			}
			if err = gkr.RegisterGate(internal.Pow2TimesGateName, pow2TimesGate, 2, gkr.WithUnverifiedDegree(3), gkr.WithNoSolvableVar()); err != nil {
				return
			}
			if err = gkr.RegisterGate(internal.Pow4TimesGateName, pow4TimesGate, 2, gkr.WithUnverifiedDegree(5), gkr.WithNoSolvableVar()); err != nil {
				return
			}

			extKeySBox := func(round int, varIndex int) error {
				if err := gkr.RegisterGate(gateNames.Integrated(varIndex, round), extKeySBoxGate(&p.RoundKeys[round][varIndex]), 2, gkr.WithUnverifiedDegree(poseidon2.DegreeSBox()), gkr.WithNoSolvableVar()); err != nil {
					return err
				}

				return gkr.RegisterGate(gateNames.Linear(varIndex, round), extKeyGate(&p.RoundKeys[round][varIndex]), 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0))
			}

			intKeySBox2 := func(round int) error {
				if err := gkr.RegisterGate(gateNames.Linear(y, round), intKeyGate2(&p.RoundKeys[round][1]), 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
					return err
				}
				return gkr.RegisterGate(gateNames.Integrated(y, round), intKeySBoxGate2(&p.RoundKeys[round][1]), 2, gkr.WithUnverifiedDegree(poseidon2.DegreeSBox()), gkr.WithNoSolvableVar())
			}

			fullRound := func(i int) error {
				if err := extKeySBox(i, x); err != nil {
					return err
				}
				return extKeySBox(i, y)
			}

			for i := range halfRf {
				if err = fullRound(i); err != nil {
					return
				}
			}

			{ // i = halfRf: first partial round
				if err = extKeySBox(halfRf, x); err != nil {
					return
				}
				if err = gkr.RegisterGate(gateNames.Linear(y, halfRf), extGate2, 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
					return
				}
			}

			for i := halfRf + 1; i < halfRf+p.NbPartialRounds; i++ {
				if err = extKeySBox(i, x); err != nil { // for x1, intKeySBox is identical to extKeySBox
					return
				}
				if err = gkr.RegisterGate(gateNames.Linear(y, i), intGate2, 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
					return
				}
			}

			{
				i := halfRf + p.NbPartialRounds
				if err = extKeySBox(i, x); err != nil {
					return
				}
				if err = intKeySBox2(i); err != nil {
					return
				}
			}

			for i := halfRf + p.NbPartialRounds + 1; i < p.NbPartialRounds+p.NbFullRounds; i++ {
				if err = fullRound(i); err != nil {
					return
				}
			}

			err = gkr.RegisterGate(gateNames.Linear(y, p.NbPartialRounds+p.NbFullRounds), extAddGate, 3, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0))
		},
	)
	return err
}
