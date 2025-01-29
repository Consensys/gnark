package poseidon2

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	frGkr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/gkr"
	frMiMC "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	constraint "github.com/consensys/gnark/constraint/bls12-377"
	"hash"
)

// extKeySBoxGateFr applies the external matrix mul, then adds the round key, then applies the sBox
// because of its symmetry, we don't need to define distinct x1 and x2 versions of it
type extKeySBoxGateFr struct {
	roundKey fr.Element
	d        int
}

func (g *extKeySBoxGateFr) Evaluate(x ...fr.Element) fr.Element {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}

	x[0].
		Double(&x[0]).
		Add(&x[0], &x[1]).
		Add(&x[0], &g.roundKey)
	return powerFr(x[0], g.d)
}

func (g *extKeySBoxGateFr) Degree() int {
	return g.d
}

// for x1, the partial round gates are identical to full round gates
// for x2, the partial round gates are just a linear combination
// TODO @Tabaie eliminate the x2 partial round gates and have the x1 gates depend on i - rf/2 or so previous x1's

// extKeyGate2Fr applies the external matrix mul, then adds the round key
type extKeyGate2Fr struct {
	roundKey fr.Element
	d        int
}

func (g *extKeyGate2Fr) Evaluate(x ...fr.Element) fr.Element {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	x[1].
		Double(&x[1]).
		Add(&x[1], &x[0]).
		Add(&x[1], &g.roundKey)
	return x[1]
}

func (g *extKeyGate2Fr) Degree() int {
	return 1
}

// intKeyGate2Fr applies the internal matrix mul, then adds the round key
type intKeyGate2Fr struct {
	roundKey fr.Element
	d        int
}

func (g *intKeyGate2Fr) Evaluate(x ...fr.Element) fr.Element {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	x[0].Add(&x[0], &x[1])
	x[1].
		Double(&x[1]).
		Add(&x[1], &x[0]).
		Add(&x[1], &g.roundKey)
	return x[1]
}

func (g *intKeyGate2Fr) Degree() int {
	return 1
}

// intKeySBoxGateFr applies the second row of internal matrix mul, then adds the round key, then applies the sBox
type intKeySBoxGate2Fr struct {
	roundKey fr.Element
	d        int
}

func (g *intKeySBoxGate2Fr) Evaluate(x ...fr.Element) fr.Element {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	x[0].Add(&x[0], &x[1])
	x[1].
		Double(&x[1]).
		Add(&x[1], &x[0]).
		Add(&x[1], &g.roundKey)

	return powerFr(x[1], g.d)
}

func (g *intKeySBoxGate2Fr) Degree() int {
	return g.d
}

type extGateFr struct{}

func (g extGateFr) Evaluate(x ...fr.Element) fr.Element {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	x[0].
		Double(&x[0]).
		Add(&x[0], &x[1])
	return x[0]
}

func (g extGateFr) Degree() int {
	return 1
}

func powerFr(x fr.Element, n int) fr.Element {
	tmp := x
	switch n {
	case 3:
		x.Square(&x).Mul(&tmp, &x)
	case 5:
		x.Square(&x).Square(&x).Mul(&x, &tmp)
	case 7:
		x.Square(&x).Mul(&x, &tmp).Square(&x).Mul(&x, &tmp)
	case 17:
		x.Square(&x).Square(&x).Square(&x).Square(&x).Mul(&x, &tmp)
	case -1:
		x.Inverse(&x)
	default:
		panic("unknown sBox degree")
	}
	return x
}

// TODO find better name
// these are the fr gatea
func AddGkrGatesSolution() {

	constraint.RegisterHashBuilder("mimc", func() hash.Hash {
		return frMiMC.NewMiMC()
	})

	roundKeysFr := bls12377RoundKeys()
	const halfRf = rF / 2

	gateNameBase := gateNameBase()

	gateNameX := func(i int) string {
		return fmt.Sprintf("x-round=%d%s", i, gateNameBase)
	}
	gateNameY := func(i int) string {
		return fmt.Sprintf("y-round=%d%s", i, gateNameBase)
	}

	fullRound := func(i int) {
		frGkr.Gates[gateNameX(i)] = &extKeySBoxGateFr{
			roundKey: roundKeysFr[i][0],
			d:        d,
		}

		frGkr.Gates[gateNameY(i)] = &extKeySBoxGateFr{
			roundKey: roundKeysFr[i][1],
			d:        d,
		}
	}

	for i := range halfRf {
		fullRound(i)
	}

	{ // i = halfRf: first partial round
		const i = halfRf
		frGkr.Gates[gateNameX(i)] = &extKeySBoxGateFr{
			roundKey: roundKeysFr[i][0],
			d:        d,
		}

		frGkr.Gates[gateNameY(i)] = &extKeyGate2Fr{ // TODO replace with extGateFr
			//roundKey: roundKeysFr[i][1],
			d: d,
		}
	}

	for i := halfRf + 1; i < halfRf+rP; i++ {
		frGkr.Gates[gateNameX(i)] = &extKeySBoxGateFr{ // for x1, intKeySBox is identical to extKeySBox
			roundKey: roundKeysFr[i][0],
			d:        d,
		}

		frGkr.Gates[gateNameY(i)] = &intKeyGate2Fr{ // TODO replace with intGateFr
			//roundKey: roundKeysFr[i][1],
			d: d,
		}
	}

	{
		const i = halfRf + rP
		frGkr.Gates[gateNameX(i)] = &extKeySBoxGateFr{
			roundKey: roundKeysFr[i][0],
			d:        d,
		}

		frGkr.Gates[gateNameY(i)] = &intKeySBoxGate2Fr{
			roundKey: roundKeysFr[i][1],
			d:        d,
		}
	}

	for i := halfRf + rP + 1; i < rP+rF; i++ {
		fullRound(i)
	}

	frGkr.Gates[gateNameY(rP+rF)] = extGateFr{}
}
