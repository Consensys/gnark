package sw_emulated

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

// This file implements the slope computations used by the point addition and
// doubling formulas with hinted witnesses certified by single deferred
// zero-assertions, instead of the [emulated.Field.Div] pattern which costs
// two deferred checks (a multiplication check and an equality check).
//
// The constraint content is unchanged: Div asserts λ·den = num (mod p), and
// so does the zero-assertion here. In particular the exceptional behavior is
// identical: when den ≡ 0 and num ≢ 0 the assertion is unsatisfiable, and
// when den ≡ num ≡ 0 the slope is unconstrained (callers exclude or handle
// both cases exactly as they did with Div).

// assertedRatio returns λ = num/den certified by the single deferred
// assertion λ·den − num ≡ 0 (mod p).
func (c *Curve[B, S]) assertedRatio(num, den *emulated.Element[B]) *emulated.Element[B] {
	lams, err := c.baseApi.NewHint(ratioHint, 1, num, den)
	if err != nil {
		panic(fmt.Sprintf("ratio hint: %v", err))
	}
	lam := lams[0]
	c.baseApi.AssertEvalIsZero(
		[][]*emulated.Element[B]{{lam, den}, {num}},
		[]int{1, -1},
	)
	return lam
}

// tangentSlope returns the tangent slope λ = (3x² + a)/(2y) at p, certified
// by a single deferred zero-assertion without materializing x².
//
// When unified is set, y ≡ 0 forces λ = 0 while keeping the assertion
// satisfiable (matching the dummy-denominator Select pattern of the unified
// formulas): the certified relation becomes λ·(2y + z) − (1−z)·(3x² + a) ≡ 0
// with z the y ≡ 0 indicator bit. Otherwise y ≡ 0 makes the circuit
// unsatisfiable, as with the previous Div-based tangent.
func (c *Curve[B, S]) tangentSlope(p *AffinePoint[B], unified bool) *emulated.Element[B] {
	var lams []*emulated.Element[B]
	var err error
	if c.addA {
		lams, err = c.baseApi.NewHint(tangentHintA, 1, &p.X, &p.Y, &c.a)
	} else {
		lams, err = c.baseApi.NewHint(tangentHint, 1, &p.X, &p.Y)
	}
	if err != nil {
		panic(fmt.Sprintf("tangent hint: %v", err))
	}
	lam := lams[0]
	if !unified {
		// λ·2y − 3x² − a ≡ 0
		terms := [][]*emulated.Element[B]{{lam, &p.Y}, {&p.X, &p.X}}
		coefs := []int{2, -3}
		if c.addA {
			terms = append(terms, []*emulated.Element[B]{&c.a})
			coefs = append(coefs, -1)
		}
		c.baseApi.AssertEvalIsZero(terms, coefs)
		return lam
	}
	// unified: z = 1 iff y ≡ 0. The multiplier 2y + z never vanishes: it is
	// 2y ≠ 0 when y ≢ 0 and 1 when y ≡ 0, so λ is always pinned; in the
	// latter case the right-hand side is zeroed by 1−z and λ = 0.
	isYZero := c.baseApi.IsZero(&p.Y)
	zEl := c.baseApi.FromBits(isYZero)
	nzEl := c.baseApi.Sub(c.baseApi.One(), zEl)
	terms := [][]*emulated.Element[B]{{lam, &p.Y}, {lam, zEl}, {nzEl, &p.X, &p.X}}
	coefs := []int{2, 1, -3}
	if c.addA {
		terms = append(terms, []*emulated.Element[B]{nzEl, &c.a})
		coefs = append(coefs, -1)
	}
	c.baseApi.AssertEvalIsZero(terms, coefs)
	return lam
}

// ratioHint computes num/den modulo the emulated modulus, or 0 when
// den ≡ 0 (the zero-assertion then decides satisfiability).
func ratioHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		den := new(big.Int).Mod(in[1], p)
		if den.Sign() == 0 {
			out[0].SetInt64(0)
			return nil
		}
		den.ModInverse(den, p)
		out[0].Mod(in[0], p)
		out[0].Mul(out[0], den).Mod(out[0], p)
		return nil
	})
}

// tangentHint computes 3x²/(2y) modulo the emulated modulus (curves with
// a = 0), or 0 when y ≡ 0.
func tangentHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		return tangentSlopeVal(p, in[0], in[1], nil, out[0])
	})
}

// tangentHintA computes (3x² + a)/(2y) modulo the emulated modulus, or 0
// when y ≡ 0.
func tangentHintA(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 3 || len(out) != 1 {
			return errors.New("expecting three inputs and one output")
		}
		return tangentSlopeVal(p, in[0], in[1], in[2], out[0])
	})
}

func tangentSlopeVal(p, x, y, a, out *big.Int) error {
	den := new(big.Int).Lsh(y, 1)
	den.Mod(den, p)
	if den.Sign() == 0 {
		out.SetInt64(0)
		return nil
	}
	den.ModInverse(den, p)
	num := new(big.Int).Mul(x, x)
	num.Mod(num, p)
	num.Mul(num, big.NewInt(3))
	if a != nil {
		num.Add(num, a)
	}
	num.Mod(num, p)
	out.Mul(num, den).Mod(out, p)
	return nil
}

// unifiedSlopeHint computes the slope of the j-invariant-0 unified addition:
// the tangent 3x1²/(2y1) when x1 ≡ x2, the chord (y2−y1)/(x2−x1) otherwise,
// and 0 when the selected denominator vanishes. Inputs: x1, y1, x2, y2.
func unifiedSlopeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 4 || len(out) != 1 {
			return errors.New("expecting four inputs and one output")
		}
		x1 := new(big.Int).Mod(in[0], p)
		y1 := new(big.Int).Mod(in[1], p)
		x2 := new(big.Int).Mod(in[2], p)
		y2 := new(big.Int).Mod(in[3], p)
		dx := new(big.Int).Sub(x2, x1)
		dx.Mod(dx, p)
		if dx.Sign() == 0 {
			return tangentSlopeVal(p, x1, y1, nil, out[0])
		}
		dx.ModInverse(dx, p)
		out[0].Sub(y2, y1)
		out[0].Mul(out[0], dx).Mod(out[0], p)
		return nil
	})
}

// bjSlopeHint computes the Brier-Joye unified slope
// ((x1+x2)² − x1·x2 + a)/(y1 + y2) used on j ≠ 0 curves. When y1 + y2 ≡ 0 it
// returns the numerator itself, matching the dummy-1-denominator semantics of
// the caller (the result is then discarded by a select). Inputs: x1, y1, x2,
// y2, a.
func bjSlopeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 5 || len(out) != 1 {
			return errors.New("expecting five inputs and one output")
		}
		x1 := new(big.Int).Mod(in[0], p)
		y1 := new(big.Int).Mod(in[1], p)
		x2 := new(big.Int).Mod(in[2], p)
		y2 := new(big.Int).Mod(in[3], p)
		num := new(big.Int).Add(x1, x2)
		num.Mul(num, num)
		tmp := new(big.Int).Mul(x1, x2)
		num.Sub(num, tmp)
		num.Add(num, in[4])
		num.Mod(num, p)
		den := new(big.Int).Add(y1, y2)
		den.Mod(den, p)
		if den.Sign() == 0 {
			out[0].Set(num)
			return nil
		}
		den.ModInverse(den, p)
		out[0].Mul(num, den).Mod(out[0], p)
		return nil
	})
}
