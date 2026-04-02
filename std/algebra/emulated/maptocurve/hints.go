package maptocurve

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		xIncrementHint,
		yIncrementHint,
	}
}

// parseHintInputs extracts the curve parameters and message from the hint inputs.
// Format: [nbLimbs, q_limbs..., a, b, s, msg_limbs...]
func parseHintInputs(inputs []*big.Int) (q, a, b *big.Int, s, nbLimbs int, msg *big.Int, err error) {
	if len(inputs) < 1 {
		return nil, nil, nil, 0, 0, nil, fmt.Errorf("empty inputs")
	}
	nbLimbs = int(inputs[0].Int64())
	// expected: 1 + nbLimbs + 3 + nbLimbs = 2*nbLimbs + 4
	expected := 1 + nbLimbs + 3 + nbLimbs
	if len(inputs) != expected {
		return nil, nil, nil, 0, 0, nil, fmt.Errorf("expected %d inputs, got %d", expected, len(inputs))
	}
	q = recompose(inputs[1:1+nbLimbs], nbLimbs)
	a = inputs[1+nbLimbs]
	b = inputs[2+nbLimbs]
	s = int(inputs[3+nbLimbs].Int64())
	msg = recompose(inputs[4+nbLimbs:4+2*nbLimbs], nbLimbs)
	return q, a, b, s, nbLimbs, msg, nil
}

// xIncrementHint computes the x-increment witness for a given message.
//
// Inputs: [nbLimbs, q_limbs..., a, b, s, msg_limbs...]
// Outputs: [k, x_limbs..., y_limbs..., z_limbs...]
//
// Searches k ∈ [0, T) such that x = msg*T + k lies on the curve and y has a
// 2^s-th root. Only practical for low 2-adicity fields (S ≤ 4).
func xIncrementHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	q, a, b, s, nbLimbs, msg, err := parseHintInputs(inputs)
	if err != nil {
		return fmt.Errorf("xIncrementHint: %w", err)
	}

	for k := int64(0); k < T; k++ {
		x := new(big.Int).Mul(msg, big.NewInt(T))
		x.Add(x, big.NewInt(k))
		x.Mod(x, q)

		rhs := evalCurveRHS(x, a, b, q)
		y := modSqrt(rhs, q)
		if y == nil {
			continue
		}

		z := nthRoot2S(y, s, q)
		if z == nil {
			y.Sub(q, y)
			z = nthRoot2S(y, s, q)
			if z == nil {
				continue
			}
		}

		outputs[0].SetInt64(k)
		decompose(x, nbLimbs, outputs[1:1+nbLimbs])
		decompose(y, nbLimbs, outputs[1+nbLimbs:1+2*nbLimbs])
		decompose(z, nbLimbs, outputs[1+2*nbLimbs:1+3*nbLimbs])
		return nil
	}
	return fmt.Errorf("xIncrementHint: no valid k found for msg (s=%d)", s)
}

// yIncrementHint computes the y-increment witness for a given message.
//
// Inputs: [nbLimbs, q_limbs..., a, b, s, msg_limbs...]
// Outputs: [k, x_limbs...]
//
// For j=0 curves (a=0): x = cbrt(y² - b) where y = msg*T + k.
func yIncrementHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	q, a, b, _, nbLimbs, msg, err := parseHintInputs(inputs)
	if err != nil {
		return fmt.Errorf("yIncrementHint: %w", err)
	}

	if a.Sign() != 0 {
		return fmt.Errorf("yIncrementHint: j≠0 curves (a≠0) not yet supported")
	}

	for k := int64(0); k < T; k++ {
		y := new(big.Int).Mul(msg, big.NewInt(T))
		y.Add(y, big.NewInt(k))
		y.Mod(y, q)

		y2 := new(big.Int).Mul(y, y)
		y2.Mod(y2, q)
		rhs := new(big.Int).Sub(y2, b)
		rhs.Mod(rhs, q)

		x := modCbrt(rhs, q)
		if x == nil {
			continue
		}

		outputs[0].SetInt64(k)
		decompose(x, nbLimbs, outputs[1:1+nbLimbs])
		return nil
	}
	return fmt.Errorf("yIncrementHint: no valid k found for msg")
}

// --- field arithmetic helpers for hints ---

// evalCurveRHS computes x³ + a*x + b mod q.
func evalCurveRHS(x, a, b, q *big.Int) *big.Int {
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, q)
	x3 := new(big.Int).Mul(x2, x)
	x3.Mod(x3, q)
	rhs := new(big.Int).Set(x3)
	if a.Sign() != 0 {
		ax := new(big.Int).Mul(a, x)
		ax.Mod(ax, q)
		rhs.Add(rhs, ax)
		rhs.Mod(rhs, q)
	}
	rhs.Add(rhs, b)
	rhs.Mod(rhs, q)
	return rhs
}

// modSqrt returns sqrt(a) mod q, or nil if a is not a QR.
func modSqrt(a, q *big.Int) *big.Int {
	r := new(big.Int).ModSqrt(a, q)
	return r
}

// nthRoot2S computes z such that z^{2^s} = a mod q, or nil if no such z exists.
func nthRoot2S(a *big.Int, s int, q *big.Int) *big.Int {
	z := new(big.Int).Set(a)
	for i := 0; i < s; i++ {
		z = modSqrt(z, q)
		if z == nil {
			return nil
		}
	}
	return z
}

// modCbrt computes the cube root of a mod q, or nil if a is not a cube.
func modCbrt(a, q *big.Int) *big.Int {
	if a.Sign() == 0 {
		return new(big.Int)
	}

	a = new(big.Int).Mod(a, q)
	three := big.NewInt(3)
	one := big.NewInt(1)
	qm1 := new(big.Int).Sub(q, one)

	qMod3 := new(big.Int).Mod(q, three)
	if qMod3.Cmp(big.NewInt(2)) == 0 {
		// q ≡ 2 mod 3: cbrt(a) = a^{(2q-1)/3}
		exp := new(big.Int).Mul(big.NewInt(2), q)
		exp.Sub(exp, one)
		exp.Div(exp, three)
		return new(big.Int).Exp(a, exp, q)
	}

	// q ≡ 1 mod 3: factor q-1 = 3^s * t with gcd(t, 3) = 1
	s := 0
	t := new(big.Int).Set(qm1)
	for {
		rem := new(big.Int)
		quo := new(big.Int)
		quo.DivMod(t, three, rem)
		if rem.Sign() != 0 {
			break
		}
		t.Set(quo)
		s++
	}

	// check a is a cube: a^{(q-1)/3} == 1
	exp := new(big.Int).Div(qm1, three)
	check := new(big.Int).Exp(a, exp, q)
	if check.Cmp(one) != 0 {
		return nil
	}

	// find primitive 3^s-th root of unity
	threePowS := new(big.Int).Exp(three, big.NewInt(int64(s)), nil)
	gExp := new(big.Int).Div(qm1, threePowS) // (q-1)/3^s
	var g *big.Int
	for gen := int64(2); ; gen++ {
		candidate := new(big.Int).Exp(big.NewInt(gen), gExp, q)
		// check it has order 3^s (not lower)
		pow := new(big.Int).Exp(candidate, new(big.Int).Div(threePowS, three), q)
		if pow.Cmp(one) != 0 {
			g = candidate
			break
		}
	}

	// initial candidate: a^{3^{-1} mod t}
	threeInvT := new(big.Int).ModInverse(three, t)
	candidate := new(big.Int).Exp(a, threeInvT, q)

	// try candidate * g^i for i = 0..3^s-1
	nCorrections := threePowS.Int64()
	gi := new(big.Int).Set(one)
	c3Check := new(big.Int)
	for i := int64(0); i < nCorrections; i++ {
		c := new(big.Int).Mul(candidate, gi)
		c.Mod(c, q)
		c3Check.Mul(c, c)
		c3Check.Mod(c3Check, q)
		c3Check.Mul(c3Check, c)
		c3Check.Mod(c3Check, q)
		if c3Check.Cmp(a) == 0 {
			return c
		}
		gi.Mul(gi, g)
		gi.Mod(gi, q)
	}
	return nil
}

// recompose reconstructs a big.Int from its limbs (little-endian, 64-bit each).
func recompose(limbs []*big.Int, nbLimbs int) *big.Int {
	result := new(big.Int)
	for i := nbLimbs - 1; i >= 0; i-- {
		result.Lsh(result, 64)
		result.Add(result, limbs[i])
	}
	return result
}

// decompose splits v into nbLimbs 64-bit limbs (little-endian).
func decompose(v *big.Int, nbLimbs int, outputs []*big.Int) {
	mask := new(big.Int).SetUint64(^uint64(0))
	tmp := new(big.Int).Set(v)
	for i := 0; i < nbLimbs; i++ {
		outputs[i].And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
}
