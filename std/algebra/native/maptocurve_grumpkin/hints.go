package maptocurve_grumpkin

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
		yIncrementHint,
	}
}

// yIncrementHint computes y-increment witness for Grumpkin (y² = x³ - 17).
//
// Inputs: [msg]
// Outputs: [k, x] where y = msg*T + k, x = cbrt(y² + 17)
func yIncrementHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("yIncrementHint: expected 1 input, got %d", len(inputs))
	}
	msg := inputs[0]
	q := mod

	for k := int64(0); k < T; k++ {
		y := new(big.Int).Mul(msg, big.NewInt(T))
		y.Add(y, big.NewInt(k))
		y.Mod(y, q)

		// x³ = y² + 17
		y2 := new(big.Int).Mul(y, y)
		y2.Mod(y2, q)
		rhs := new(big.Int).Add(y2, big.NewInt(17))
		rhs.Mod(rhs, q)

		x := modCbrt(rhs, q)
		if x == nil {
			continue
		}

		outputs[0].SetInt64(k)
		outputs[1].Set(x)
		return nil
	}
	return fmt.Errorf("yIncrementHint: no valid k found for Grumpkin")
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
		exp := new(big.Int).Mul(big.NewInt(2), q)
		exp.Sub(exp, one)
		exp.Div(exp, three)
		return new(big.Int).Exp(a, exp, q)
	}

	// q ≡ 1 mod 3: factor q-1 = 3^s * t
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

	exp := new(big.Int).Div(qm1, three)
	check := new(big.Int).Exp(a, exp, q)
	if check.Cmp(one) != 0 {
		return nil
	}

	threePowS := new(big.Int).Exp(three, big.NewInt(int64(s)), nil)
	gExp := new(big.Int).Div(qm1, threePowS)
	var g *big.Int
	for gen := int64(2); ; gen++ {
		candidate := new(big.Int).Exp(big.NewInt(gen), gExp, q)
		pow := new(big.Int).Exp(candidate, new(big.Int).Div(threePowS, three), q)
		if pow.Cmp(one) != 0 {
			g = candidate
			break
		}
	}

	threeInvT := new(big.Int).ModInverse(three, t)
	candidate := new(big.Int).Exp(a, threeInvT, q)

	nCorrections := threePowS.Int64()
	gi := new(big.Int).Set(one)
	for i := int64(0); i < nCorrections; i++ {
		c := new(big.Int).Mul(candidate, gi)
		c.Mod(c, q)
		c3 := new(big.Int).Mul(c, c)
		c3.Mod(c3, q)
		c3.Mul(c3, c)
		c3.Mod(c3, q)
		if c3.Cmp(a) == 0 {
			return c
		}
		gi.Mul(gi, g)
		gi.Mod(gi, q)
	}
	return nil
}
