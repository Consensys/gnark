package twistededwards

import (
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	edbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		rationalReconstruct,
		scalarMulHint,
		decomposeScalar,
		doubleBaseScalarMulHint,
		multiRationalReconstructExtHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

type glvParams struct {
	lambda, order big.Int
	glvBasis      ecc.Lattice
}

func decomposeScalar(scalarField *big.Int, inputs []*big.Int, res []*big.Int) error {
	// the efficient endomorphism exists on Bandersnatch only
	if scalarField.Cmp(ecc.BLS12_381.ScalarField()) != 0 {
		return errors.New("no efficient endomorphism is available on this curve")
	}
	var glv glvParams
	var init sync.Once
	init.Do(func() {
		glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
		glv.order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		ecc.PrecomputeLattice(&glv.order, &glv.lambda, &glv.glvBasis)
	})

	// sp[0] is always negative because, in SplitScalar(), we always round above
	// the determinant/2 computed in PrecomputeLattice() which is negative for Bandersnatch.
	// Thus taking -sp[0] here and negating the point in ScalarMul().
	// If we keep -sp[0] it will be reduced mod r (the BLS12-381 prime order)
	// and not the Bandersnatch prime order (Order) and the result will be incorrect.
	// Also, if we reduce it mod Order here, we can't use api.ToBinary(sp[0], 129)
	// and hence we can't reduce optimally the number of constraints.
	sp := ecc.SplitScalar(inputs[0], &glv.glvBasis)
	res[0].Neg(&(sp[0]))
	res[1].Set(&(sp[1]))

	// figure out how many times we have overflowed
	res[2].Mul(res[1], &glv.lambda).Sub(res[2], res[0])
	res[2].Sub(res[2], inputs[0])
	res[2].Div(res[2], &glv.order)

	return nil
}

// rationalReconstruct decomposes a scalar s ∈ Fr into (s1, s2, signBit, k) such
// that s1 + s2·s = k·r in the integers, with |s1|, |s2| < γ₂·√r ≈ 1.15·√r
// (proven LLL/Hermite bound). Replaces the older heuristic-bound HalfGCD.
//
// The bit-decomposition convention: s1 ≥ 0 always, s2 = ±|s2| with signBit = 1
// iff the underlying signed s2 was negative. The integer k is signed.
func rationalReconstruct(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs (s, r)")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs (s1, |s2|, signBit, k)")
	}
	// Zero scalar: trivial (s1=s2=k=0). The in-circuit IsZero(s2)=0 guard
	// rejects this; the caller must pre-route scalar=1 (mirrors the existing
	// scalarMulFakeGLV: checkedScalar = Select(isScalarZero, 1, scalar)).
	if inputs[0].Sign() == 0 {
		for i := range outputs {
			outputs[i].SetUint64(0)
		}
		return nil
	}

	// lattice.RationalReconstruct returns (x, z) with x ≡ z·s mod r,
	// so x − z·s = m·r for some signed integer m, with |x|, |z| < γ₂·√r.
	// Map onto our convention: s1 + s2·s = k·r ⇒ s1 = x, s2 = −z, k = m.
	res := lattice.RationalReconstruct(inputs[0], inputs[1])
	x, z := new(big.Int).Set(res[0]), new(big.Int).Set(res[1])

	// Normalise so s1 ≥ 0. Flipping signs of (x, z) preserves x − z·s = m·r
	// (with m negated).
	if x.Sign() < 0 {
		x.Neg(x)
		z.Neg(z)
	}
	outputs[0].Set(x) // s1 = x ≥ 0

	// k = (x − z·s) / r computed in signed integers.
	k := new(big.Int).Mul(z, inputs[0])
	k.Sub(x, k)
	k.Quo(k, inputs[1])
	outputs[3].Set(k)

	// s2 = −z, encoded as |s2| + signBit. signBit = 1 iff −z < 0 iff z > 0.
	outputs[1].Abs(z)
	outputs[2].SetUint64(0)
	if z.Sign() > 0 {
		outputs[2].SetUint64(1)
	}
	return nil
}

func scalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return errors.New("expecting four inputs")
	}
	if len(outputs) != 2 {
		return errors.New("expecting two outputs")
	}
	// compute the resulting point [s]Q
	if field.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		order, _ := new(big.Int).SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		if inputs[3].Cmp(order) == 0 {
			var P bandersnatch.PointAffine
			P.X.SetBigInt(inputs[0])
			P.Y.SetBigInt(inputs[1])
			P.ScalarMultiplication(&P, inputs[2])
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		} else {
			var P jubjub.PointAffine
			P.X.SetBigInt(inputs[0])
			P.Y.SetBigInt(inputs[1])
			P.ScalarMultiplication(&P, inputs[2])
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		}
	} else if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		var P babyjubjub.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		var P edbls12377.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		var P edbw6761.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else {
		return errors.New("scalarMulHint: unknown curve")
	}
	return nil
}

// doubleBaseScalarMulHint computes [s1]P1 and [s2]P2 separately and returns
// their (X, Y) coords. Inputs: P1.X, P1.Y, s1, P2.X, P2.Y, s2, order.
// Outputs: Q1.X, Q1.Y, Q2.X, Q2.Y where Q1=[s1]P1 and Q2=[s2]P2.
//
// Used by `doubleBaseScalarMul3MSMLogUp` and `doubleBaseScalarMul6MSMLogUp` to
// hint the result that the in-circuit MSM verifies.
func doubleBaseScalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 7 {
		return errors.New("expecting seven inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	if field.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		order, _ := new(big.Int).SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		if inputs[6].Cmp(order) == 0 {
			var P1, P2 bandersnatch.PointAffine
			P1.X.SetBigInt(inputs[0])
			P1.Y.SetBigInt(inputs[1])
			P1.ScalarMultiplication(&P1, inputs[2])
			P2.X.SetBigInt(inputs[3])
			P2.Y.SetBigInt(inputs[4])
			P2.ScalarMultiplication(&P2, inputs[5])
			P1.X.BigInt(outputs[0])
			P1.Y.BigInt(outputs[1])
			P2.X.BigInt(outputs[2])
			P2.Y.BigInt(outputs[3])
		} else {
			var P1, P2 jubjub.PointAffine
			P1.X.SetBigInt(inputs[0])
			P1.Y.SetBigInt(inputs[1])
			P1.ScalarMultiplication(&P1, inputs[2])
			P2.X.SetBigInt(inputs[3])
			P2.Y.SetBigInt(inputs[4])
			P2.ScalarMultiplication(&P2, inputs[5])
			P1.X.BigInt(outputs[0])
			P1.Y.BigInt(outputs[1])
			P2.X.BigInt(outputs[2])
			P2.Y.BigInt(outputs[3])
		}
	} else if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		var P1, P2 babyjubjub.PointAffine
		P1.X.SetBigInt(inputs[0])
		P1.Y.SetBigInt(inputs[1])
		P1.ScalarMultiplication(&P1, inputs[2])
		P2.X.SetBigInt(inputs[3])
		P2.Y.SetBigInt(inputs[4])
		P2.ScalarMultiplication(&P2, inputs[5])
		P1.X.BigInt(outputs[0])
		P1.Y.BigInt(outputs[1])
		P2.X.BigInt(outputs[2])
		P2.Y.BigInt(outputs[3])
	} else if field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		var P1, P2 edbls12377.PointAffine
		P1.X.SetBigInt(inputs[0])
		P1.Y.SetBigInt(inputs[1])
		P1.ScalarMultiplication(&P1, inputs[2])
		P2.X.SetBigInt(inputs[3])
		P2.Y.SetBigInt(inputs[4])
		P2.ScalarMultiplication(&P2, inputs[5])
		P1.X.BigInt(outputs[0])
		P1.Y.BigInt(outputs[1])
		P2.X.BigInt(outputs[2])
		P2.Y.BigInt(outputs[3])
	} else if field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		var P1, P2 edbw6761.PointAffine
		P1.X.SetBigInt(inputs[0])
		P1.Y.SetBigInt(inputs[1])
		P1.ScalarMultiplication(&P1, inputs[2])
		P2.X.SetBigInt(inputs[3])
		P2.Y.SetBigInt(inputs[4])
		P2.ScalarMultiplication(&P2, inputs[5])
		P1.X.BigInt(outputs[0])
		P1.Y.BigInt(outputs[1])
		P2.X.BigInt(outputs[2])
		P2.Y.BigInt(outputs[3])
	} else {
		return errors.New("doubleBaseScalarMulHint: unknown curve")
	}
	return nil
}

// multiRationalReconstructExtHint decomposes (k1, k2) jointly via 6-D LLL
// reconstruction: finds (x1, y1, x2, y2, z, t) with shared denominator
// (z + λ·t) such that
//
//	k1 ≡ (x1 + λ·y1) / (z + λ·t)   (mod r)
//	k2 ≡ (x2 + λ·y2) / (z + λ·t)   (mod r)
//
// with each component bounded by ~r^(1/3). Used by the GLV-curve
// `doubleBaseScalarMul6MSMLogUp` path.
//
// inputs: k1, k2, order, lambda
// outputs[0..5]:  |x1|, |y1|, |x2|, |y2|, |z|, |t|
// outputs[6..11]: signX1, signY1, signX2, signY2, signZ, signT
func multiRationalReconstructExtHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return errors.New("expecting four inputs: k1, k2, order, lambda")
	}
	if len(outputs) != 12 {
		return errors.New("expecting 12 outputs")
	}
	k1, k2, order, lambda := inputs[0], inputs[1], inputs[2], inputs[3]

	if k1.Sign() == 0 && k2.Sign() == 0 {
		for i := range outputs {
			outputs[i].SetUint64(0)
		}
		return nil
	}

	rc := lattice.NewReconstructor(order).SetLambda(lambda)
	res := rc.MultiRationalReconstructExt(k1, k2)
	x1, y1, x2, y2, z, t := res[0], res[1], res[2], res[3], res[4], res[5]

	outputs[0].Abs(x1)
	outputs[1].Abs(y1)
	outputs[2].Abs(x2)
	outputs[3].Abs(y2)
	outputs[4].Abs(z)
	outputs[5].Abs(t)

	setSign := func(out *big.Int, val *big.Int) {
		if val.Sign() < 0 {
			out.SetUint64(1)
		} else {
			out.SetUint64(0)
		}
	}
	setSign(outputs[6], x1)
	setSign(outputs[7], y1)
	setSign(outputs[8], x2)
	setSign(outputs[9], y2)
	setSign(outputs[10], z)
	setSign(outputs[11], t)

	return nil
}
