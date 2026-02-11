package twistededwards

import (
	"errors"
	"math/big"

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
		doubleBaseScalarMulHint,
		multiRationalReconstructExtHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func rationalReconstruct(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	// Handle zero scalar case
	if inputs[0].Sign() == 0 {
		outputs[0].SetUint64(0)
		outputs[1].SetUint64(0)
		outputs[2].SetUint64(0)
		outputs[3].SetUint64(0)
		return nil
	}

	// Use lattice reduction to find (x, z) such that s ≡ x/z (mod r),
	// i.e., x - s*z ≡ 0 (mod r), or equivalently x + s*(-z) ≡ 0 (mod r).
	// The circuit checks: s1 + s*_s2 ≡ 0 (mod r)
	// So we need s1 = x and _s2 = -z.
	rc := lattice.NewReconstructor(inputs[1])
	res := rc.RationalReconstruct(inputs[0])
	x, z := res[0], res[1]

	// Ensure x is non-negative (the circuit bit-decomposes s1 assuming it's small positive).
	// If x < 0, flip signs: (x, z) -> (-x, -z), which preserves s = x/z.
	if x.Sign() < 0 {
		x.Neg(x)
		z.Neg(z)
	}

	outputs[0].Set(x)
	outputs[1].Abs(z)

	// The sign indicates whether to negate s2 in circuit to get -z.
	// sign = 1 when z > 0 (so -z < 0, and we need to negate |z| to get -z)
	outputs[2].SetUint64(0)
	if z.Sign() > 0 {
		outputs[2].SetUint64(1)
	}

	// Compute overflow: k = (x - s*z) / r
	// The constraint is x - s*z ≡ 0 (mod r), so x - s*z = k*r for some integer k
	// We need to keep the sign of k for the circuit to work correctly.
	outputs[3].Mul(z, inputs[0])          // s*z
	outputs[3].Sub(x, outputs[3])         // x - s*z
	outputs[3].Div(outputs[3], inputs[1]) // k = (x - s*z) / r

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

// doubleBaseScalarMulHint computes [s1]P1 and [s2]P2 for the hinted double-base scalar multiplication
// inputs: P1.X, P1.Y, s1, P2.X, P2.Y, s2, order
// outputs: Q1.X, Q1.Y, Q2.X, Q2.Y where Q1=[s1]P1 and Q2=[s2]P2
func doubleBaseScalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 7 {
		return errors.New("expecting seven inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	// compute [s1]P1 and [s2]P2
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

// multiRationalReconstructExtHint decomposes two scalars k1, k2 using MultiRationalReconstructExt
// for curves with a GLV endomorphism (Bandersnatch).
// inputs: k1, k2, order, lambda
// outputs: |x1|, |y1|, |x2|, |y2|, |z|, |t|, signX1, signY1, signX2, signY2, signZ, signT
// where k1 ≡ (x1 + λ*y1)/(z + λ*t) (mod order) and k2 ≡ (x2 + λ*y2)/(z + λ*t) (mod order)
// The circuit verifies: [x1]P + [y1]φ(P) + [x2]Q + [y2]φ(Q) = [z]R + [t]φ(R)
// where R = [k1]P + [k2]Q (hinted separately)
func multiRationalReconstructExtHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return errors.New("expecting four inputs: k1, k2, order, lambda")
	}
	if len(outputs) != 12 {
		return errors.New("expecting 12 outputs")
	}

	k1, k2, order, lambda := inputs[0], inputs[1], inputs[2], inputs[3]

	// Handle zero scalar cases
	if k1.Sign() == 0 && k2.Sign() == 0 {
		for i := 0; i < 12; i++ {
			outputs[i].SetUint64(0)
		}
		return nil
	}

	// Use MultiRationalReconstructExt to find (x1, y1, x2, y2, z, t) with shared denominator
	// k1 ≡ (x1 + λ*y1)/(z + λ*t) (mod order)
	// k2 ≡ (x2 + λ*y2)/(z + λ*t) (mod order)
	rc := lattice.NewReconstructor(order).SetLambda(lambda)
	res := rc.MultiRationalReconstructExt(k1, k2)
	x1, y1, x2, y2, z, t := res[0], res[1], res[2], res[3], res[4], res[5]

	// Store absolute values
	outputs[0].Abs(x1)
	outputs[1].Abs(y1)
	outputs[2].Abs(x2)
	outputs[3].Abs(y2)
	outputs[4].Abs(z)
	outputs[5].Abs(t)

	// Store signs (1 if negative, 0 if non-negative)
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
