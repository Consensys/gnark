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
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
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
