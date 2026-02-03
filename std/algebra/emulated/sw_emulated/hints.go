package sw_emulated

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn_fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bw6_fp "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secp_fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	stark_curve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	stark_fp "github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		scalarMulHint,
		jointScalarMulHint,
		rationalReconstruct,
		multiRationalReconstruct,
		rationalReconstructExt,
	}
}

func decomposeScalarG1(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 2 {
			return fmt.Errorf("expecting two outputs, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 2 {
			return fmt.Errorf("expecting two inputs, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 2 {
			return fmt.Errorf("expecting two outputs, got %d", len(emuOutputs))
		}
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(moduli[0], emuInputs[1], glvBasis)
		sp := ecc.SplitScalar(emuInputs[0], glvBasis)
		emuOutputs[0].Set(&(sp[0]))
		emuOutputs[1].Set(&(sp[1]))
		// we need the absolute values for the in-circuit computations,
		// otherwise the negative values will be reduced modulo the SNARK scalar
		// field and not the emulated field.
		// 		output0 = |s0| mod r
		// 		output1 = |s1| mod r
		nativeOutputs[0].SetUint64(0) // set the sign
		if emuOutputs[0].Sign() == -1 {
			emuOutputs[0].Neg(emuOutputs[0])
			nativeOutputs[0].SetUint64(1) // we return the sign of the first subscalar
		}
		nativeOutputs[1].SetUint64(0) // set the sign
		if emuOutputs[1].Sign() == -1 {
			emuOutputs[1].Neg(emuOutputs[1])
			nativeOutputs[1].SetUint64(1) // we return the sign of the second subscalar
		}
		return nil
	})
}

func scalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expecting two moduli, got %d", len(moduli))
		}
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		if len(baseInputs) != 2 {
			return fmt.Errorf("expecting two base inputs, got %d", len(baseInputs))
		}
		if len(baseOutputs) != 2 {
			return fmt.Errorf("expecting two base outputs, got %d", len(baseOutputs))
		}
		if len(scalarInputs) != 1 {
			return fmt.Errorf("expecting one scalar input, got %d", len(scalarInputs))
		}
		Px := baseInputs[0]
		Py := baseInputs[1]
		S := scalarInputs[0]
		if baseModulus.Cmp(elliptic.P256().Params().P) == 0 {
			curve := elliptic.P256()
			// compute the resulting point [s]P
			Qx, Qy := curve.ScalarMult(Px, Py, S.Bytes())
			baseOutputs[0].Set(Qx)
			baseOutputs[1].Set(Qy)
		} else if baseModulus.Cmp(elliptic.P384().Params().P) == 0 {
			curve := elliptic.P384()
			// compute the resulting point [s]P
			Qx, Qy := curve.ScalarMult(Px, Py, S.Bytes())
			baseOutputs[0].Set(Qx)
			baseOutputs[1].Set(Qy)
		} else if baseModulus.Cmp(stark_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P stark_curve.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(bn_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P bn254.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(bls12381_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P bls12381.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(secp_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P secp256k1.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(bw6_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P bw6761.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else {
			return errors.New("unsupported curve")
		}
		return nil
	})
}

// jointScalarMulHint computes [s]Q + [t]R given Q, R, s, t.
func jointScalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expecting two moduli, got %d", len(moduli))
		}
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		if len(baseInputs) != 4 {
			return fmt.Errorf("expecting four base inputs (Qx, Qy, Rx, Ry), got %d", len(baseInputs))
		}
		if len(baseOutputs) != 2 {
			return fmt.Errorf("expecting two base outputs, got %d", len(baseOutputs))
		}
		if len(scalarInputs) != 2 {
			return fmt.Errorf("expecting two scalar inputs (s, t), got %d", len(scalarInputs))
		}
		Qx, Qy := baseInputs[0], baseInputs[1]
		Rx, Ry := baseInputs[2], baseInputs[3]
		S, T := scalarInputs[0], scalarInputs[1]
		if baseModulus.Cmp(elliptic.P256().Params().P) == 0 {
			curve := elliptic.P256()
			Px, Py := curve.ScalarMult(Qx, Qy, S.Bytes())
			Tx, Ty := curve.ScalarMult(Rx, Ry, T.Bytes())
			Px, Py = curve.Add(Px, Py, Tx, Ty)
			baseOutputs[0].Set(Px)
			baseOutputs[1].Set(Py)
		} else if baseModulus.Cmp(elliptic.P384().Params().P) == 0 {
			curve := elliptic.P384()
			Px, Py := curve.ScalarMult(Qx, Qy, S.Bytes())
			Tx, Ty := curve.ScalarMult(Rx, Ry, T.Bytes())
			Px, Py = curve.Add(Px, Py, Tx, Ty)
			baseOutputs[0].Set(Px)
			baseOutputs[1].Set(Py)
		} else if baseModulus.Cmp(stark_fp.Modulus()) == 0 {
			var Q, R stark_curve.G1Affine
			Q.X.SetBigInt(Qx)
			Q.Y.SetBigInt(Qy)
			R.X.SetBigInt(Rx)
			R.Y.SetBigInt(Ry)
			Q.ScalarMultiplication(&Q, S)
			R.ScalarMultiplication(&R, T)
			Q.Add(&Q, &R)
			Q.X.BigInt(baseOutputs[0])
			Q.Y.BigInt(baseOutputs[1])
		} else {
			return errors.New("unsupported curve for jointScalarMulHint")
		}
		return nil
	})
}

func rationalReconstruct(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 1 {
			return fmt.Errorf("expecting one output, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 1 {
			return fmt.Errorf("expecting one input, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 2 {
			return fmt.Errorf("expecting two outputs, got %d", len(emuOutputs))
		}
		// Use lattice reduction to find (x, z) such that s ≡ x/z (mod r),
		// i.e., x - s*z ≡ 0 (mod r), or equivalently x + s*(-z) ≡ 0 (mod r).
		// The circuit checks: s1 + s*_s2 ≡ 0 (mod r)
		// So we need s1 = x and _s2 = -z.
		res := lattice.RationalReconstruct(emuInputs[0], moduli[0])
		x, z := res[0], res[1]

		// Ensure x is non-negative (the circuit bit-decomposes s1 assuming it's small positive).
		// If x < 0, flip signs: (x, z) -> (-x, -z), which preserves s = x/z.
		if x.Sign() < 0 {
			x.Neg(x)
			z.Neg(z)
		}

		emuOutputs[0].Set(x)
		emuOutputs[1].Abs(z)

		// we need the absolute values for the in-circuit computations,
		// otherwise the negative values will be reduced modulo the SNARK scalar
		// field and not the emulated field.
		// The sign indicates whether to negate s2 in circuit to get -z.
		// sign = 1 when z > 0 (so -z < 0, and we need to negate |z| to get -z)
		nativeOutputs[0].SetUint64(0)
		if z.Sign() > 0 {
			nativeOutputs[0].SetUint64(1)
		}
		return nil
	})
}

// multiRationalReconstruct decomposes two scalars s, t into three scalars u1, u2, v
// using lattice.MultiRationalReconstruct. Each output scalar is ~r^(1/3) bits.
// This is used for 3-MSM on curves without GLV endomorphism.
//
// The decomposition satisfies:
//
//	s * v + u1 ≡ 0 (mod r)
//	t * v + u2 ≡ 0 (mod r)
func multiRationalReconstruct(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 3 {
			return fmt.Errorf("expecting three native outputs, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 2 {
			return fmt.Errorf("expecting two inputs, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 3 {
			return fmt.Errorf("expecting three emulated outputs, got %d", len(emuOutputs))
		}

		// Use lattice reduction to find (x1, x2, z) such that
		// k1 ≡ x1/z (mod r)  and  k2 ≡ x2/z (mod r)
		// We use k1 = -s, k2 = -t so that:
		// -s ≡ u1/v (mod r) => s*v + u1 ≡ 0
		// -t ≡ u2/v (mod r) => t*v + u2 ≡ 0
		k1 := new(big.Int).Neg(emuInputs[0])
		k1.Mod(k1, moduli[0])
		k2 := new(big.Int).Neg(emuInputs[1])
		k2.Mod(k2, moduli[0])

		res := lattice.MultiRationalReconstruct(k1, k2, moduli[0])
		x1, x2, z := res[0], res[1], res[2]

		// Return absolute values
		emuOutputs[0].Abs(x1) // |u1|
		emuOutputs[1].Abs(x2) // |u2|
		emuOutputs[2].Abs(z)  // |v|

		// Set the signs
		nativeOutputs[0].SetUint64(0) // isNegu1
		nativeOutputs[1].SetUint64(0) // isNegu2
		nativeOutputs[2].SetUint64(0) // isNegv

		if x1.Sign() < 0 {
			nativeOutputs[0].SetUint64(1)
		}
		if x2.Sign() < 0 {
			nativeOutputs[1].SetUint64(1)
		}
		if z.Sign() < 0 {
			nativeOutputs[2].SetUint64(1)
		}

		return nil
	})
}

func rationalReconstructExt(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 4 {
			return fmt.Errorf("expecting four outputs, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 2 {
			return fmt.Errorf("expecting two inputs, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 4 {
			return fmt.Errorf("expecting four outputs, got %d", len(emuOutputs))
		}

		// Use lattice reduction to find (x, y, z, t) such that
		// k ≡ (x + λ*y) / (z + λ*t) (mod r)
		//
		// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
		// so here we use k = -s.
		//
		// With k = -s:
		// -s ≡ (x + λ*y) / (z + λ*t) (mod r)
		// s ≡ -(x + λ*y) / (z + λ*t) = (-x - λ*y) / (z + λ*t) (mod r)
		//
		// The circuit checks: s*(v1 + λ*v2) + u1 + λ*u2 ≡ 0 (mod r)
		// Rearranging: s ≡ -(u1 + λ*u2) / (v1 + λ*v2) (mod r)
		//
		// Matching: (-x - λ*y) = -(u1 + λ*u2)
		// So: u1 = x, u2 = y, v1 = z, v2 = t
		k := new(big.Int).Neg(emuInputs[0])
		k.Mod(k, moduli[0])
		res := lattice.RationalReconstructExt(k, moduli[0], emuInputs[1])
		x, y, z, t := res[0], res[1], res[2], res[3]

		// u1 = x, u2 = y, v1 = z, v2 = t
		// We return absolute values and track signs
		emuOutputs[0].Abs(x) // |u1| = |x|
		emuOutputs[1].Abs(y) // |u2| = |y|
		emuOutputs[2].Abs(z) // |v1| = |z|
		emuOutputs[3].Abs(t) // |v2| = |t|

		// signs
		nativeOutputs[0].SetUint64(0) // isNegu1
		nativeOutputs[1].SetUint64(0) // isNegu2
		nativeOutputs[2].SetUint64(0) // isNegv1
		nativeOutputs[3].SetUint64(0) // isNegv2

		// u1 = x is negative when x < 0
		if x.Sign() < 0 {
			nativeOutputs[0].SetUint64(1)
		}
		// u2 = y is negative when y < 0
		if y.Sign() < 0 {
			nativeOutputs[1].SetUint64(1)
		}
		// v1 = z is negative when z < 0
		if z.Sign() < 0 {
			nativeOutputs[2].SetUint64(1)
		}
		// v2 = t is negative when t < 0
		if t.Sign() < 0 {
			nativeOutputs[3].SetUint64(1)
		}
		return nil
	})
}
