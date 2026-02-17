package sw_emulated

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/eisenstein"
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
		halfGCD,
		halfGCDEisenstein,
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

func halfGCD(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
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
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(moduli[0], emuInputs[0], glvBasis)
		emuOutputs[0].Set(&glvBasis.V1[0])
		emuOutputs[1].Set(&glvBasis.V1[1])
		// we need the absolute values for the in-circuit computations,
		// otherwise the negative values will be reduced modulo the SNARK scalar
		// field and not the emulated field.
		// 		output0 = |s0| mod r
		// 		output1 = |s1| mod r
		nativeOutputs[0].SetUint64(0)
		if emuOutputs[1].Sign() == -1 {
			emuOutputs[1].Neg(emuOutputs[1])
			nativeOutputs[0].SetUint64(1) // we return the sign of the second subscalar
		}
		return nil
	})
}

func halfGCDEisenstein(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
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

		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(moduli[0], emuInputs[1], glvBasis)
		r := eisenstein.ComplexNumber{
			A0: glvBasis.V1[0],
			A1: glvBasis.V1[1],
		}
		sp := ecc.SplitScalar(emuInputs[0], glvBasis)
		// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
		// so here we return -s instead of s.
		s := eisenstein.ComplexNumber{
			A0: sp[0],
			A1: sp[1],
		}
		s.Neg(&s)

		res := eisenstein.HalfGCD(&r, &s)
		// values
		emuOutputs[0].Set(&res[0].A0)
		emuOutputs[1].Set(&res[0].A1)
		emuOutputs[2].Set(&res[1].A0)
		emuOutputs[3].Set(&res[1].A1)
		// signs
		nativeOutputs[0].SetUint64(0)
		nativeOutputs[1].SetUint64(0)
		nativeOutputs[2].SetUint64(0)
		nativeOutputs[3].SetUint64(0)

		if res[0].A0.Sign() == -1 {
			emuOutputs[0].Neg(emuOutputs[0])
			nativeOutputs[0].SetUint64(1)
		}
		if res[0].A1.Sign() == -1 {
			emuOutputs[1].Neg(emuOutputs[1])
			nativeOutputs[1].SetUint64(1)
		}
		if res[1].A0.Sign() == -1 {
			emuOutputs[2].Neg(emuOutputs[2])
			nativeOutputs[2].SetUint64(1)
		}
		if res[1].A1.Sign() == -1 {
			emuOutputs[3].Neg(emuOutputs[3])
			nativeOutputs[3].SetUint64(1)
		}
		return nil
	})
}
