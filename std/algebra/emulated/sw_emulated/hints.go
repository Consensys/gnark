package sw_emulated

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn_fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bw6_fp "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secp_fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	stark_curve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	stark_fp "github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
	"github.com/consensys/gnark-crypto/field/eisenstein"
	"github.com/consensys/gnark/constraint/solver"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1Signs,
		decomposeScalarG1Subscalars,
		scalarMulG1Hint,
		scalarMulGLVG1Hint,
		halfGCD,
		halfGCDSigns,
		halfGCDEisenstein,
		halfGCDEisensteinSigns,
	}
}

func decomposeScalarG1Subscalars(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 2 {
			return fmt.Errorf("expecting two inputs")
		}
		if len(outputs) != 2 {
			return fmt.Errorf("expecting two outputs")
		}
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(field, inputs[1], glvBasis)
		sp := ecc.SplitScalar(inputs[0], glvBasis)
		outputs[0].Set(&(sp[0]))
		outputs[1].Set(&(sp[1]))
		// we need the absolute values for the in-circuit computations,
		// otherwise the negative values will be reduced modulo the SNARK scalar
		// field and not the emulated field.
		// 		output0 = |s0| mod r
		// 		output1 = |s1| mod r
		if outputs[0].Sign() == -1 {
			outputs[0].Neg(outputs[0])
		}
		if outputs[1].Sign() == -1 {
			outputs[1].Neg(outputs[1])
		}

		return nil
	})
}

func decomposeScalarG1Signs(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeOutput(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 2 {
			return fmt.Errorf("expecting two inputs")
		}
		if len(outputs) != 2 {
			return fmt.Errorf("expecting two outputs")
		}
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(field, inputs[1], glvBasis)
		sp := ecc.SplitScalar(inputs[0], glvBasis)
		outputs[0].SetUint64(0)
		if sp[0].Sign() == -1 {
			outputs[0].SetUint64(1)
		}
		outputs[1].SetUint64(0)
		if sp[1].Sign() == -1 {
			outputs[1].SetUint64(1)
		}

		return nil
	})
}

// TODO @yelhousni: generalize for any supported curve.
// as it currently works only for P-256, P-384 and STARK curve.
func scalarMulG1Hint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(outputs) != 2 {
			return fmt.Errorf("expecting two outputs")
		}
		if field.Cmp(elliptic.P256().Params().P) == 0 {
			var fp emparams.P256Fp
			var fr emparams.P256Fr
			PXLimbs := inputs[:fp.NbLimbs()]
			PYLimbs := inputs[fp.NbLimbs() : 2*fp.NbLimbs()]
			SLimbs := inputs[2*fp.NbLimbs():]
			Px, Py, S := new(big.Int), new(big.Int), new(big.Int)
			if err := limbs.Recompose(PXLimbs, fp.BitsPerLimb(), Px); err != nil {
				return err

			}
			if err := limbs.Recompose(PYLimbs, fp.BitsPerLimb(), Py); err != nil {
				return err

			}
			if err := limbs.Recompose(SLimbs, fr.BitsPerLimb(), S); err != nil {
				return err

			}
			curve := elliptic.P256()
			// compute the resulting point [s]Q
			outputs[0], outputs[1] = curve.ScalarMult(Px, Py, S.Bytes())
		} else if field.Cmp(elliptic.P384().Params().P) == 0 {
			var fp emparams.P384Fp
			var fr emparams.P384Fr
			PXLimbs := inputs[:fp.NbLimbs()]
			PYLimbs := inputs[fp.NbLimbs() : 2*fp.NbLimbs()]
			SLimbs := inputs[2*fp.NbLimbs():]
			Px, Py, S := new(big.Int), new(big.Int), new(big.Int)
			if err := limbs.Recompose(PXLimbs, fp.BitsPerLimb(), Px); err != nil {
				return err

			}
			if err := limbs.Recompose(PYLimbs, fp.BitsPerLimb(), Py); err != nil {
				return err

			}
			if err := limbs.Recompose(SLimbs, fr.BitsPerLimb(), S); err != nil {
				return err

			}
			curve := elliptic.P384()
			// compute the resulting point [s]Q
			outputs[0], outputs[1] = curve.ScalarMult(Px, Py, S.Bytes())
		} else if field.Cmp(stark_fp.Modulus()) == 0 {
			var fp emparams.STARKCurveFp
			var fr emparams.STARKCurveFr
			PXLimbs := inputs[:fp.NbLimbs()]
			PYLimbs := inputs[fp.NbLimbs() : 2*fp.NbLimbs()]
			SLimbs := inputs[2*fp.NbLimbs():]
			Px, Py, S := new(big.Int), new(big.Int), new(big.Int)
			if err := limbs.Recompose(PXLimbs, fp.BitsPerLimb(), Px); err != nil {
				return err

			}
			if err := limbs.Recompose(PYLimbs, fp.BitsPerLimb(), Py); err != nil {
				return err

			}
			if err := limbs.Recompose(SLimbs, fr.BitsPerLimb(), S); err != nil {
				return err

			}
			// compute the resulting point [s]Q
			var P stark_curve.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		} else {
			return fmt.Errorf("unsupported curve")
		}

		return nil
	})
}

func scalarMulGLVG1Hint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(outputs) != 2 {
			return fmt.Errorf("expecting two outputs")
		}

		if field.Cmp(bn_fp.Modulus()) == 0 {
			var fp emparams.BN254Fp
			var fr emparams.BN254Fr
			PXLimbs := inputs[:fp.NbLimbs()]
			PYLimbs := inputs[fp.NbLimbs() : 2*fp.NbLimbs()]
			SLimbs := inputs[2*fp.NbLimbs():]
			Px, Py, S := new(big.Int), new(big.Int), new(big.Int)
			if err := limbs.Recompose(PXLimbs, fp.BitsPerLimb(), Px); err != nil {
				return err

			}
			if err := limbs.Recompose(PYLimbs, fp.BitsPerLimb(), Py); err != nil {
				return err

			}
			if err := limbs.Recompose(SLimbs, fr.BitsPerLimb(), S); err != nil {
				return err

			}
			// compute the resulting point [s]Q
			var P bn254.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		} else if field.Cmp(secp_fp.Modulus()) == 0 {
			var fp emparams.Secp256k1Fp
			var fr emparams.Secp256k1Fr
			PXLimbs := inputs[:fp.NbLimbs()]
			PYLimbs := inputs[fp.NbLimbs() : 2*fp.NbLimbs()]
			SLimbs := inputs[2*fp.NbLimbs():]
			Px, Py, S := new(big.Int), new(big.Int), new(big.Int)
			if err := limbs.Recompose(PXLimbs, fp.BitsPerLimb(), Px); err != nil {
				return err

			}
			if err := limbs.Recompose(PYLimbs, fp.BitsPerLimb(), Py); err != nil {
				return err

			}
			if err := limbs.Recompose(SLimbs, fr.BitsPerLimb(), S); err != nil {
				return err

			}
			// compute the resulting point [s]Q
			var P secp256k1.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		} else if field.Cmp(bw6_fp.Modulus()) == 0 {
			var fp emparams.BW6761Fp
			var fr emparams.BW6761Fr
			PXLimbs := inputs[:fp.NbLimbs()]
			PYLimbs := inputs[fp.NbLimbs() : 2*fp.NbLimbs()]
			SLimbs := inputs[2*fp.NbLimbs():]
			Px, Py, S := new(big.Int), new(big.Int), new(big.Int)
			if err := limbs.Recompose(PXLimbs, fp.BitsPerLimb(), Px); err != nil {
				return err

			}
			if err := limbs.Recompose(PYLimbs, fp.BitsPerLimb(), Py); err != nil {
				return err

			}
			if err := limbs.Recompose(SLimbs, fr.BitsPerLimb(), S); err != nil {
				return err

			}
			// compute the resulting point [s]Q
			var P bw6761.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		} else {
			return fmt.Errorf("unsupported curve")
		}

		return nil
	})
}

func halfGCDSigns(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeOutput(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 1 {
			return fmt.Errorf("expecting one input")
		}
		if len(outputs) != 1 {
			return fmt.Errorf("expecting one output")
		}
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(field, inputs[0], glvBasis)
		outputs[0].SetUint64(0)
		if glvBasis.V1[1].Sign() == -1 {
			outputs[0].SetUint64(1)
		}

		return nil
	})
}

func halfGCD(mod *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 1 {
			return fmt.Errorf("expecting one input")
		}
		if len(outputs) != 2 {
			return fmt.Errorf("expecting two outputs")
		}
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(field, inputs[0], glvBasis)
		outputs[0].Set(&glvBasis.V1[0])
		outputs[1].Set(&glvBasis.V1[1])

		// we need the absolute values for the in-circuit computations,
		// otherwise the negative values will be reduced modulo the SNARK scalar
		// field and not the emulated field.
		// 		output0 = |s0| mod r
		// 		output1 = |s1| mod r
		if outputs[1].Sign() == -1 {
			outputs[1].Neg(outputs[1])
		}

		return nil
	})
}

func halfGCDEisensteinSigns(mod *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeOutput(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 2 {
			return fmt.Errorf("expecting two input")
		}
		if len(outputs) != 6 {
			return fmt.Errorf("expecting six outputs")
		}
		var r, s eisenstein.ComplexNumber
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(field, inputs[1], glvBasis)
		r.A0.Set(&glvBasis.V1[0])
		r.A1.Set(&glvBasis.V1[1])
		sp := ecc.SplitScalar(inputs[0], glvBasis)
		s.A0.Set(&sp[0])
		s.A1.Set(&sp[1])

		outputs[0].SetUint64(0)
		outputs[1].SetUint64(0)
		outputs[2].SetUint64(0)
		outputs[3].SetUint64(0)
		outputs[4].SetUint64(0)
		outputs[5].SetUint64(0)
		res := eisenstein.HalfGCD(&r, &s)
		if res[0].A0.Sign() == -1 {
			outputs[0].SetUint64(1)
		}
		if res[0].A1.Sign() == -1 {
			outputs[1].SetUint64(1)
		}
		if res[1].A0.Sign() == -1 {
			outputs[2].SetUint64(1)
		}
		if res[1].A1.Sign() == -1 {
			outputs[3].SetUint64(1)
		}
		if res[2].A0.Sign() == -1 {
			outputs[4].SetUint64(1)
		}
		if res[2].A1.Sign() == -1 {
			outputs[5].SetUint64(1)
		}

		return nil
	})
}

func halfGCDEisenstein(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 2 {
			return fmt.Errorf("expecting two input")
		}
		if len(outputs) != 6 {
			return fmt.Errorf("expecting six outputs")
		}
		var r, s eisenstein.ComplexNumber
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(field, inputs[1], glvBasis)
		r.A0.Set(&glvBasis.V1[0])
		r.A1.Set(&glvBasis.V1[1])
		sp := ecc.SplitScalar(inputs[0], glvBasis)
		s.A0.Set(&sp[0])
		s.A1.Set(&sp[1])

		res := eisenstein.HalfGCD(&r, &s)
		outputs[0].Set(&res[0].A0)
		outputs[1].Set(&res[0].A1)
		outputs[2].Set(&res[1].A0)
		outputs[3].Set(&res[1].A1)
		outputs[4].Set(&res[2].A0)
		outputs[5].Set(&res[2].A1)
		if outputs[0].Sign() == -1 {
			outputs[0].Neg(outputs[0])
		}
		if outputs[1].Sign() == -1 {
			outputs[1].Neg(outputs[1])
		}
		if outputs[2].Sign() == -1 {
			outputs[2].Neg(outputs[2])
		}
		if outputs[3].Sign() == -1 {
			outputs[3].Neg(outputs[3])
		}
		if outputs[4].Sign() == -1 {
			outputs[4].Neg(outputs[4])
		}
		if outputs[5].Sign() == -1 {
			outputs[5].Neg(outputs[5])
		}
		fmt.Println(outputs[0].BitLen(), outputs[1].BitLen(), outputs[2].BitLen(), outputs[3].BitLen(), outputs[4].BitLen(), outputs[5].BitLen())

		return nil

	})
}
