package twistededwards

import (
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	edbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	edbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/twistededwards"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	edbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark-crypto/field/zz2"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		halfGCD,
		scalarMulHint,
		decomposeScalar,
		halfGCDZZ2,
		halfGCDZZ2Emulated,
		halfGCDZZ2Signs,
		decompose,
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

func halfGCD(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(inputs[1], inputs[0], glvBasis)
	outputs[0].Set(&glvBasis.V1[0])
	outputs[1].Set(&glvBasis.V1[1])

	// figure out how many times we have overflowed
	// s2 * s + s1 = k*r
	outputs[3].Mul(outputs[1], inputs[0]).
		Add(outputs[3], outputs[0]).
		Div(outputs[3], inputs[1])

	outputs[2].SetUint64(0)
	if outputs[1].Sign() == -1 {
		outputs[1].Neg(outputs[1])
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
	} else if field.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
		var P edbls24315.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
		var P edbls24317.PointAffine
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
	} else if field.Cmp(ecc.BW6_633.ScalarField()) == 0 {
		var P edbw6633.PointAffine
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

func halfGCDZZ2(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two input")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	// the efficient endomorphism exists on Bandersnatch only
	if mod.Cmp(ecc.BLS12_381.ScalarField()) != 0 {
		return errors.New("no efficient endomorphism is available on this curve")
	}
	var glv glvParams
	var init sync.Once
	init.Do(func() {
		glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
		glv.order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		ecc.PrecomputeLattice(&glv.order, &glv.lambda, &glv.glvBasis)
	})

	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(&glv.order, inputs[1], glvBasis)
	r := zz2.ComplexNumber{
		A0: &glvBasis.V1[0],
		A1: &glvBasis.V1[1],
	}
	sp := ecc.SplitScalar(inputs[0], glvBasis)
	// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
	// so here we return -s instead of s.
	s := zz2.ComplexNumber{
		A0: &sp[0],
		A1: &sp[1],
	}
	s.Neg(&s)
	res := zz2.HalfGCD(&r, &s)
	outputs[0].Set(res[0].A0)
	outputs[1].Set(res[0].A1)
	outputs[2].Set(res[1].A0)
	outputs[3].Set(res[1].A1)

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
	return nil
}

func halfGCDZZ2Emulated(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nnMod *big.Int, nninputs, nnOutputs []*big.Int) error {
		if len(nninputs) != 2 {
			return errors.New("expecting two input")
		}
		if len(nnOutputs) != 4 {
			return errors.New("expecting four outputs")
		}
		// the efficient endomorphism exists on Bandersnatch only
		if nativeMod.Cmp(ecc.BLS12_381.ScalarField()) != 0 {
			return errors.New("no efficient endomorphism is available on this curve")
		}
		var glv glvParams
		var init sync.Once
		init.Do(func() {
			glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
			glv.order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
			ecc.PrecomputeLattice(&glv.order, &glv.lambda, &glv.glvBasis)
		})

		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(&glv.order, nninputs[1], glvBasis)
		r := zz2.ComplexNumber{
			A0: &glvBasis.V1[0],
			A1: &glvBasis.V1[1],
		}
		sp := ecc.SplitScalar(nninputs[0], glvBasis)
		// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
		// so here we return -s instead of s.
		s := zz2.ComplexNumber{
			A0: &sp[0],
			A1: &sp[1],
		}
		s.Neg(&s)
		res := zz2.HalfGCD(&r, &s)
		nnOutputs[0].Set(res[0].A0)
		nnOutputs[1].Set(res[0].A1)
		nnOutputs[2].Set(res[1].A0)
		nnOutputs[3].Set(res[1].A1)

		return nil
	})
}

func halfGCDZZ2Signs(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two input")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	// the efficient endomorphism exists on Bandersnatch only
	if mod.Cmp(ecc.BLS12_381.ScalarField()) != 0 {
		return errors.New("no efficient endomorphism is available on this curve")
	}
	var glv glvParams
	var init sync.Once
	init.Do(func() {
		glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
		glv.order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		ecc.PrecomputeLattice(&glv.order, &glv.lambda, &glv.glvBasis)
	})

	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(&glv.order, inputs[1], glvBasis)
	r := zz2.ComplexNumber{
		A0: &glvBasis.V1[0],
		A1: &glvBasis.V1[1],
	}
	sp := ecc.SplitScalar(inputs[0], glvBasis)
	s := zz2.ComplexNumber{
		A0: &sp[0],
		A1: &sp[1],
	}
	s.Neg(&s)
	res := zz2.HalfGCD(&r, &s)

	outputs[0].SetUint64(0)
	outputs[1].SetUint64(0)
	outputs[2].SetUint64(0)
	outputs[3].SetUint64(0)

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
	return nil
}

func checkHalfGCDZZ2(api frontend.API, s, lambda frontend.Variable) {
	var fr emparams.BandersnatchFr
	sapi, err := emulated.NewField[emparams.BandersnatchFr](api)
	if err != nil {
		panic(err)
	}

	// compute the decomposition using a hint. We have to use the emulated
	// version which takes native input and outputs non-native outputs.
	//
	// the hints allow to decompose the scalar s into s1 and s2 such that
	// 	   u1 + λ * u2 + s * (v1 + λ * v2) == 0 mod r
	sd, err := sapi.NewHintWithNativeInput(halfGCDZZ2Emulated, 4, s, lambda)
	if err != nil {
		panic(err)
	}
	// lambda as nonnative element
	lambdaEmu := sapi.NewElement(lambda)
	// the scalar as nonnative element. We need to split at 64 bits.
	limbs, err := api.NewHint(decompose, int(fr.NbLimbs()), s)
	if err != nil {
		panic(err)
	}
	sEmu := sapi.NewElement(limbs)

	// u1 + λ * u2 + s * (v1 + λ * v2) == 0 mod r
	lhs := sapi.MulNoReduce(sd[1], lambdaEmu)
	lhs = sapi.Add(lhs, sd[0])
	temp := sapi.MulNoReduce(sd[3], lambdaEmu)
	temp = sapi.Add(temp, sd[2])
	temp = sapi.MulNoReduce(temp, sEmu)
	lhs = sapi.Add(lhs, temp)

	sapi.AssertIsEqual(lhs, sapi.Zero())
}

func decompose(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 && len(outputs) != 4 {
		return errors.New("input/output length mismatch")
	}
	tmp := new(big.Int).Set(inputs[0])
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := 0; i < 4; i++ {
		outputs[i].And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
	return nil
}
