package sw_bls12377

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG1Simple,
		decomposeScalarG2,
		decompose,
		halfGCD,
		scalarMulHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func decomposeScalarG1Simple(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expecting two outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	outputs[0].Set(&(sp[0]))
	outputs[1].Set(&(sp[1]))

	return nil
}

func decomposeScalarG1(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 3 {
		return fmt.Errorf("expecting three outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	outputs[0].Set(&(sp[0]))
	outputs[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for outputs[0].Cmp(cc.lambda) < 1 && outputs[1].Cmp(cc.lambda) < 1 {
		outputs[0].Add(outputs[0], cc.lambda)
		outputs[0].Add(outputs[0], one)
		outputs[1].Add(outputs[1], cc.lambda)
	}
	// figure out how many times we have overflowed
	outputs[2].Mul(outputs[1], cc.lambda).Add(outputs[2], outputs[0])
	outputs[2].Sub(outputs[2], inputs[0])
	outputs[2].Div(outputs[2], cc.fr)

	return nil
}

func decomposeScalarG2(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 3 {
		return fmt.Errorf("expecting three outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	outputs[0].Set(&(sp[0]))
	outputs[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for outputs[0].Cmp(cc.lambda) < 1 && outputs[1].Cmp(cc.lambda) < 1 {
		outputs[0].Add(outputs[0], cc.lambda)
		outputs[0].Add(outputs[0], one)
		outputs[1].Add(outputs[1], cc.lambda)
	}
	// figure out how many times we have overflowed
	outputs[2].Mul(outputs[1], cc.lambda).Add(outputs[2], outputs[0])
	outputs[2].Sub(outputs[2], inputs[0])
	outputs[2].Div(outputs[2], cc.fr)

	return nil
}

func scalarMulHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("expecting three inputs")
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expecting two outputs")
	}

	// compute the resulting point [s]Q
	var R bls12377.G1Affine
	R.X.SetBigInt(inputs[0])
	R.Y.SetBigInt(inputs[1])
	R.ScalarMultiplication(&R, inputs[2])

	R.X.BigInt(outputs[0])
	R.Y.BigInt(outputs[1])

	return nil
}

func halfGCD(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nnMod *big.Int, nninputs, nnOutputs []*big.Int) error {
		if len(nninputs) != 1 {
			return fmt.Errorf("expecting one input")
		}
		if len(nnOutputs) != 2 {
			return fmt.Errorf("expecting two outputs")
		}
		glvBasis := new(ecc.Lattice)
		cc := getInnerCurveConfig(nativeMod)
		ecc.PrecomputeLattice(cc.fr, nninputs[0], glvBasis)
		nnOutputs[0].Set(&(glvBasis.V1[0]))
		nnOutputs[1].Set(&(glvBasis.V1[1]))

		return nil
	})
}

func callHalfGCD(api frontend.API, s frontend.Variable) (s1, s2 frontend.Variable) {
	var fr emparams.BLS12377Fr
	sapi, err := emulated.NewField[emparams.BLS12377Fr](api)
	if err != nil {
		panic(err)
	}

	// compute the decomposition using a hint. We have to use the emulated
	// version which takes native input and outputs non-native outputs.
	//
	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + s * s2 == 0 mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := sapi.NewHintWithNativeInput(halfGCD, 2, s)
	if err != nil {
		panic(err)
	}
	// the scalar as nonnative element. We need to split at 64 bits.
	limbs, err := api.NewHint(decompose, int(fr.NbLimbs()), s)
	if err != nil {
		panic(err)
	}
	semu := sapi.NewElement(limbs)
	// s * s2 == -s1 mod r
	lhs := sapi.MulNoReduce(sd[1], semu)
	rhs := sapi.Neg(sd[0])

	sapi.AssertIsEqual(lhs, rhs)

	s1 = 0
	s2 = 0
	b := big.NewInt(1)
	for i := range sd[0].Limbs {
		s1 = api.Add(s1, api.Mul(sd[0].Limbs[i], b))
		s2 = api.Add(s2, api.Mul(sd[1].Limbs[i], b))
		b.Lsh(b, 64)
	}

	return s1, s2
}

func decompose(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 && len(outputs) != 4 {
		return fmt.Errorf("input/output length mismatch")
	}
	tmp := new(big.Int).Set(inputs[0])
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := 0; i < 4; i++ {
		outputs[i].And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
	return nil
}
