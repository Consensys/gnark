package sw_bls24315

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG2,

		decomposeScalarG1SimpleEmulated,
		decompose,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func decomposeScalarG1SimpleEmulated(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nnMod *big.Int, nninputs, nnOutputs []*big.Int) error {
		if len(nninputs) != 1 {
			return fmt.Errorf("expecting one input")
		}
		if len(nnOutputs) != 2 {
			return fmt.Errorf("expecting three outputs")
		}
		cc := getInnerCurveConfig(nativeMod)
		sp := ecc.SplitScalar(nninputs[0], cc.glvBasis)
		nnOutputs[0].Set(&(sp[0]))
		nnOutputs[1].Set(&(sp[1]))

		return nil
	})
}

func callDecomposeScalarG1Simple(api frontend.API, s frontend.Variable) (s1, s2 frontend.Variable) {
	cc := getInnerCurveConfig(api.Compiler().Field())
	sapi, err := emulated.NewField[emparams.BLS24315Fr](api)
	if err != nil {
		panic(err)
	}
	// compute the decomposition using a hint. We have to use the emulated
	// version which takes native input and outputs non-native outputs.
	//
	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := sapi.NewHintWithNativeInput(decomposeScalarG1SimpleEmulated, 2, s)
	if err != nil {
		panic(err)
	}
	// lambda as nonnative element
	lambdaEmu := sapi.NewElement(cc.lambda)
	// the scalar as nonnative element. We need to split at 64 bits.
	limbs, err := api.NewHint(decompose, 4, s)
	if err != nil {
		panic(err)
	}
	semu := sapi.NewElement(limbs)
	// s1 + λ * s2 == s mod r
	lhs := sapi.Mul(sd[1], lambdaEmu)
	lhs = sapi.Add(lhs, sd[0])

	sapi.AssertIsEqual(lhs, semu)

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

func decomposeScalarG1(scalarField *big.Int, inputs []*big.Int, res []*big.Int) error {
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	res[0].Set(&(sp[0]))
	res[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for res[0].Cmp(cc.lambda) < 1 && res[1].Cmp(cc.lambda) < 1 {
		res[0].Add(res[0], cc.lambda)
		res[0].Add(res[0], one)
		res[1].Add(res[1], cc.lambda)
	}
	// figure out how many times we have overflowed
	res[2].Mul(res[1], cc.lambda).Add(res[2], res[0])
	res[2].Sub(res[2], inputs[0])
	res[2].Div(res[2], cc.fr)

	return nil
}

func decomposeScalarG2(scalarField *big.Int, inputs []*big.Int, res []*big.Int) error {
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	res[0].Set(&(sp[0]))
	res[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for res[0].Cmp(cc.lambda) < 1 && res[1].Cmp(cc.lambda) < 1 {
		res[0].Add(res[0], cc.lambda)
		res[0].Add(res[0], one)
		res[1].Add(res[1], cc.lambda)
	}
	// figure out how many times we have overflowed
	res[2].Mul(res[1], cc.lambda).Add(res[2], res[0])
	res[2].Sub(res[2], inputs[0])
	res[2].Div(res[2], cc.fr)

	return nil
}
