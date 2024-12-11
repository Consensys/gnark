package sw_bls24315

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalar,
		decomposeScalarSimple,
		decompose,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func decomposeScalarSimple(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nnMod *big.Int, nninputs, nnOutputs []*big.Int) error {
		if len(nninputs) != 1 {
			return errors.New("expecting one input")
		}
		if len(nnOutputs) != 2 {
			return errors.New("expecting two outputs")
		}
		cc := getInnerCurveConfig(nativeMod)
		sp := ecc.SplitScalar(nninputs[0], cc.glvBasis)
		nnOutputs[0].Set(&(sp[0]))
		nnOutputs[1].Set(&(sp[1]))

		return nil
	})
}

func decomposeScalar(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nnMod *big.Int, nninputs, nnOutputs []*big.Int) error {
		if len(nninputs) != 1 {
			return errors.New("expecting one input")
		}
		if len(nnOutputs) != 2 {
			return errors.New("expecting two outputs")
		}
		cc := getInnerCurveConfig(nativeMod)
		sp := ecc.SplitScalar(nninputs[0], cc.glvBasis)
		nnOutputs[0].Set(&(sp[0]))
		nnOutputs[1].Set(&(sp[1]))
		one := big.NewInt(1)
		// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
		// the high bits are set in decomposition.
		for nnOutputs[0].Cmp(cc.lambda) < 1 && nnOutputs[1].Cmp(cc.lambda) < 1 {
			nnOutputs[0].Add(nnOutputs[0], cc.lambda)
			nnOutputs[0].Add(nnOutputs[0], one)
			nnOutputs[1].Add(nnOutputs[1], cc.lambda)
		}

		return nil
	})
}

func callDecomposeScalar(api frontend.API, s frontend.Variable, simple bool) (s1, s2 frontend.Variable) {
	var fr emparams.BLS24315Fr
	cc := getInnerCurveConfig(api.Compiler().Field())
	sapi, err := emulated.NewField[emparams.BLS24315Fr](api)
	if err != nil {
		panic(err)
	}
	var hintFn solver.Hint
	if simple {
		hintFn = decomposeScalarSimple
	} else {
		hintFn = decomposeScalar
	}
	// compute the decomposition using a hint. We have to use the emulated
	// version which takes native input and outputs non-native outputs.
	//
	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := sapi.NewHintWithNativeInput(hintFn, 2, s)
	if err != nil {
		panic(err)
	}
	// lambda as nonnative element
	lambdaEmu := sapi.NewElement(cc.lambda)
	// the scalar as nonnative element. We need to split at 64 bits.
	limbs, err := api.NewHint(decompose, int(fr.NbLimbs()), s)
	if err != nil {
		panic(err)
	}
	semu := sapi.NewElement(limbs)
	// s1 + λ * s2 == s mod r
	lhs := sapi.MulNoReduce(sd[1], lambdaEmu)
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
