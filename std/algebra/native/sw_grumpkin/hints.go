package sw_grumpkin

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
		decompose,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
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
		nnOutputs[1].Neg(&(sp[1]))

		return nil
	})
}

func callDecomposeScalar(api frontend.API, s frontend.Variable, simple bool) (s1, s2 frontend.Variable) {
	cc := getInnerCurveConfig(api.Compiler().Field())
	sapi, err := emulated.NewField[emparams.GrumpkinFr](api)
	if err != nil {
		panic(err)
	}
	// compute the decomposition using a hint. We have to use the emulated
	// version which takes native input and outputs non-native outputs.
	//
	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := sapi.NewHintWithNativeInput(decomposeScalar, 2, s)
	if err != nil {
		panic(err)
	}
	// lambda as nonnative element
	lambdaEmu := sapi.NewElement(cc.lambda)
	// the scalar as nonnative element. We need to split at 64 bits.
	nbLimbs, _ := emulated.GetEffectiveFieldParams[emparams.BLS24315Fr](api.Compiler().Field())
	limbs, err := api.NewHint(decompose, int(nbLimbs), s)
	if err != nil {
		panic(err)
	}
	semu := sapi.NewElement(limbs)
	// s1 + λ * s2 == s mod r
	lhs := sapi.MulNoReduce(sd[1], lambdaEmu)
	lhs = sapi.Sub(sd[0], lhs)

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
	nbLimbs, nbBits := emulated.GetEffectiveFieldParams[emparams.BLS24315Fr](mod)
	if uint(len(outputs)) != nbLimbs {
		return errors.New("output length mismatch")
	}
	if len(inputs) != 1 {
		return errors.New("input/output length mismatch")
	}
	tmp := new(big.Int).Set(inputs[0])
	mask := new(big.Int).Lsh(big.NewInt(1), nbBits)
	mask.Sub(mask, big.NewInt(1))
	for i := range nbLimbs {
		outputs[i].And(tmp, mask)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}
