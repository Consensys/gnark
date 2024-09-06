package twistededwards

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
		decomposeScalar,
		decomposeScalarSigns,
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

func decomposeScalar(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nnMod *big.Int, nninputs, nnOutputs []*big.Int) error {
		if len(nninputs) != 1 {
			return fmt.Errorf("expecting one input")
		}
		if len(nnOutputs) != 2 {
			return fmt.Errorf("expecting two outputs")
		}
		var glv glvParams
		glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
		glv.order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		ecc.PrecomputeLattice(&glv.order, &glv.lambda, &glv.glvBasis)
		sp := ecc.SplitScalar(nninputs[0], &glv.glvBasis)
		nnOutputs[0].Set(&(sp[0]))
		nnOutputs[1].Set(&(sp[1]))

		if nnOutputs[1].Sign() == -1 {
			nnOutputs[1].Neg(nnOutputs[1])
		}

		return nil
	})
}

func decomposeScalarSigns(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 1 {
		return fmt.Errorf("expecting one output")
	}
	var glv glvParams
	glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
	glv.order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
	ecc.PrecomputeLattice(&glv.order, &glv.lambda, &glv.glvBasis)
	sp := ecc.SplitScalar(inputs[0], &glv.glvBasis)
	outputs[0].SetUint64(0)
	if sp[1].Sign() == -1 {
		outputs[0].SetUint64(1)
	}

	return nil
}

func callDecomposeScalar(api frontend.API, s frontend.Variable) (s1, s2, s3 frontend.Variable) {
	var fr emparams.BandersnatchFr
	var glv glvParams
	glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)

	sapi, err := emulated.NewField[emparams.BandersnatchFr](api)
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
	bit, err := api.NewHint(decomposeScalarSigns, 1, s)
	if err != nil {
		panic(err)
	}
	// lambda as nonnative element
	lambdaEmu := sapi.NewElement(glv.lambda)
	// the scalar as nonnative element. We need to split at 64 bits.
	limbs, err := api.NewHint(decompose, int(fr.NbLimbs()), s)
	if err != nil {
		panic(err)
	}
	semu := sapi.NewElement(limbs)
	// we negated s2 in decomposeScalar so we check instead:
	// 		s1 + λ * s2 == s mod r
	_s1 := sapi.Select(bit[0], sapi.Neg(sd[1]), sd[1])
	rhs := sapi.MulNoReduce(_s1, lambdaEmu)
	rhs = sapi.Add(rhs, sd[0])
	sapi.AssertIsEqual(rhs, semu)

	s1 = 0
	s2 = 0
	s3 = bit[0]
	b := big.NewInt(1)
	for i := range sd[0].Limbs {
		s1 = api.Add(s1, api.Mul(sd[0].Limbs[i], b))
		s2 = api.Add(s2, api.Mul(sd[1].Limbs[i], b))
		b.Lsh(b, 64)
	}
	return s1, s2, s3
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
