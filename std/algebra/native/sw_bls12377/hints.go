package sw_bls12377

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG1Simple,
		decomposeScalarG2,
		halfGCD,
		scalarMulG1Hint,
		scalarMulG2Hint,
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

func scalarMulG1Hint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
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

func scalarMulG2Hint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 5 {
		return fmt.Errorf("expecting five inputs")
	}
	if len(outputs) != 4 {
		return fmt.Errorf("expecting four outputs")
	}

	// compute the resulting point [s]Q
	var R bls12377.G2Affine
	R.X.A0.SetBigInt(inputs[0])
	R.X.A1.SetBigInt(inputs[1])
	R.Y.A0.SetBigInt(inputs[2])
	R.Y.A1.SetBigInt(inputs[3])
	R.ScalarMultiplication(&R, inputs[4])

	R.X.A0.BigInt(outputs[0])
	R.X.A1.BigInt(outputs[1])
	R.Y.A0.BigInt(outputs[2])
	R.Y.A1.BigInt(outputs[3])

	return nil
}

func halfGCD(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expecting two outputs")
	}
	var v0, v1 big.Int
	cc := getInnerCurveConfig(nativeMod)
	ecc.HalfGCD(cc.fr, inputs[0], &v0, &v1)
	outputs[0].Set(&v0)
	outputs[1].Set(&v1)

	return nil
}
