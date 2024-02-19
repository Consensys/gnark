package sw_bls12377

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG2,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
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
