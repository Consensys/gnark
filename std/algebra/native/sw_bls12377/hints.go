package sw_bls12377

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/field/eisenstein"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG1Simple,
		decomposeScalarG2,
		scalarMulGLVG1Hint,
		halfGCDEisenstein,
		halfGCDEisensteinSigns,
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

func scalarMulGLVG1Hint(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("expecting three inputs")
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expecting two outputs")
	}

	// compute the resulting point [s]Q
	var P bls12377.G1Affine
	P.X.SetBigInt(inputs[0])
	P.Y.SetBigInt(inputs[1])
	P.ScalarMultiplication(&P, inputs[2])
	P.X.BigInt(outputs[0])
	P.Y.BigInt(outputs[1])
	return nil
}

func halfGCDEisenstein(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("expecting two input")
	}
	if len(outputs) != 10 {
		return fmt.Errorf("expecting ten outputs")
	}
	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(mod, inputs[1], glvBasis)
	r := eisenstein.ComplexNumber{
		A0: &glvBasis.V1[0],
		A1: &glvBasis.V1[1],
	}
	// r = 91893752504881257701523279626832445440 - ω
	sp := ecc.SplitScalar(inputs[0], glvBasis)
	// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
	// so here we return -s instead of s.
	// s.A0 and s.A1 are always positive.
	s := eisenstein.ComplexNumber{
		A0: &sp[0],
		A1: &sp[1],
	}
	s.Neg(&s)
	res := eisenstein.HalfGCD(&r, &s)
	outputs[0].Set(res[0].A0)
	outputs[1].Set(res[0].A1)
	outputs[2].Set(res[1].A0)
	outputs[3].Set(res[1].A1)
	outputs[4].Set(res[2].A0)
	outputs[5].Set(res[2].A1)
	outputs[6].Set(r.A0)
	outputs[7].Set(r.A1)
	outputs[8].Set(s.A0)
	outputs[9].Set(s.A1)
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
	if outputs[6].Sign() == -1 {
		outputs[6].Neg(outputs[6])
	}
	if outputs[7].Sign() == -1 {
		outputs[7].Neg(outputs[7])
	}
	if outputs[8].Sign() == -1 {
		outputs[8].Neg(outputs[8])
	}
	if outputs[9].Sign() == -1 {
		outputs[9].Neg(outputs[9])
	}
	return nil
}

func halfGCDEisensteinSigns(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("expecting two input")
	}
	if len(outputs) != 6 {
		return fmt.Errorf("expecting six outputs")
	}
	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(mod, inputs[1], glvBasis)
	// r = 91893752504881257701523279626832445440 - ω
	r := eisenstein.ComplexNumber{
		A0: &glvBasis.V1[0],
		A1: &glvBasis.V1[1],
	}
	sp := ecc.SplitScalar(inputs[0], glvBasis)
	// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
	// so here we return -s instead of s.
	s := eisenstein.ComplexNumber{
		A0: &sp[0],
		A1: &sp[1],
	}
	s.Neg(&s)

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
}
