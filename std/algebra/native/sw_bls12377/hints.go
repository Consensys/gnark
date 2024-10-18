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

func halfGCDEisenstein(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("expecting two input")
	}
	if len(outputs) != 5 {
		return fmt.Errorf("expecting five outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(cc.fr, inputs[1], glvBasis)
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
	res := eisenstein.HalfGCD(&r, &s)
	outputs[0].Set(res[0].A0)
	outputs[1].Set(res[0].A1)
	outputs[2].Set(res[1].A0)
	outputs[3].Set(res[1].A1)
	outputs[4].Mul(res[1].A1, inputs[1]).
		Add(outputs[4], res[1].A0).
		Mul(outputs[4], inputs[0]).
		Add(outputs[4], res[0].A0)
	s.A0.Mul(res[0].A1, inputs[1])
	outputs[4].Add(outputs[4], s.A0).
		Div(outputs[4], cc.fr)

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

	return nil
}

func halfGCDEisensteinSigns(scalarField *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("expecting two input")
	}
	if len(outputs) != 5 {
		return fmt.Errorf("expecting five outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(cc.fr, inputs[1], glvBasis)
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
	res := eisenstein.HalfGCD(&r, &s)
	s.A1.Mul(res[1].A1, inputs[1]).
		Add(s.A1, res[1].A0).
		Mul(s.A1, inputs[0]).
		Add(s.A1, res[0].A0)
	s.A0.Mul(res[0].A1, inputs[1])
	s.A1.Add(s.A1, s.A0).
		Div(s.A1, cc.fr)

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
	if s.A1.Sign() == -1 {
		outputs[4].SetUint64(1)
	}
	return nil
}
