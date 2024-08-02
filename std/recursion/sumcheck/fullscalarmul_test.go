package sumcheck

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr_secp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type ScalarMulCircuit[Base, Scalars emulated.FieldParams] struct {
	Points  []sw_emulated.AffinePoint[Base]
	Scalars []emulated.Element[Scalars]

	nbScalarBits int
}

func (c *ScalarMulCircuit[B, S]) Define(api frontend.API) error {
	if len(c.Points) != len(c.Scalars) {
		return fmt.Errorf("len(inputs) != len(scalars)")
	}
	baseApi, err := emulated.NewField[B](api)
	if err != nil {
		return fmt.Errorf("new base field: %w", err)
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		return fmt.Errorf("new scalar field: %w", err)
	}
	for i := range c.Points {
		step, err := callHintScalarMulSteps[B, S](api, baseApi, scalarApi, c.nbScalarBits, c.Points[i], c.Scalars[i])
		if err != nil {
			return fmt.Errorf("hint scalar mul steps: %w", err)
		}
		_ = step
	}
	return nil
}

func callHintScalarMulSteps[B, S emulated.FieldParams](api frontend.API,
	baseApi *emulated.Field[B], scalarApi *emulated.Field[S],
	nbScalarBits int,
	point sw_emulated.AffinePoint[B], scalar emulated.Element[S]) ([][6]*emulated.Element[B], error) {
	var fp B
	var fr S
	inputs := []frontend.Variable{fp.BitsPerLimb(), fp.NbLimbs()}
	inputs = append(inputs, baseApi.Modulus().Limbs...)
	inputs = append(inputs, point.X.Limbs...)
	inputs = append(inputs, point.Y.Limbs...)
	inputs = append(inputs, fr.BitsPerLimb(), fr.NbLimbs())
	inputs = append(inputs, scalarApi.Modulus().Limbs...)
	inputs = append(inputs, scalar.Limbs...)
	nbRes := nbScalarBits * int(fp.NbLimbs()) * 6
	hintRes, err := api.Compiler().NewHint(hintScalarMulSteps, nbRes, inputs...)
	if err != nil {
		return nil, fmt.Errorf("new hint: %w", err)
	}
	res := make([][6]*emulated.Element[B], nbScalarBits)
	for i := range res {
		for j := 0; j < 6; j++ {
			limbs := hintRes[i*(6*int(fp.NbLimbs()))+j*int(fp.NbLimbs()) : i*(6*int(fp.NbLimbs()))+(j+1)*int(fp.NbLimbs())]
			res[i][j] = baseApi.NewElement(limbs)
		}
	}
	return res, nil
}

func hintScalarMulSteps(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	fpLimbs := inputs[2 : 2+nbLimbs]
	xLimbs := inputs[2+nbLimbs : 2+2*nbLimbs]
	yLimbs := inputs[2+2*nbLimbs : 2+3*nbLimbs]
	nbScalarBits := int(inputs[2+3*nbLimbs].Int64())
	nbScalarLimbs := int(inputs[3+3*nbLimbs].Int64())
	frLimbs := inputs[4+3*nbLimbs : 4+3*nbLimbs+nbScalarLimbs]
	scalarLimbs := inputs[4+3*nbLimbs+nbScalarLimbs : 4+3*nbLimbs+2*nbScalarLimbs]

	x := new(big.Int)
	y := new(big.Int)
	fp := new(big.Int)
	fr := new(big.Int)
	scalar := new(big.Int)
	if err := recompose(fpLimbs, uint(nbBits), fp); err != nil {
		return fmt.Errorf("recompose fp: %w", err)
	}
	if err := recompose(frLimbs, uint(nbScalarBits), fr); err != nil {
		return fmt.Errorf("recompose fr: %w", err)
	}
	if err := recompose(xLimbs, uint(nbBits), x); err != nil {
		return fmt.Errorf("recompose x: %w", err)
	}
	if err := recompose(yLimbs, uint(nbBits), y); err != nil {
		return fmt.Errorf("recompose y: %w", err)
	}
	if err := recompose(scalarLimbs, uint(nbScalarBits), scalar); err != nil {
		return fmt.Errorf("recompose scalar: %w", err)
	}
	fmt.Println(fp, fr, x, y, scalar)

	scalarLength := len(outputs) / (6 * nbLimbs)
	println("scalarLength", scalarLength)
	return nil
}

func recompose(inputs []*big.Int, nbBits uint, res *big.Int) error {
	if len(inputs) == 0 {
		return fmt.Errorf("zero length slice input")
	}
	if res == nil {
		return fmt.Errorf("result not initialized")
	}
	res.SetUint64(0)
	for i := range inputs {
		res.Lsh(res, nbBits)
		res.Add(res, inputs[len(inputs)-i-1])
	}
	// TODO @gbotrel mod reduce ?
	return nil
}

func decompose(input *big.Int, nbBits uint, res []*big.Int) error {
	// limb modulus
	if input.BitLen() > len(res)*int(nbBits) {
		return fmt.Errorf("decomposed integer does not fit into res")
	}
	for _, r := range res {
		if r == nil {
			return fmt.Errorf("result slice element uninitalized")
		}
	}
	base := new(big.Int).Lsh(big.NewInt(1), nbBits)
	tmp := new(big.Int).Set(input)
	for i := 0; i < len(res); i++ {
		res[i].Mod(tmp, base)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}

func TestScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	type B = emparams.Secp256k1Fp
	type S = emparams.Secp256k1Fr
	t.Log(B{}.Modulus(), S{}.Modulus())
	var P secp256k1.G1Affine
	var s fr_secp256k1.Element
	nbInputs := 1 << 0
	nbScalarBits := 2
	scalarBound := new(big.Int).Lsh(big.NewInt(1), uint(nbScalarBits))
	points := make([]sw_emulated.AffinePoint[B], nbInputs)
	scalars := make([]emulated.Element[S], nbInputs)
	for i := range points {
		s.SetRandom()
		P.ScalarMultiplicationBase(s.BigInt(new(big.Int)))
		sc, _ := rand.Int(rand.Reader, scalarBound)
		t.Log(P.X.String(), P.Y.String(), sc.String())
		points[i] = sw_emulated.AffinePoint[B]{
			X: emulated.ValueOf[B](P.X),
			Y: emulated.ValueOf[B](P.Y),
		}
		scalars[i] = emulated.ValueOf[S](sc)
	}
	circuit := ScalarMulCircuit[B, S]{
		Points:       make([]sw_emulated.AffinePoint[B], nbInputs),
		Scalars:      make([]emulated.Element[S], nbInputs),
		nbScalarBits: nbScalarBits,
	}
	witness := ScalarMulCircuit[B, S]{
		Points:  points,
		Scalars: scalars,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}