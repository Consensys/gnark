package sw_bls12381

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type mulG2Circuit struct {
	In, Res G2Affine
	S       Scalar
}

func (c *mulG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res1 := g2.scalarMulGLV(&c.In, &c.S)
	res2 := g2.scalarMulGeneric(&c.In, &c.S)
	g2.AssertIsEqual(res1, &c.Res)
	g2.AssertIsEqual(res2, &c.Res)
	return nil
}

func TestScalarMulG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	var r fr_bls12381.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var res bls12381.G2Affine
	_, _, _, gen := bls12381.Generators()
	res.ScalarMultiplication(&gen, s)

	witness := mulG2Circuit{
		In:  NewG2Affine(gen),
		S:   NewScalar(r),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&mulG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type addG2Circuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *addG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.add(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Add(&in1, &in2)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type doubleG2Circuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *doubleG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.double(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	var in1Jac, resJac bls12381.G2Jac
	in1Jac.FromAffine(&in1)
	resJac.Double(&in1Jac)
	res.FromJacobian(&resJac)
	witness := doubleG2Circuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&doubleG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type doubleAndAddG2Circuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *doubleAndAddG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.doubleAndAdd(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleAndAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Double(&in1).
		Add(&res, &in2)
	witness := doubleAndAddG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&doubleAndAddG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type scalarMulG2BySeedCircuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *scalarMulG2BySeedCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.scalarMulBySeed(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2BySeedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	x0, _ := new(big.Int).SetString("15132376222941642752", 10)
	res.ScalarMultiplication(&in1, x0).Neg(&res)
	witness := scalarMulG2BySeedCircuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2BySeedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiScalarMulTest struct {
	Points  []G2Affine
	Scalars []Scalar
	Res     G2Affine
}

func (c *MultiScalarMulTest) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	ps := make([]*G2Affine, len(c.Points))
	for i := range c.Points {
		ps[i] = &c.Points[i]
	}
	ss := make([]*Scalar, len(c.Scalars))
	for i := range c.Scalars {
		ss[i] = &c.Scalars[i]
	}
	res, err := g2.MultiScalarMul(ps, ss)
	if err != nil {
		return err
	}
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 4
	P := make([]bls12381.G2Affine, nbLen)
	S := make([]fr_bls12381.Element, nbLen)
	for i := 0; i < nbLen; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res bls12381.G2Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]G2Affine, len(P))
	for i := range cP {
		cP[i] = G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](P[i].X.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](P[i].X.A1)},
				Y: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](P[i].Y.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](P[i].Y.A1)},
			},
			Lines: nil,
		}
	}
	cS := make([]Scalar, len(S))
	for i := range cS {
		cS[i] = emulated.ValueOf[emulated.BLS12381Fr](S[i])
	}
	assignment := MultiScalarMulTest{
		Points:  cP,
		Scalars: cS,
		Res: G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](res.X.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](res.X.A1)},
				Y: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](res.Y.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](res.Y.A1)},
			},
			Lines: nil,
		},
	}
	err = test.IsSolved(&MultiScalarMulTest{
		Points:  make([]G2Affine, nbLen),
		Scalars: make([]Scalar, nbLen),
	}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MarshalG2Test struct {
	G G2Affine
	R []frontend.Variable
}

func (c *MarshalG2Test) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	br := g2.Marshal(c.G)
	for i := 0; i < len(c.R); i++ {
		api.AssertIsEqual(c.R[i], br[i])
	}
	return nil
}

func TestMarshalG2(t *testing.T) {
	assert := test.NewAssert(t)
	testFn := func(r fr_bls12381.Element) {
		var P bls12381.G2Affine
		P.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
		gBytes := P.Marshal()
		nbBytes := 4 * fp_bls12381.Bytes
		nbBits := nbBytes * 8
		circuit := &MarshalG2Test{
			R: make([]frontend.Variable, nbBits),
		}
		witness := &MarshalG2Test{
			G: G2Affine{
				P: g2AffP{
					X: fields_bls12381.E2{
						A0: emulated.ValueOf[emulated.BLS12381Fp](P.X.A0),
						A1: emulated.ValueOf[emulated.BLS12381Fp](P.X.A1),
					},
					Y: fields_bls12381.E2{
						A0: emulated.ValueOf[emulated.BLS12381Fp](P.Y.A0),
						A1: emulated.ValueOf[emulated.BLS12381Fp](P.Y.A1),
					},
				},
			},
			R: make([]frontend.Variable, nbBits),
		}
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				witness.R[i*8+j] = (gBytes[i] >> (7 - j)) & 1
			}
		}
		err := test.IsSolved(circuit, witness, bls12381.ID.ScalarField())
		assert.NoError(err)
	}
	assert.Run(func(assert *test.Assert) {
		var r fr_bls12381.Element
		r.SetRandom()
		testFn(r)
	})
	assert.Run(func(assert *test.Assert) {
		var r fr_bls12381.Element
		r.SetZero()
		testFn(r)
	})
}

type UnmarshalG2Test struct {
	G G2Affine
	R []frontend.Variable
}

func (c *UnmarshalG2Test) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	p, err := g2.Unmarshal(c.R)
	if err != nil {
		return fmt.Errorf("unmarshal G2: %w", err)
	}
	g2.AssertIsEqual(&c.G, p)
	return nil
}

func TestUnmarshalG2(t *testing.T) {
	assert := test.NewAssert(t)
	testFn := func(r fr_bls12381.Element) {
		var P bls12381.G2Affine
		P.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
		gBytes := P.Marshal()
		nbBytes := 4 * fp_bls12381.Bytes
		nbBits := nbBytes * 8
		circuit := &MarshalG2Test{
			R: make([]frontend.Variable, nbBits),
		}
		witness := &MarshalG2Test{
			G: G2Affine{
				P: g2AffP{
					X: fields_bls12381.E2{
						A0: emulated.ValueOf[emulated.BLS12381Fp](P.X.A0),
						A1: emulated.ValueOf[emulated.BLS12381Fp](P.X.A1),
					},
					Y: fields_bls12381.E2{
						A0: emulated.ValueOf[emulated.BLS12381Fp](P.Y.A0),
						A1: emulated.ValueOf[emulated.BLS12381Fp](P.Y.A1),
					},
				},
			},
			R: make([]frontend.Variable, nbBits),
		}
		for i := 0; i < nbBytes; i++ {
			for j := 0; j < 8; j++ {
				witness.R[i*8+j] = (gBytes[i] >> (7 - j)) & 1
			}
		}
		err := test.IsSolved(circuit, witness, bls12381.ID.ScalarField())
		assert.NoError(err)
	}
	assert.Run(func(assert *test.Assert) {
		var r fr_bls12381.Element
		r.SetRandom()
		testFn(r)
	})
	assert.Run(func(assert *test.Assert) {
		var r fr_bls12381.Element
		r.SetZero()
		testFn(r)
	})
}

type ToBytesG2Test struct {
	P               G2Affine
	CompressedPoint []uints.U8
}

func (c *ToBytesG2Test) Define(api frontend.API) error {
	g, err := NewG2(api)
	if err != nil {
		return err
	}
	bytes, err := g.ToCompressedBytes(c.P)
	if err != nil {
		return err
	}
	for i := 0; i < len(c.CompressedPoint); i++ {
		api.AssertIsEqual(c.CompressedPoint[i].Val, bytes[i].Val)
	}
	return nil
}

func TestToBytesG2(t *testing.T) {
	assert := test.NewAssert(t)
	{
		_, _, _, p := bls12381.Generators()
		var r fr_bls12381.Element
		r.SetRandom()
		p.ScalarMultiplication(&p, r.BigInt(new(big.Int)))
		pMarshalled := p.Bytes()
		var witness, circuit ToBytesG2Test
		nbBytes := 2 * fp_bls12381.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.P = G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{
					A0: emulated.ValueOf[emulated.BLS12381Fp](p.X.A0),
					A1: emulated.ValueOf[emulated.BLS12381Fp](p.X.A1),
				},
				Y: fields_bls12381.E2{
					A0: emulated.ValueOf[emulated.BLS12381Fp](p.Y.A0),
					A1: emulated.ValueOf[emulated.BLS12381Fp](p.Y.A1),
				},
			},
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
	// infinity
	{
		var witness, circuit ToBytesG2Test
		nbBytes := 2 * fp_bls12381.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		var p bls12381.G2Affine
		p.X.SetZero()
		p.Y.SetZero()
		pMarshalled := p.Bytes()
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.P = G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{
					A0: emulated.ValueOf[emulated.BLS12381Fp](p.X.A0),
					A1: emulated.ValueOf[emulated.BLS12381Fp](p.X.A1),
				},
				Y: fields_bls12381.E2{
					A0: emulated.ValueOf[emulated.BLS12381Fp](p.Y.A0),
					A1: emulated.ValueOf[emulated.BLS12381Fp](p.Y.A1),
				},
			},
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type FromBytesG2Test struct {
	CompressedPoint []uints.U8
	XA0             emulated.Element[BaseField]
	XA1             emulated.Element[BaseField]
	YA0             emulated.Element[BaseField]
	YA1             emulated.Element[BaseField]
}

func (c *FromBytesG2Test) Define(api frontend.API) error {
	g, err := NewG2(api)
	if err != nil {
		return err
	}
	point, err := g.FromCompressedBytes(c.CompressedPoint)
	if err != nil {
		return err
	}
	g.Ext2.AssertIsEqual(&point.P.X, &fields_bls12381.E2{A0: c.XA0, A1: c.XA1})
	g.Ext2.AssertIsEqual(&point.P.Y, &fields_bls12381.E2{A0: c.YA0, A1: c.YA1})
	return nil
}

func TestFromBytesG2(t *testing.T) {
	assert := test.NewAssert(t)
	{
		_, _, _, p := bls12381.Generators()
		var r fr_bls12381.Element
		r.SetRandom()
		p.ScalarMultiplication(&p, r.BigInt(new(big.Int)))
		pMarshalled := p.Bytes()
		var witness, circuit FromBytesG2Test
		nbBytes := 2 * fp_bls12381.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.XA0 = emulated.ValueOf[BaseField](p.X.A0)
		witness.XA1 = emulated.ValueOf[BaseField](p.X.A1)
		witness.YA0 = emulated.ValueOf[BaseField](p.Y.A0)
		witness.YA1 = emulated.ValueOf[BaseField](p.Y.A1)

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
	// infinity
	{
		var witness, circuit FromBytesG2Test
		nbBytes := 2 * fp_bls12381.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		var p bls12381.G2Affine
		p.X.SetZero()
		p.Y.SetZero()
		pMarshalled := p.Bytes()
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.XA0 = emulated.ValueOf[BaseField](p.X.A0)
		witness.XA1 = emulated.ValueOf[BaseField](p.X.A1)
		witness.YA0 = emulated.ValueOf[BaseField](p.Y.A0)
		witness.YA1 = emulated.ValueOf[BaseField](p.Y.A1)

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}
