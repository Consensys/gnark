package sw

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/std/algebra/tower/fp24"
	"github.com/consensys/gnark/test"
)

type g2AffineInterfaceConstraint[T G2AffineConstraint] interface {
	*T
	SetRandom() (*T, error)
	Add(*T, *T) *T
	Set(*T) *T
}

type g2AddAssignAffine[T tower.Basis, PT tower.BasisPt[T]] struct {
	A, B G2Affine[T, PT]
	C    G2Affine[T, PT] `gnark:",public"`
}

func (circuit *g2AddAssignAffine[T, PT]) Define(api frontend.API) error {
	expected, err := NewG2Affine[T, PT](api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Set(circuit.A)
	expected.AddAssign(circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func testAddAssignAffineG2[T G2AffineConstraint, TT tower.Basis, PT g2AffineInterfaceConstraint[T], PTT tower.BasisPt[TT]](assert *test.Assert, curve ecc.ID) {
	var a, b, c T
	PT(&a).SetRandom()
	PT(&b).SetRandom()
	PT(&c).Add(&a, &b)
	circuit := &g2AddAssignAffine[TT, PTT]{}
	witness := &g2AddAssignAffine[TT, PTT]{
		A: FromG2Affine[TT, PTT](a),
		B: FromG2Affine[TT, PTT](b),
		C: FromG2Affine[TT, PTT](c),
	}
	assert.SolvingSucceeded(circuit, witness, test.WithCurves(curve))
}

func TestAddAssignAffineG2(t *testing.T) {
	assert := test.NewAssert(t)
	testAddAssignAffineG2[bls12377.G2Affine, fp2.E2](assert, ecc.BW6_761)
	testAddAssignAffineG2[bls24315.G2Affine, fp24.E4](assert, ecc.BW6_633)
}

type g2DoubleAndAddAffine[T tower.Basis, PT tower.BasisPt[T]] struct {
	A, B G2Affine[T, PT]
	C    G2Affine[T, PT] `gnark:",public"`
}

func (circuit *g2DoubleAndAddAffine[T, PT]) Define(api frontend.API) error {
	expected, err := NewG2Affine[T, PT](api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.DoubleAndAdd(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestDoubleAndAddAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	_b := randomPointG2()
	var a, b, c bls12377.G2Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g2DoubleAndAddAffine[fp2.E2, *fp2.E2]

	// assign the inputs
	witness.A = FromG2Affine[fp2.E2](a)
	witness.B = FromG2Affine[fp2.E2](b)

	// compute the result
	_a.Double(&_a).AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C = FromG2Affine[fp2.E2](c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type g2DoubleAffine[T tower.Basis, PT tower.BasisPt[T]] struct {
	A G2Affine[T, PT]
	C G2Affine[T, PT] `gnark:",public"`
}

func (circuit *g2DoubleAffine[T, PT]) Define(api frontend.API) error {
	expected, err := NewG2Affine[T, PT](api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Double(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestDoubleAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	var a, c bls12377.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2DoubleAffine[fp2.E2, *fp2.E2]

	// assign the inputs
	witness.A = FromG2Affine[fp2.E2](a)

	// compute the result
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C = FromG2Affine[fp2.E2](c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

func randomPointG2() bls12377.G2Jac {
	_, p2, _, _ := bls12377.Generators()

	var r1 fr.Element
	var b big.Int
	r1.SetRandom()
	p2.ScalarMultiplication(&p2, r1.ToBigIntRegular(&b))
	return p2
}

func BenchmarkDoubleAffineG2(b *testing.B) {
	var c g2DoubleAffine[fp2.E2, *fp2.E2]
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_761, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkAddAssignAffineG2(b *testing.B) {
	var c g2AddAssignAffine[fp2.E2, *fp2.E2]
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_761, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkDoubleAndAddAffineG2(b *testing.B) {
	var c g2DoubleAndAddAffine[fp2.E2, *fp2.E2]
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_761, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}
