package fp2

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	bls24315fp "github.com/consensys/gnark-crypto/ecc/bls24-315/fp"
	bw6633fr "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TODO: this is used only for test - move it out to test and make interfaces
// simpler simpler
type e2InterfaceConstraint[T E2Constraint] interface {
	*T
	Add(*T, *T) *T
	SetRandom() (*T, error)
}

// for everything add BW6-761/bls12-377

type e2Add struct {
	A, B, C E2
}

func (circuit *e2Add) Define(api frontend.API) error {
	expected, err := New(api)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	expected.Add(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func testAddFp2[F E2Constraint, Pt e2InterfaceConstraint[F]](assert *test.Assert, curve ecc.ID) {
	var a, b, c F
	pa, pb, pc := Pt(&a), Pt(&b), Pt(&c)
	pa.SetRandom()
	pb.SetRandom()
	pc.Add(&a, &b)

	var witness e2Add
	witness.A = From(a)
	witness.B = From(b)
	witness.C = From(c)

	assert.SolvingSucceeded(&e2Add{}, &witness, test.WithCurves(curve))
}

func TestAddFp2(t *testing.T) {
	assert := test.NewAssert(t)
	testAddFp2[bls24315.E2](assert, ecc.BW6_633)
	testAddFp2[bls12377.E2](assert, ecc.BW6_761)
}

type e2Sub struct {
	A, B, C E2
}

func (circuit *e2Sub) Define(api frontend.API) error {
	expected, err := New(api)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	expected.Sub(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	// witness values
	var a, b, c bls24315.E2
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	var witness e2Sub
	witness.A = From(a)
	witness.B = From(b)
	witness.C = From(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Sub{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e2Square struct {
	A, C E2
}

func (circuit *e2Square) Define(api frontend.API) error {
	expected, err := New(api)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	expected.Square(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestSquareFp2(t *testing.T) {

	// witness values
	var a, c bls24315.E2
	a.SetRandom()
	c.Square(&a)

	var witness e2Square
	witness.A = From(a)
	witness.C = From(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Square{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e2Mul struct {
	A, B, C E2
}

func (circuit *e2Mul) Define(api frontend.API) error {
	expected, err := New(api)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	expected.Mul(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	// witness values
	var a, b, c bls24315.E2
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	var witness e2Mul
	witness.A = From(a)
	witness.B = From(b)
	witness.C = From(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Mul{}, &witness, test.WithCurves(ecc.BW6_633))

}

type fp2MulByFp struct {
	A E2
	B frontend.Variable
	C E2 `gnark:",public"`
}

func (circuit *fp2MulByFp) Define(api frontend.API) error {
	expected, err := New(api)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	expected.MulByFp(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestMulByFpFp2(t *testing.T) {

	var circuit, witness fp2MulByFp

	// witness values
	var a, c bls24315.E2
	var b bls24315fp.Element
	a.SetRandom()
	b.SetRandom()
	c.MulByElement(&a, &b)

	witness.B = (bw6633fr.Element)(b)
	witness.A = From(a)
	witness.C = From(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type fp2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Conjugate) Define(api frontend.API) error {
	expected, err := New(api)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	expected.Conjugate(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestConjugateFp2(t *testing.T) {

	var circuit, witness fp2Conjugate

	// witness values
	var a, c bls24315.E2
	a.SetRandom()
	c.Conjugate(&a)

	witness.A = From(a)
	witness.C = From(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Inverse) Define(api frontend.API) error {
	expected, err := New(api)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	expected.Inverse(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestInverseFp2(t *testing.T) {

	var circuit, witness fp2Inverse

	// witness values
	var a, c bls24315.E2
	a.SetRandom()
	c.Inverse(&a)

	witness.A = From(a)
	witness.C = From(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}
