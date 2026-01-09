package fieldextension

import (
	"testing"

	fr "github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type kbE2AddTestCircuit struct {
	A, B, C e2
}

func (c *kbE2AddTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.Add(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2Add(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetRandom(); err != nil {
		t.Fatal(err)
	}
	c.Add(&a, &b)

	assert.CheckCircuit(
		&kbE2AddTestCircuit{},
		test.WithValidAssignment(&kbE2AddTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: e2{A0: b.A0, A1: b.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbE2SubTestCircuit struct {
	A, B, C e2
}

func (c *kbE2SubTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.Sub(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2Sub(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetRandom(); err != nil {
		t.Fatal(err)
	}
	c.Sub(&a, &b)

	assert.CheckCircuit(
		&kbE2SubTestCircuit{},
		test.WithValidAssignment(&kbE2SubTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: e2{A0: b.A0, A1: b.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbE2MulTestCircuit struct {
	A, B, C e2
}

func (c *kbE2MulTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.Mul(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2Mul(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetRandom(); err != nil {
		t.Fatal(err)
	}
	c.Mul(&a, &b)

	assert.CheckCircuit(
		&kbE2MulTestCircuit{},
		test.WithValidAssignment(&kbE2MulTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: e2{A0: b.A0, A1: b.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbE2MulByElementTestCircuit struct {
	A e2
	B frontend.Variable
	C e2
}

func (c *kbE2MulByElementTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.MulByElement(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2MulByElement(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E2
	var b fr.Element
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetRandom(); err != nil {
		t.Fatal(err)
	}
	c.MulByElement(&a, &b)

	assert.CheckCircuit(
		&kbE2MulByElementTestCircuit{},
		test.WithValidAssignment(&kbE2MulByElementTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: b,
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbE2MulByNonResidueTestCircuit struct {
	A, C e2
}

func (c *kbE2MulByNonResidueTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.MulByNonResidue(c.A)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2MulByNonResidue(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E2
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	c.MulByNonResidue(&a)

	assert.CheckCircuit(
		&kbE2MulByNonResidueTestCircuit{},
		test.WithValidAssignment(&kbE2MulByNonResidueTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbE2InverseTestCircuit struct {
	A, AInv e2
}

func (c *kbE2InverseTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	invA := ext2.Inverse(c.A)
	api.AssertIsEqual(invA.A0, c.AInv.A0)
	api.AssertIsEqual(invA.A1, c.AInv.A1)
	return nil
}

func TestKoalabearExt2Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	var a, aInv extensions.E2
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if a.IsZero() {
		a.SetOne()
	}
	aInv.Inverse(&a)

	assert.CheckCircuit(
		&kbE2InverseTestCircuit{},
		test.WithValidAssignment(&kbE2InverseTestCircuit{
			A:    e2{A0: a.A0, A1: a.A1},
			AInv: e2{A0: aInv.A0, A1: aInv.A1},
		}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbExt4AddTestCircuit struct {
	A, B, C Element
}

func (c *kbExt4AddTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	addRes := ext4.Add(c.A, c.B)
	ext4.AssertIsEqual(addRes, c.C)

	return nil
}

func TestKoalabearExt4Add(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.MustSetRandom()
	b.MustSetRandom()
	c.Add(&a, &b)

	assert.CheckCircuit(
		&kbExt4AddTestCircuit{},
		test.WithValidAssignment(&kbExt4AddTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbExt4SubTestCircuit struct {
	A, B, C Element
}

func (c *kbExt4SubTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	subRes := ext4.Sub(c.A, c.B)
	ext4.AssertIsEqual(subRes, c.C)

	return nil
}

func TestKoalabearExt4Sub(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.MustSetRandom()
	b.MustSetRandom()
	c.Sub(&a, &b)

	assert.CheckCircuit(
		&kbExt4SubTestCircuit{},
		test.WithValidAssignment(&kbExt4SubTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbExt4MulByElementTestCircuit struct {
	A Element
	B frontend.Variable
	C Element
}

func (c *kbExt4MulByElementTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	mulRes := ext4.MulByElement(c.A, c.B)
	ext4.AssertIsEqual(mulRes, c.C)

	return nil
}

func TestKoalabearExt4MulByElement(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E4
	var b fr.Element
	a.MustSetRandom()
	if _, err := b.SetRandom(); err != nil {
		t.Fatal(err)
	}
	c.MulByElement(&a, &b)

	assert.CheckCircuit(
		&kbExt4MulByElementTestCircuit{},
		test.WithValidAssignment(&kbExt4MulByElementTestCircuit{A: ValueOf(a), B: b, C: ValueOf(c)}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbMulTestCircuit struct {
	A, B, C Element
}

func (c *kbMulTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	mulRes := ext4.Mul(c.A, c.B)
	ext4.AssertIsEqual(mulRes, c.C)

	return nil
}

func TestKoalabearExt4Mul(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.MustSetRandom()
	b.MustSetRandom()
	c.Mul(&a, &b)

	assert.CheckCircuit(
		&kbMulTestCircuit{},
		test.WithValidAssignment(&kbMulTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}

type kbInverseTestCircuit struct {
	A, AInv Element
}

func (c *kbInverseTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	invA := ext4.Inverse(c.A)
	ext4.AssertIsEqual(invA, c.AInv)
	return nil
}
func TestKoalabearExt4Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	var a, aInv extensions.E4
	a.MustSetRandom()
	if a.IsZero() {
		a.SetOne()
	}
	aInv.Inverse(&a)

	assert.CheckCircuit(
		&kbInverseTestCircuit{},
		test.WithValidAssignment(&kbInverseTestCircuit{A: ValueOf(a), AInv: ValueOf(aInv)}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}
