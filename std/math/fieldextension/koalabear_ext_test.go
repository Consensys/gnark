package fieldextension

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

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
	aInv.Inverse(&a)

	assert.CheckCircuit(
		&kbInverseTestCircuit{},
		test.WithValidAssignment(&kbInverseTestCircuit{A: ValueOf(a), AInv: ValueOf(aInv)}),
		test.WithNoCurves(),
		test.WithSmallfieldCheck())
}
