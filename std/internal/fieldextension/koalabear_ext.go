package fieldextension

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
)

// e2 is a quadratic extension over the base field
type e2 struct {
	A0, A1 frontend.Variable
}

// e4 is a quadratic extension over e2
type e4 struct {
	B0, B1 e2
}

// flattenE4 flattens an e4 element into a slice of frontend.Variable. It is
// used in the fieldextension package and we want to have compatibility.
func flattenE4(e e4) []frontend.Variable {
	return []frontend.Variable{e.B0.A0, e.B0.A1, e.B1.A0, e.B1.A1}
}

func unflattenE4(vars []frontend.Variable) e4 {
	if len(vars) > 4 {
		panic("unflattenE4: expected at most 4 variables")
	}
	// we init as constant values
	var b0a0, b0a1, b1a0, b1a1 frontend.Variable = 0, 0, 0, 0
	switch len(vars) {
	case 4:
		b1a1 = vars[3]
		fallthrough
	case 3:
		b1a0 = vars[2]
		fallthrough
	case 2:
		b0a1 = vars[1]
		fallthrough
	case 1:
		b0a0 = vars[0]
	}
	return e4{
		B0: e2{
			A0: b0a0,
			A1: b0a1,
		},
		B1: e2{
			A0: b1a0,
			A1: b1a1,
		},
	}
}

type koalabearExt2 struct {
	api   frontend.API
	qnrE2 koalabear.Element
}

type koalabearExt4 struct {
	api  frontend.API
	ext2 *koalabearExt2
}

func newKoalabearExt2(api frontend.API) *koalabearExt2 {
	u := koalabear.NewElement(3)
	return &koalabearExt2{api: api, qnrE2: u}
}

func newKoalabearExt4(api frontend.API) *koalabearExt4 {
	ext2 := newKoalabearExt2(api)
	return &koalabearExt4{api: api, ext2: ext2}
}

func (ext2 *koalabearExt2) Add(a, b e2) e2 {
	a0 := ext2.api.Add(a.A0, b.A0)
	a1 := ext2.api.Add(a.A1, b.A1)
	return e2{A0: a0, A1: a1}
}

func (ext2 *koalabearExt2) Mul(a, b e2) e2 {
	l1 := ext2.api.Add(a.A0, a.A1)
	l2 := ext2.api.Add(b.A0, b.A1)

	u := ext2.api.Mul(l1, l2)
	ac := ext2.api.Mul(a.A0, b.A0)
	bd := ext2.api.Mul(a.A1, b.A1)

	l31 := ext2.api.Add(ac, bd)
	a1 := ext2.api.Sub(u, l31)

	l41 := ext2.api.Mul(bd, ext2.qnrE2)
	a0 := ext2.api.Add(ac, l41)

	return e2{A0: a0, A1: a1}
}

func (ext2 *koalabearExt2) MulByElement(a e2, b frontend.Variable) e2 {
	a0 := ext2.api.Mul(a.A0, b)
	a1 := ext2.api.Mul(a.A1, b)
	return e2{A0: a0, A1: a1}
}

func (ext2 *koalabearExt2) MulByNonResidue(a e2) e2 {
	a0 := ext2.api.Mul(a.A1, ext2.qnrE2)
	a1 := a.A0
	return e2{A0: a0, A1: a1}
}

func (ext2 *koalabearExt2) Sub(a, b e2) e2 {
	a0 := ext2.api.Sub(a.A0, b.A0)
	a1 := ext2.api.Sub(a.A1, b.A1)
	return e2{A0: a0, A1: a1}
}

func (ext2 *koalabearExt2) Inverse(a e2) e2 {
	res, err := ext2.api.Compiler().NewHint(inverseE2Hint, 2, a.A0, a.A1)
	if err != nil {
		panic(err)
	}
	resE2 := e2{
		A0: res[0],
		A1: res[1],
	}
	prod := ext2.Mul(a, resE2)
	ext2.api.AssertIsEqual(prod.A0, 1)
	ext2.api.AssertIsEqual(prod.A1, 0)
	return resE2
}

func (ext4 *koalabearExt4) Reduce(a Element) Element {
	return a
}

func (ext4 *koalabearExt4) Mul(a Element, b Element) Element {
	ma, mb := unflattenE4(a), unflattenE4(b)
	l1 := ext4.ext2.Add(ma.B0, ma.B1)
	l2 := ext4.ext2.Add(mb.B0, mb.B1)

	u := ext4.ext2.Mul(l1, l2)
	ac := ext4.ext2.Mul(ma.B0, mb.B0)
	bd := ext4.ext2.Mul(ma.B1, mb.B1)

	l31 := ext4.ext2.Add(ac, bd)
	resB1 := ext4.ext2.Sub(u, l31)
	l41 := ext4.ext2.MulByNonResidue(bd)
	resB0 := ext4.ext2.Add(ac, l41)

	return flattenE4(e4{B0: resB0, B1: resB1})
}

func (ext4 *koalabearExt4) MulNoReduce(a Element, b Element) Element {
	return ext4.Mul(a, b)
}

func (ext4 *koalabearExt4) Add(a Element, b Element) Element {
	ma, mb := unflattenE4(a), unflattenE4(b)
	resB0 := ext4.ext2.Add(ma.B0, mb.B0)
	resB1 := ext4.ext2.Add(ma.B1, mb.B1)
	return flattenE4(e4{B0: resB0, B1: resB1})
}

func (ext4 *koalabearExt4) Sub(a Element, b Element) Element {
	ma, mb := unflattenE4(a), unflattenE4(b)
	resB0 := ext4.ext2.Sub(ma.B0, mb.B0)
	resB1 := ext4.ext2.Sub(ma.B1, mb.B1)
	return flattenE4(e4{B0: resB0, B1: resB1})
}

func (ext4 *koalabearExt4) MulByElement(a Element, b frontend.Variable) Element {
	ma := unflattenE4(a)
	resB0 := ext4.ext2.MulByElement(ma.B0, b)
	resB1 := ext4.ext2.MulByElement(ma.B1, b)
	return flattenE4(e4{B0: resB0, B1: resB1})
}

func (ext4 *koalabearExt4) AssertIsEqual(a Element, b Element) {
	ma, mb := unflattenE4(a), unflattenE4(b)
	ext4.api.AssertIsEqual(ma.B0.A0, mb.B0.A0)
	ext4.api.AssertIsEqual(ma.B0.A1, mb.B0.A1)
	ext4.api.AssertIsEqual(ma.B1.A0, mb.B1.A0)
	ext4.api.AssertIsEqual(ma.B1.A1, mb.B1.A1)
}

func (ext4 *koalabearExt4) Zero() Element {
	return []frontend.Variable{}
}

func (ext4 *koalabearExt4) One() Element {
	return []frontend.Variable{1}
}

func (ext4 *koalabearExt4) AsExtensionVariable(a frontend.Variable) Element {
	return []frontend.Variable{a}
}

func (ext4 *koalabearExt4) Degree() int {
	return 4
}

func (ext4 *koalabearExt4) Inverse(a Element) Element {
	ma := unflattenE4(a)
	res, err := ext4.api.Compiler().NewHint(inverseE4Hint, 4, ma.B0.A0, ma.B0.A1, ma.B1.A0, ma.B1.A1)
	if err != nil {
		panic(err)
	}
	resE4 := e4{
		B0: e2{
			A0: res[0],
			A1: res[1],
		},
		B1: e2{
			A0: res[2],
			A1: res[3],
		},
	}
	prod := ext4.Mul(a, flattenE4(resE4))
	ext4.AssertIsEqual(prod, ext4.One())
	return flattenE4(resE4)
}
