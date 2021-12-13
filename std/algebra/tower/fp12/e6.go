/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fp12

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
)

// TODO(ivokub): pointers are better, but we need to resolve the question of
// value initialization first.

// E6 element in a quadratic extension
type E6 struct {
	B0, B1, B2 fp2.E2
	api        frontend.API
}

// NewFp6Zero creates a new
func NewFp6Zero(api frontend.API) (E6, error) {
	var ret E6
	b0, err := fp2.New(api)
	if err != nil {
		return ret, fmt.Errorf("new b0: %w", err)
	}
	b1, err := fp2.New(api)
	if err != nil {
		return ret, fmt.Errorf("new b1: %w", err)
	}
	b2, err := fp2.New(api)
	if err != nil {
		return ret, fmt.Errorf("new b2: %w", err)
	}
	return E6{
		B0:  b0,
		B1:  b1,
		B2:  b2,
		api: api,
	}, nil
}

type CubicElement interface {
	bls12377.E6
}

type CubicElementPt[T CubicElement] interface {
	*T
}

func FromFp6[T CubicElement](v T) E6 {
	var b0, b1, b2 fp2.E2
	switch vv := (any)(v).(type) {
	case bls12377.E6:
		b0, b1, b2 = fp2.From(vv.B0), fp2.From(vv.B1), fp2.From(vv.B2)
	}
	return E6{
		B0: b0,
		B1: b1,
		B2: b2,
	}
}

// Add creates a fp6elmt from fp elmts
func (e *E6) Add(e1, e2 E6) *E6 {
	e.B0.Add(e1.B0, e2.B0)
	e.B1.Add(e1.B1, e2.B1)
	e.B2.Add(e1.B2, e2.B2)

	return e
}

// Sub creates a fp6elmt from fp elmts
func (e *E6) Sub(e1, e2 E6) *E6 {

	e.B0.Sub(e1.B0, e2.B0)
	e.B1.Sub(e1.B1, e2.B1)
	e.B2.Sub(e1.B2, e2.B2)

	return e
}

// Neg negates an Fp6 elmt
func (e *E6) Neg(e1 E6) *E6 {
	e.B0.Neg(e1.B0)
	e.B1.Neg(e1.B1)
	e.B2.Neg(e1.B2)
	return e
}

// Mul creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) Mul(e1, e2 E6) *E6 {
	var err error

	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	var t [3]fp2.E2
	var c [3]fp2.E2
	var tmp fp2.E2
	for i := range t {
		t[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent API assignment")
		}
	}
	for i := range c {
		c[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent API assignment")
		}
	}
	tmp, err = fp2.New(e.api)
	if err != nil {
		panic("inconsistent API assignment")
	}
	t[0].Mul(e1.B0, e2.B0)
	t[1].Mul(e1.B1, e2.B1)
	t[2].Mul(e1.B2, e2.B2)

	c[0].Add(e1.B1, e1.B2)
	tmp.Add(e2.B1, e2.B2)
	c[0].Mul(c[0], tmp).Sub(c[0], t[1]).Sub(c[0], t[2]).MulByNonResidue(c[0]).Add(c[0], t[0])

	c[1].Add(e1.B0, e1.B1)
	tmp.Add(e2.B0, e2.B1)
	c[1].Mul(c[1], tmp).Sub(c[1], t[0]).Sub(c[1], t[1])
	tmp.MulByNonResidue(t[2])
	c[1].Add(c[1], tmp)

	tmp.Add(e1.B0, e1.B2)
	c[2].Add(e2.B0, e2.B2).Mul(c[2], tmp).Sub(c[2], t[0]).Sub(c[2], t[2]).Add(c[2], t[1])

	e.B0 = c[0]
	e.B1 = c[1]
	e.B2 = c[2]

	return e
}

// MulByFp2 creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) MulByFp2(e1 E6, e2 fp2.E2) *E6 {
	res, err := NewFp6Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	res.B0.Mul(e1.B0, e2)
	res.B1.Mul(e1.B1, e2)
	res.B2.Mul(e1.B2, e2)

	e.B0 = res.B0
	e.B1 = res.B1
	e.B2 = res.B2

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F^2)
func (e *E6) MulByNonResidue(e1 E6) *E6 {
	tmp, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistend API")
	}
	tmp.MulByNonResidue(e1.B2)
	e.B1.Set(e1.B0)
	e.B2.Set(e1.B1)
	e.B0 = tmp
	return e
}

// Square sets z to the E6 product of x,x, returns e
func (e *E6) Square(x E6) *E6 {
	var err error
	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c [6]fp2.E2
	for i := range c {
		c[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent API assignment")
		}
	}
	c[4].Mul(x.B0, x.B1).Double(c[4])
	c[5].Square(x.B2)
	c[1].MulByNonResidue(c[5]).Add(c[1], c[4])
	c[2].Sub(c[4], c[5])
	c[3].Square(x.B0)
	c[4].Sub(x.B0, x.B1).Add(c[4], x.B2)
	c[5].Mul(x.B1, x.B2).Double(c[5])
	c[4].Square(c[4])
	c[0].MulByNonResidue(c[5]).Add(c[0], c[3])
	e.B2.Add(c[2], c[4]).Add(e.B2, c[5]).Sub(e.B2, c[3])
	e.B0 = c[0]
	e.B1 = c[1]

	return e
}

// Inverse inverses an Fp6 elmt
func (e *E6) Inverse(e1 E6) *E6 {
	var err error
	var t [7]fp2.E2
	var c [3]fp2.E2
	var buf fp2.E2
	for i := range t {
		t[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent API assignment")
		}
	}
	for i := range c {
		c[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent API assignment")
		}
	}
	buf, err = fp2.New(e.api)
	if err != nil {
		panic("inconsistent API assignment")
	}

	t[0].Square(e1.B0)
	t[1].Square(e1.B1)
	t[2].Square(e1.B2)
	t[3].Mul(e1.B0, e1.B1)
	t[4].Mul(e1.B0, e1.B2)
	t[5].Mul(e1.B1, e1.B2)

	c[0].MulByNonResidue(t[5])

	c[0].Neg(c[0]).Add(c[0], t[0])

	c[1].MulByNonResidue(t[2])

	c[1].Sub(c[1], t[3])
	c[2].Sub(t[1], t[4])
	t[6].Mul(e1.B2, c[1])
	buf.Mul(e1.B1, c[2])
	t[6].Add(t[6], buf)

	t[6].MulByNonResidue(t[6])

	buf.Mul(e1.B0, c[0])
	t[6].Add(t[6], buf)

	t[6].Inverse(t[6])
	e.B0.Mul(c[0], t[6])
	e.B1.Mul(c[1], t[6])
	e.B2.Mul(c[2], t[6])

	return e

}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E6) MustBeEqual(other E6) {
	e.B0.MustBeEqual(other.B0)
	e.B1.MustBeEqual(other.B1)
	e.B2.MustBeEqual(other.B2)
}

// MulByE2 multiplies an element in E6 by an element in E2
func (e *E6) MulByE2(e1 E6, e2 fp2.E2) *E6 {
	e2Copy := e2
	e.B0.Mul(e1.B0, e2Copy)
	e.B1.Mul(e1.B1, e2Copy)
	e.B2.Mul(e1.B2, e2Copy)
	return e
}

// MulBy01 multiplication by sparse element (c[0],c[1],0)
func (e *E6) MulBy01(c0, c1 fp2.E2) *E6 {
	var err error
	var t [3]fp2.E2
	for i := range t {
		t[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent API assignment")
		}
	}
	a, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent API assignment")
	}
	b, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent API assignment")
	}
	tmp, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent API assignment")
	}

	a.Mul(e.B0, c0)
	b.Mul(e.B1, c1)

	tmp.Add(e.B1, e.B2)
	t[0].Mul(c1, tmp)
	t[0].Sub(t[0], b)
	t[0].MulByNonResidue(t[0])
	t[0].Add(t[0], a)

	tmp.Add(e.B0, e.B2)
	t[2].Mul(c0, tmp)
	t[2].Sub(t[2], a)
	t[2].Add(t[2], b)

	t[1].Add(c0, c1)
	tmp.Add(e.B0, e.B1)
	t[1].Mul(t[1], tmp)
	t[1].Sub(t[1], a)
	t[1].Sub(t[1], b)

	e.B0 = t[0]
	e.B1 = t[1]
	e.B2 = t[2]

	return e
}

func (e *E6) Set(other E6) {
	e.B0.Set(other.B0)
	e.B1.Set(other.B1)
	e.B2.Set(other.B2)
}
