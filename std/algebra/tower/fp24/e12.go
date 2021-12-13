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

package fp24

import (
	"fmt"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
)

// TODO(ivokub): allocate temp variables once

// E12 element in a quadratic extension
type E12 struct {
	C0, C1, C2 E4
	api        frontend.API
}

// NewFp12Zero creates a new
func NewFp12Zero(api frontend.API) (E12, error) {
	var ret E12
	c0, err := NewFp4Zero(api)
	if err != nil {
		return ret, fmt.Errorf("new c[0]: %w", err)
	}
	c1, err := NewFp4Zero(api)
	if err != nil {
		return ret, fmt.Errorf("new c[1]: %w", err)
	}
	c2, err := NewFp4Zero(api)
	if err != nil {
		return ret, fmt.Errorf("new c[2]: %w", err)
	}
	return E12{
		C0:  c0,
		C1:  c1,
		C2:  c2,
		api: api,
	}, nil
}

type E12Constraint interface {
	bls24315.E12
}

func FromFp12[T E12Constraint](v T) E12 {
	var c0, c1, c2 E4
	switch vv := (any)(v).(type) {
	case bls24315.E12:
		c0, c1, c2 = FromFp4(vv.C0), FromFp4(vv.C1), FromFp4(vv.C2)
	}
	return E12{
		C0: c0,
		C1: c1,
		C2: c2,
	}
}

// Add creates a fp12elmt from fp elmts
func (e *E12) Add(e1, e2 E12) *E12 {

	e.C0.Add(e1.C0, e2.C0)
	e.C1.Add(e1.C1, e2.C1)
	e.C2.Add(e1.C2, e2.C2)

	return e
}

// Sub creates a fp12elmt from fp elmts
func (e *E12) Sub(e1, e2 E12) *E12 {

	e.C0.Sub(e1.C0, e2.C0)
	e.C1.Sub(e1.C1, e2.C1)
	e.C2.Sub(e1.C2, e2.C2)

	return e
}

// Neg negates an Fp12 elmt
func (e *E12) Neg(e1 E12) *E12 {
	e.C0.Neg(e1.C0)
	e.C1.Neg(e1.C1)
	e.C2.Neg(e1.C2)
	return e
}

// Mul creates a fp12elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E12) Mul(e1, e2 E12) *E12 {
	var err error
	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf

	var t, c [3]E4
	for i := range t {
		t[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	for i := range c {
		c[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	tmp, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	t[0].Mul(e1.C0, e2.C0)
	t[1].Mul(e1.C1, e2.C1)
	t[2].Mul(e1.C2, e2.C2)

	c[0].Add(e1.C1, e1.C2)
	tmp.Add(e2.C1, e2.C2)
	c[0].Mul(c[0], tmp).Sub(c[0], t[1]).Sub(c[0], t[2]).MulByNonResidue(c[0]).Add(c[0], t[0])

	c[1].Add(e1.C0, e1.C1)
	tmp.Add(e2.C0, e2.C1)
	c[1].Mul(c[1], tmp).Sub(c[1], t[0]).Sub(c[1], t[1])
	tmp.MulByNonResidue(t[2])
	c[1].Add(c[1], tmp)

	tmp.Add(e1.C0, e1.C2)
	c[2].Add(e2.C0, e2.C2).Mul(c[2], tmp).Sub(c[2], t[0]).Sub(c[2], t[2]).Add(c[2], t[1])

	e.C0.Set(c[0])
	e.C1.Set(c[1])
	e.C2.Set(c[2])

	return e
}

// MulByFp2 creates a fp12elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E12) MulByFp2(e1 E12, e2 E4) *E12 {
	res, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	res.C0.Mul(e1.C0, e2)
	res.C1.Mul(e1.C1, e2)
	res.C2.Mul(e1.C2, e2)

	e.C0.Set(res.C0)
	e.C1.Set(res.C1)
	e.C2.Set(res.C1)

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp12 (noted a+bV+cV where V**3 in F^2)
func (e *E12) MulByNonResidue(e1 E12) *E12 {
	res, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	res.C0.MulByNonResidue(e1.C2)
	e.C1.Set(e1.C0)
	e.C2.Set(e1.C1)
	e.C0.Set(res.C0)
	return e
}

// Square sets z to the E12 product of x,x, returns e
func (e *E12) Square(x E12) *E12 {
	var err error
	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c [6]E4
	for i := range c {
		c[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	c[4].Mul(x.C0, x.C1).Double(c[4])
	c[5].Square(x.C2)
	c[1].MulByNonResidue(c[5]).Add(c[1], c[4])
	c[2].Sub(c[4], c[5])
	c[3].Square(x.C0)
	c[4].Sub(x.C0, x.C1).Add(c[4], x.C2)
	c[5].Mul(x.C1, x.C2).Double(c[5])
	c[4].Square(c[4])
	c[0].MulByNonResidue(c[5]).Add(c[0], c[3])
	e.C2.Add(c[2], c[4]).Add(e.C2, c[5]).Sub(e.C2, c[3])
	e.C0.Set(c[0])
	e.C1.Set(c[1])

	return e
}

// Inverse inverses an Fp12 elmt
func (e *E12) Inverse(e1 E12) *E12 {
	var err error
	var t [7]E4
	var c [3]E4
	for i := range t {
		t[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	for i := range c {
		c[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	buf, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	t[0].Square(e1.C0)
	t[1].Square(e1.C1)
	t[2].Square(e1.C2)
	t[3].Mul(e1.C0, e1.C1)
	t[4].Mul(e1.C0, e1.C2)
	t[5].Mul(e1.C1, e1.C2)

	c[0].MulByNonResidue(t[5])

	c[0].Neg(c[0]).Add(c[0], t[0])

	c[1].MulByNonResidue(t[2])

	c[1].Sub(c[1], t[3])
	c[2].Sub(t[1], t[4])
	t[6].Mul(e1.C2, c[1])
	buf.Mul(e1.C1, c[2])
	t[6].Add(t[6], buf)

	t[6].MulByNonResidue(t[6])

	buf.Mul(e1.C0, c[0])
	t[6].Add(t[6], buf)

	t[6].Inverse(t[6])
	e.C0.Mul(c[0], t[6])
	e.C1.Mul(c[1], t[6])
	e.C2.Mul(c[2], t[6])

	return e

}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E12) MustBeEqual(other E12) {
	e.C0.MustBeEqual(other.C0)
	e.C1.MustBeEqual(other.C1)
	e.C2.MustBeEqual(other.C2)
}

// MulByE4 multiplies an element in E12 by an element in E4
func (e *E12) MulByE4(e1 E12, e2 E4) *E12 {
	e2Copy, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	e2Copy.Set(e2)
	e.C0.Mul(e1.C0, e2Copy)
	e.C1.Mul(e1.C1, e2Copy)
	e.C2.Mul(e1.C2, e2Copy)
	return e
}

// MulBy01 multiplication by sparse element (c[0],c[1],0)
func (e *E12) MulBy01(c0, c1 E4) *E12 {
	var err error
	var t [3]E4
	for i := range t {
		t[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	a, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	b, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	tmp, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	a.Mul(e.C0, c0)
	b.Mul(e.C1, c1)

	tmp.Add(e.C1, e.C2)
	t[0].Mul(c1, tmp)
	t[0].Sub(t[0], b)
	t[0].MulByNonResidue(t[0])
	t[0].Add(t[0], a)

	tmp.Add(e.C0, e.C2)
	t[2].Mul(c0, tmp)
	t[2].Sub(t[2], a)
	t[2].Add(t[2], b)

	t[1].Add(c0, c1)
	tmp.Add(e.C0, e.C1)
	t[1].Mul(t[1], tmp)
	t[1].Sub(t[1], a)
	t[1].Sub(t[1], b)

	e.C0.Set(t[0])
	e.C1.Set(t[1])
	e.C2.Set(t[2])

	return e
}

func (e *E12) Set(other E12) {
	e.C0.Set(other.C0)
	e.C1.Set(other.C1)
	e.C2.Set(other.C2)
}
