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
	"github.com/consensys/gnark/std/algebra/tower/fp2"
)

// TODO(ivokub): think about method with any input (mulbyfp)

// E4 element in a quadratic extension
type E4 struct {
	B0, B1 fp2.E2
	api    frontend.API
}

// New creates a new
func NewFp4Zero(api frontend.API) (E4, error) {
	var ret E4
	b0, err := fp2.New(api)
	if err != nil {
		return ret, fmt.Errorf("new fp2: %w", err)
	}
	b1, err := fp2.New(api)
	if err != nil {
		return ret, fmt.Errorf("new fp2: %w", err)
	}
	return E4{
		B0:  b0,
		B1:  b1,
		api: api,
	}, nil
}

type E4Constraint interface {
	bls24315.E4
}

type E4ConstraintPt[T E4Constraint] interface {
	*T
}

func FromFp4[T E4Constraint](v T) E4 {
	var b0, b1 fp2.E2
	switch vv := (any)(v).(type) {
	case bls24315.E4:
		b0, b1 = fp2.From(vv.B0), fp2.From(vv.B1)
	}
	return E4{
		B0: b0,
		B1: b1,
	}
}

func (e *E4) SetAPI(api frontend.API) {
	e.api = api
	e.B0.SetAPI(api)
	e.B1.SetAPI(api)
}

// SetOne returns a newly allocated element equal to 1
func (e *E4) SetOne() *E4 {
	e.B0.A0 = 1
	e.B0.A1 = 0
	e.B1.A0 = 0
	e.B1.A1 = 0
	return e
}

// Neg negates a e4 elmt
func (e *E4) Neg(e1 E4) *E4 {
	e.B0.Neg(e1.B0)
	e.B1.Neg(e1.B1)
	return e
}

// Add e4 elmts
func (e *E4) Add(e1, e2 E4) *E4 {
	e.B0.Add(e1.B0, e2.B0)
	e.B1.Add(e1.B1, e2.B1)
	return e
}

// Double e4 elmt
func (e *E4) Double(e1 E4) *E4 {
	e.B0.Double(e1.B0)
	e.B1.Double(e1.B1)
	return e
}

// Sub e4 elmts
func (e *E4) Sub(e1, e2 E4) *E4 {
	e.B0.Sub(e1.B0, e2.B0)
	e.B1.Sub(e1.B1, e2.B1)
	return e
}

// Mul e4 elmts: 5C
func (e *E4) Mul(e1, e2 E4) *E4 {
	a, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	b, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	c, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	a.Add(e1.B0, e1.B1)
	b.Add(e2.B0, e2.B1)
	a.Mul(a, b)
	b.Mul(e1.B0, e2.B0)
	c.Mul(e1.B1, e2.B1)
	e.B1.Sub(a, b).Sub(e.B1, c)
	e.B0.MulByNonResidue(c).Add(e.B0, b)

	return e
}

// Square e4 elt
func (e *E4) Square(x E4) *E4 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf

	c0, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	c2, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	c3, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	c0.Sub(x.B0, x.B1)
	c3.MulByNonResidue(x.B1).Sub(x.B0, c3)
	c2.Mul(x.B0, x.B1)
	c0.Mul(c0, c3).Add(c0, c2)
	e.B1.Double(c2)
	c2.MulByNonResidue(c2)
	e.B0.Add(c0, c2)

	return e
}

// MulByFp multiplies an e4 elmt by an fp elmt
func (e *E4) MulByFp(e1 E4, c interface{}) *E4 {
	e.B0.MulByFp(e1.B0, c)
	e.B1.MulByFp(e1.B1, c)
	return e
}

// MulByNonResidue multiplies an e4 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *E4) MulByNonResidue(e1 E4) *E4 {
	e.B1.Set(e1.B0)
	e.B0.Set(e1.B1)
	e.B0.MulByNonResidue(e.B0)
	return e
}

// Conjugate conjugation of an e4 elmt
func (e *E4) Conjugate(e1 E4) *E4 {
	e.B0.Set(e1.B0)
	e.B1.Neg(e1.B1)
	return e
}

// Inverse inverses an e4 elmt
func (e *E4) Inverse(e1 E4) *E4 {

	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	t0, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	t1, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	tmp, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	t0.Square(e1.B0)
	t1.Square(e1.B1)
	tmp.MulByNonResidue(t1)
	t0.Sub(t0, tmp)
	t1.Inverse(t0)
	e.B0.Mul(e1.B0, t1)
	e.B1.Mul(e1.B1, t1).Neg(e.B1)

	return e
}

// // Assign a value to self (witness assignment)
// func (e *E4) Assign(a [2][2]interface{}) {
// 	e.B0.Assign(a[0])
// 	e.B1.Assign(a[1])

// }

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E4) MustBeEqual(other E4) {
	e.B0.MustBeEqual(other.B0)
	e.B1.MustBeEqual(other.B1)
}

func (e *E4) Set(other E4) {
	e.B0.Set(other.B0)
	e.B1.Set(other.B1)
}
