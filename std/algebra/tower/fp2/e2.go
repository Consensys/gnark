package fp2

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

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	bw6633fr "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	bw6761fr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
)

// TODO(ivokub): it would be better to take *E2 as arguments everywhere, but
// this means that the variables have to be initialized, but this is not
// necessarily true when compiler calls define. An option would be to make the
// compiler initialize all nil pointers for circuit definitions.

// TODO(ivokub): right now we are using the API of the receiver. However, maybe
// receiver obtained not by initializing with API but from witness assignment
// and in that case api field is not set and we would get a panic. It is error
// alright to try to change the value initialized from the witness, but we
// should have a better error? ("trying to modify witness value")

func getU(inner ecc.ID) frontend.Variable {
	switch inner {
	case ecc.BLS12_377:
		return -5
	case ecc.BLS24_315:
		return 13
	default:
		panic("invalid inner curve")
	}
}

func newExtension(outer ecc.ID) (*extension, error) {
	var uSquare frontend.Variable
	switch outer {
	case ecc.BW6_633:
		// we get BLS24-315
		uSquare = getU(ecc.BLS24_315)
	case ecc.BW6_761:
		// we get BLS12-377
		uSquare = getU(ecc.BLS12_377)
	default:
		return nil, fmt.Errorf("unsupported curve %s for extension", outer)
	}
	return &extension{
		uSquare: uSquare,
	}, nil
}

type extension struct {
	uSquare frontend.Variable
}

// E2 element in a quadratic extension
type E2 struct {
	A0, A1 frontend.Variable
	ext    *extension
	api    frontend.API
}

func New(api frontend.API) (E2, error) {
	ext, err := newExtension(api.Curve())
	if err != nil {
		return E2{}, fmt.Errorf("new extension: %w", err)
	}
	return E2{A0: 0, A1: 0, ext: ext, api: api}, nil
}

type E2Constraint interface {
	bls24315.E2 | bls12377.E2
}

func From[F E2Constraint](e2 F) E2 {
	var uSquare, a0, a1 frontend.Variable
	switch v := (any)(e2).(type) {
	case bls24315.E2:
		uSquare = getU(ecc.BLS24_315)
		a0, a1 = (bw6633fr.Element)(v.A0), (bw6633fr.Element)(v.A1)
	case bls12377.E2:
		uSquare = getU(ecc.BLS12_377)
		a0, a1 = (bw6761fr.Element)(v.A0), (bw6761fr.Element)(v.A1)
	default:
		// constraint should prevent default case
		panic("unknown type")
	}
	return E2{
		A0: a0, A1: a1,
		ext: &extension{
			uSquare: uSquare,
		},
	}
}

func (e *E2) SetAPI(api frontend.API) {
	ext, err := newExtension(api.Curve())
	if err != nil {
		panic("incompatible api")
	}
	e.api = api
	e.ext = ext
}

// SetOne returns a newly allocated element equal to 1
func (e *E2) SetOne() *E2 {
	e.A0 = 1
	e.A1 = 0
	return e
}

// Neg negates a e2 elmt
func (e *E2) Neg(e1 E2) *E2 {
	e.A0 = e.api.Sub(0, e1.A0)
	e.A1 = e.api.Sub(0, e1.A1)
	return e
}

// Add e2 elmts
func (e *E2) Add(e1, e2 E2) *E2 {
	e.A0 = e.api.Add(e1.A0, e2.A0)
	e.A1 = e.api.Add(e1.A1, e2.A1)
	return e
}

// Double e2 elmt
func (e *E2) Double(e1 E2) *E2 {
	e.A0 = e.api.Add(e1.A0, e1.A0)
	e.A1 = e.api.Add(e1.A1, e1.A1)
	return e
}

// Sub e2 elmts
func (e *E2) Sub(e1, e2 E2) *E2 {
	e.A0 = e.api.Sub(e1.A0, e2.A0)
	e.A1 = e.api.Sub(e1.A1, e2.A1)
	return e
}

// Mul e2 elmts: 5C
func (e *E2) Mul(e1, e2 E2) *E2 {

	// 1C
	l1 := e.api.Add(e1.A0, e1.A1)
	l2 := e.api.Add(e2.A0, e2.A1)

	u := e.api.Mul(l1, l2)

	// 2C
	ac := e.api.Mul(e1.A0, e2.A0)
	bd := e.api.Mul(e1.A1, e2.A1)

	// 1C
	l31 := e.api.Add(ac, bd)
	e.A1 = e.api.Sub(u, l31)

	// 1C
	buSquare := utils.FromInterface(e.ext.uSquare)
	l41 := e.api.Mul(bd, buSquare)
	e.A0 = e.api.Add(ac, l41)

	return e
}

// Square e2 elt
func (e *E2) Square(x E2) *E2 {
	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf

	c0 := e.api.Sub(x.A0, x.A1)
	buSquare := utils.FromInterface(e.ext.uSquare)
	c3 := e.api.Mul(x.A1, buSquare)
	c3 = e.api.Sub(x.A0, c3)
	c2 := e.api.Mul(x.A0, x.A1)
	c0 = e.api.Mul(c0, c3)
	c0 = e.api.Add(c0, c2)
	e.A1 = e.api.Add(c2, c2)
	c2 = e.api.Mul(c2, buSquare)
	e.A0 = e.api.Add(c0, c2)

	return e
}

// MulByFp multiplies an fp2 elmt by an fp elmt
func (e *E2) MulByFp(e1 E2, c interface{}) *E2 {
	e.A0 = e.api.Mul(e1.A0, c)
	e.A1 = e.api.Mul(e1.A1, c)
	return e
}

// MulByNonResidue multiplies an fp2 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *E2) MulByNonResidue(e1 E2) *E2 {
	e.A0, e.A1 = e1.A1, e1.A0
	e.A0 = e.api.Mul(e.A0, e.ext.uSquare)
	return e
}

// Conjugate conjugation of an e2 elmt
func (e *E2) Conjugate(e1 E2) *E2 {
	e.A0 = e1.A0
	e.A1 = e.api.Sub(0, e1.A1)
	return e
}

// Inverse inverses an fp2elmt
func (e *E2) Inverse(e1 E2) *E2 {

	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	t0 := e.api.Mul(e1.A0, e1.A0)
	t1 := e.api.Mul(e1.A1, e1.A1)
	tmp := e.api.Mul(t1, e.ext.uSquare)
	t0 = e.api.Sub(t0, tmp)
	e.A0 = e.api.DivUnchecked(e1.A0, t0)
	e.A1 = e.api.DivUnchecked(e1.A1, t0)
	e.A1 = e.api.Sub(0, e.A1)

	return e
}

// // Assign a value to self (witness assignment)
// func (e *E2) Assign(a [2]interface{}) {
// 	e.A0 = utils.FromInterface(a[0])
// 	e.A1 = utils.FromInterface(a[1])
// }

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E2) MustBeEqual(other E2) {
	e.api.AssertIsEqual(e.A0, other.A0)
	e.api.AssertIsEqual(e.A1, other.A1)
}

func (e *E2) Set(other E2) {
	e.A0 = other.A0
	e.A1 = other.A1
}
