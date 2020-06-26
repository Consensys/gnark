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

package fields

import "github.com/consensys/gnark/frontend"

// Fp6Elmt element in a quadratic extension
type Fp6Elmt struct {
	B0, B1, B2 Fp2Elmt
}

// NewFp6Elmt creates a fp6elmt from fp elmts
func NewFp6Elmt(circuit *frontend.CS, _b00, _b01, _b10, _b11, _b20, _b21 interface{}) Fp6Elmt {

	res := Fp6Elmt{
		B0: NewFp2Elmt(circuit, _b00, _b01),
		B1: NewFp2Elmt(circuit, _b10, _b11),
		B2: NewFp2Elmt(circuit, _b20, _b21),
	}
	return res
}

// Add creates a fp6elmt from fp elmts
func (e *Fp6Elmt) Add(circuit *frontend.CS, e1, e2 *Fp6Elmt) *Fp6Elmt {

	e.B0.Add(circuit, &e1.B0, &e2.B0)
	e.B1.Add(circuit, &e1.B1, &e2.B1)
	e.B2.Add(circuit, &e1.B2, &e2.B2)

	return e
}

// NewFp6Zero creates a new
func NewFp6Zero(circuit *frontend.CS) Fp6Elmt {
	return NewFp6Elmt(circuit,
		circuit.ALLOCATE(0),
		circuit.ALLOCATE(0),
		circuit.ALLOCATE(0),
		circuit.ALLOCATE(0),
		circuit.ALLOCATE(0),
		circuit.ALLOCATE(0),
	)
}

// Sub creates a fp6elmt from fp elmts
func (e *Fp6Elmt) Sub(circuit *frontend.CS, e1, e2 *Fp6Elmt) *Fp6Elmt {

	e.B0.Sub(circuit, &e1.B0, &e2.B0)
	e.B1.Sub(circuit, &e1.B1, &e2.B1)
	e.B2.Sub(circuit, &e1.B2, &e2.B2)

	return e
}

// Neg negates an Fp6 elmt
func (e *Fp6Elmt) Neg(circuit *frontend.CS, e1 *Fp6Elmt) *Fp6Elmt {
	e.B0.Neg(circuit, &e1.B0)
	e.B1.Neg(circuit, &e1.B1)
	e.B2.Neg(circuit, &e1.B2)
	return e
}

// Mul creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *Fp6Elmt) Mul(circuit *frontend.CS, e1, e2 *Fp6Elmt, ext Extension) *Fp6Elmt {

	// notations: (a+bv+cv2)*(d+ev+fe2)
	var ad, bf, ce Fp2Elmt
	ad.Mul(circuit, &e1.B0, &e2.B0, ext)                            // 5C
	bf.Mul(circuit, &e1.B1, &e2.B2, ext).MulByIm(circuit, &bf, ext) // 6C
	ce.Mul(circuit, &e1.B2, &e2.B1, ext).MulByIm(circuit, &ce, ext) // 6C

	var cf, ae, bd Fp2Elmt
	cf.Mul(circuit, &e1.B2, &e2.B2, ext).MulByIm(circuit, &cf, ext) // 6C
	ae.Mul(circuit, &e1.B0, &e2.B1, ext)                            // 5C
	bd.Mul(circuit, &e1.B1, &e2.B0, ext)                            // 5C

	var af, be, cd Fp2Elmt
	af.Mul(circuit, &e1.B0, &e2.B2, ext) // 5C
	be.Mul(circuit, &e1.B1, &e2.B1, ext) // 5C
	cd.Mul(circuit, &e1.B2, &e2.B0, ext) // 5C

	e.B0.Add(circuit, &ad, &bf).Add(circuit, &e.B0, &ce) // 4C
	e.B1.Add(circuit, &cf, &ae).Add(circuit, &e.B1, &bd) // 4C
	e.B2.Add(circuit, &af, &be).Add(circuit, &e.B2, &cd) // 4C

	return e
}

// MulByFp2 creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *Fp6Elmt) MulByFp2(circuit *frontend.CS, e1 *Fp6Elmt, e2 *Fp2Elmt, ext Extension) *Fp6Elmt {

	res := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)

	res.B0.Mul(circuit, &e1.B0, e2, ext)
	res.B1.Mul(circuit, &e1.B1, e2, ext)
	res.B2.Mul(circuit, &e1.B2, e2, ext)

	e.B0 = res.B0
	e.B1 = res.B1
	e.B2 = res.B2

	return e
}

// MulByV multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F^2)
func (e *Fp6Elmt) MulByV(circuit *frontend.CS, e1 *Fp6Elmt, ext Extension) *Fp6Elmt {
	res := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	res.B0.Mul(circuit, &e1.B2, ext.vCube, ext)
	e.B1 = e1.B0
	e.B2 = e1.B1
	e.B0 = res.B0
	return e
}

// Inverse inverses an Fp2 elmt
func (e *Fp6Elmt) Inverse(circuit *frontend.CS, e1 *Fp6Elmt, ext Extension) *Fp6Elmt {

	var t [7]Fp2Elmt
	var c [3]Fp2Elmt
	var buf Fp2Elmt

	t[0].Mul(circuit, &e1.B0, &e1.B0, ext)
	t[1].Mul(circuit, &e1.B1, &e1.B1, ext)
	t[2].Mul(circuit, &e1.B2, &e1.B2, ext)
	t[3].Mul(circuit, &e1.B0, &e1.B1, ext)
	t[4].Mul(circuit, &e1.B0, &e1.B2, ext)
	t[5].Mul(circuit, &e1.B1, &e1.B2, ext)

	c[0].MulByIm(circuit, &t[5], ext)

	c[0].Neg(circuit, &c[0]).Add(circuit, &c[0], &t[0])

	c[1].MulByIm(circuit, &t[2], ext)

	c[1].Sub(circuit, &c[1], &t[3])
	c[2].Sub(circuit, &t[1], &t[4])
	t[6].Mul(circuit, &e1.B2, &c[1], ext)
	buf.Mul(circuit, &e1.B1, &c[2], ext)
	t[6].Add(circuit, &t[6], &buf)

	t[6].MulByIm(circuit, &t[6], ext)

	buf.Mul(circuit, &e1.B0, &c[0], ext)
	t[6].Add(circuit, &t[6], &buf)

	t[6].Inverse(circuit, &t[6], ext)
	e.B0.Mul(circuit, &c[0], &t[6], ext)
	e.B1.Mul(circuit, &c[1], &t[6], ext)
	e.B2.Mul(circuit, &c[2], &t[6], ext)

	return e

}
