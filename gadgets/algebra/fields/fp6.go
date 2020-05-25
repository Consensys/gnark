package fields

import "github.com/consensys/gnark/frontend"

// Fp6Elmt element in a quadratic extension
type Fp6Elmt struct {
	b0, b1, b2 Fp2Elmt
}

// NewFp6Elmt creates a fp6elmt from fp elmts
func NewFp6Elmt(circuit *frontend.CS, _b00, _b01, _b10, _b11, _b20, _b21 interface{}) Fp6Elmt {

	res := Fp6Elmt{
		b0: NewFp2Elmt(circuit, _b00, _b01),
		b1: NewFp2Elmt(circuit, _b10, _b11),
		b2: NewFp2Elmt(circuit, _b20, _b21),
	}
	return res
}

// Add creates a fp6elmt from fp elmts
func (e *Fp6Elmt) Add(circuit *frontend.CS, e1, e2 *Fp6Elmt) *Fp6Elmt {

	e.b0.Add(circuit, &e1.b0, &e2.b0)
	e.b1.Add(circuit, &e1.b1, &e2.b1)
	e.b2.Add(circuit, &e1.b2, &e2.b2)

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

	e.b0.Sub(circuit, &e1.b0, &e2.b0)
	e.b1.Sub(circuit, &e1.b1, &e2.b1)
	e.b2.Sub(circuit, &e1.b2, &e2.b2)

	return e
}

// Mul creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *Fp6Elmt) Mul(circuit *frontend.CS, e1, e2 *Fp6Elmt, ext Extension) *Fp6Elmt {

	res := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	tmp := NewFp2Elmt(circuit, nil, nil)

	res.b0.Mul(circuit, &e1.b0, &e2.b0, ext)
	tmp.Mul(circuit, &e1.b1, &e2.b2, ext).
		Mul(circuit, &tmp, ext.vCube, ext)
	res.b0.Add(circuit, &res.b0, &tmp)
	tmp.Mul(circuit, &e1.b2, &e2.b1, ext).
		Mul(circuit, &tmp, ext.vCube, ext)
	res.b0.Add(circuit, &res.b0, &tmp)

	res.b1.Mul(circuit, &e1.b0, &e2.b1, ext)
	tmp.Mul(circuit, &e1.b1, &e2.b0, ext)
	res.b1.Add(circuit, &res.b1, &tmp)
	tmp.Mul(circuit, &e1.b2, &e2.b2, ext).
		Mul(circuit, &tmp, ext.vCube, ext)
	res.b1.Add(circuit, &res.b1, &tmp)

	res.b2.Mul(circuit, &e1.b2, &e2.b0, ext)
	tmp.Mul(circuit, &e1.b0, &e2.b2, ext)
	res.b2.Add(circuit, &res.b2, &tmp)
	tmp.Mul(circuit, &e1.b1, &e2.b1, ext)
	res.b2.Add(circuit, &res.b2, &tmp)

	e.b0 = res.b0
	e.b1 = res.b1
	e.b2 = res.b2

	return e
}

// MulByFp2 creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *Fp6Elmt) MulByFp2(circuit *frontend.CS, e1 *Fp6Elmt, e2 *Fp2Elmt, ext Extension) *Fp6Elmt {

	res := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)

	res.b0.Mul(circuit, &e1.b0, e2, ext)
	res.b1.Mul(circuit, &e1.b1, e2, ext)
	res.b2.Mul(circuit, &e1.b2, e2, ext)

	e.b0 = res.b0
	e.b1 = res.b1
	e.b2 = res.b2

	return e
}

// MulByV multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F^2)
func (e *Fp6Elmt) MulByV(circuit *frontend.CS, e1 *Fp6Elmt, ext Extension) *Fp6Elmt {
	res := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	res.b0.Mul(circuit, &e1.b2, ext.vCube, ext)
	e.b1 = e1.b0
	e.b2 = e1.b1
	e.b0 = res.b0
	return e
}
