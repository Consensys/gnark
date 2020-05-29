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

package sw

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/fields"
)

// G2Jac point in Jacobian coords
type G2Jac struct {
	X, Y, Z fields.Fp2Elmt
}

// NewPointG2 creates a new point from interaces as coordinates
func NewPointG2(circuit *frontend.CS, x, y, z fields.Fp2Elmt) *G2Jac {
	res := &G2Jac{
		X: x,
		Y: y,
		Z: z,
	}
	return res
}

// NewInfinityG2 returns a newly allocated point at infinity
func NewInfinityG2(circuit *frontend.CS) *G2Jac {
	res := &G2Jac{
		X: fields.NewFp2Elmt(circuit, 0, 0),
		Y: fields.NewFp2Elmt(circuit, 1, 0),
		Z: fields.NewFp2Elmt(circuit, 0, 0),
	}
	return res
}

// Neg outputs -p
func (p *G2Jac) Neg(circuit *frontend.CS) *G2Jac {
	p.Y.Neg(circuit, &p.Y)
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G2Jac) AddAssign(circuit *frontend.CS, p1 *G2Jac, ext fields.Extension) *G2Jac {

	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V fields.Fp2Elmt

	Z1Z1.Mul(circuit, &p1.Z, &p1.Z, ext)

	Z2Z2.Mul(circuit, &p.Z, &p.Z, ext)

	U1.Mul(circuit, &p1.X, &Z2Z2, ext)

	U2.Mul(circuit, &p.X, &Z1Z1, ext)

	S1.Mul(circuit, &p1.Y, &p.Z, ext)
	S1.Mul(circuit, &S1, &Z2Z2, ext)

	S2.Mul(circuit, &p.Y, &p1.Z, ext)
	S2.Mul(circuit, &S2, &Z1Z1, ext)

	H.Sub(circuit, &U2, &U1)

	I.Add(circuit, &H, &H)
	I.Mul(circuit, &I, &I, ext)

	J.Mul(circuit, &H, &I, ext)

	r.Sub(circuit, &S2, &S1)
	r.Add(circuit, &r, &r)

	V.Mul(circuit, &U1, &I, ext)

	p.X.Mul(circuit, &r, &r, ext)
	p.X.Sub(circuit, &p.X, &J)
	p.X.Sub(circuit, &p.X, &V)
	p.X.Sub(circuit, &p.X, &V)

	p.Y.Sub(circuit, &V, &p.X)
	p.Y.Mul(circuit, &p.Y, &r, ext)

	S1.Mul(circuit, &J, &S1, ext)
	S1.Add(circuit, &S1, &S1)

	p.Y.Sub(circuit, &p.Y, &S1)

	p.Z.Add(circuit, &p.Z, &p1.Z)
	p.Z.Mul(circuit, &p.Z, &p.Z, ext)
	p.Z.Sub(circuit, &p.Z, &Z1Z1)
	p.Z.Sub(circuit, &p.Z, &Z2Z2)
	p.Z.Mul(circuit, &p.Z, &H, ext)

	return p
}

// Double doubles a point in jacobian coords
func (p *G2Jac) Double(circuit *frontend.CS, p1 *G2Jac, ext fields.Extension) *G2Jac {

	var XX, YY, YYYY, ZZ, S, M, T fields.Fp2Elmt

	XX.Mul(circuit, &p.X, &p.X, ext)
	YY.Mul(circuit, &p.Y, &p.Y, ext)
	YYYY.Mul(circuit, &YY, &YY, ext)
	ZZ.Mul(circuit, &p.Z, &p.Z, ext)
	S.Add(circuit, &p.X, &YY)
	S.Mul(circuit, &S, &S, ext)
	S.Sub(circuit, &S, &XX)
	S.Sub(circuit, &S, &YYYY)
	S.Add(circuit, &S, &S)
	M.MulByFp(circuit, &XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z.Add(circuit, &p.Z, &p.Y)
	p.Z.Mul(circuit, &p.Z, &p.Z, ext)
	p.Z.Sub(circuit, &p.Z, &YY)
	p.Z.Sub(circuit, &p.Z, &ZZ)
	p.X.Mul(circuit, &M, &M, ext)
	T.Add(circuit, &S, &S)
	p.X.Sub(circuit, &p.X, &T)
	p.Y.Sub(circuit, &S, &p.X)
	p.Y.Mul(circuit, &p.Y, &M, ext)
	YYYY.MulByFp(circuit, &YYYY, 8)
	p.Y.Sub(circuit, &p.Y, &YYYY)

	return p
}
