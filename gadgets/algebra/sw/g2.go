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
	x, y, z fields.Fp2Elmt
}

// NewPointG2 creates a new point from interaces as coordinates
func NewPointG2(circuit *frontend.CS, x, y, z fields.Fp2Elmt) *G2Jac {
	res := &G2Jac{
		x: x,
		y: y,
		z: z,
	}
	return res
}

// NewInfinityG2 returns a newly allocated point at infinity
func NewInfinityG2(circuit *frontend.CS) *G2Jac {
	res := &G2Jac{
		x: fields.NewFp2Elmt(circuit, 0, 0),
		y: fields.NewFp2Elmt(circuit, 1, 0),
		z: fields.NewFp2Elmt(circuit, 0, 0),
	}
	return res
}

// Neg outputs -p
func (p *G2Jac) Neg(circuit *frontend.CS) *G2Jac {
	p.y.Neg(circuit, &p.y)
	return p
}

// Add adds 2 point in Jacobian coordinates
// p=p, p1=a
func (p *G2Jac) Add(circuit *frontend.CS, p1 *G2Jac, ext fields.Extension) *G2Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V fields.Fp2Elmt

	Z1Z1.Mul(circuit, &p1.z, &p1.z, ext)
	Z2Z2.Mul(circuit, &p.z, &p.z, ext)
	U1.Mul(circuit, &p1.x, &Z2Z2, ext)
	U2.Mul(circuit, &p.x, &Z1Z1, ext)
	S1.Mul(circuit, &p1.y, &p.z, ext)
	S1.Mul(circuit, &S1, &Z2Z2, ext)
	S2.Mul(circuit, &p.y, &p1.z, ext)
	S2.Mul(circuit, &S2, &Z1Z1, ext)
	H.Sub(circuit, &U2, &U1)
	I.Add(circuit, &H, &H)
	I.Mul(circuit, &I, &I, ext)
	J.Mul(circuit, &H, &I, ext)
	r.Sub(circuit, &S2, &S1)
	V.Mul(circuit, &U1, &I, ext)
	p.x.Mul(circuit, &r, &r, ext)
	p.x.Sub(circuit, &p.x, &J)
	p.x.Sub(circuit, &p.x, &V)
	p.x.Sub(circuit, &p.x, &V)
	p.y.Sub(circuit, &V, &p.x)
	p.y.Mul(circuit, &p.y, &r, ext)
	S1.Mul(circuit, &J, &S1, ext)
	S1.Add(circuit, &S1, &S1)
	p.y.Sub(circuit, &p.y, &S1)
	p.z.Add(circuit, &p.z, &p1.z)
	p.z.Mul(circuit, &p.z, &p.z, ext)
	p.z.Sub(circuit, &p.z, &Z1Z1)
	p.z.Sub(circuit, &p.z, &Z2Z2)
	p.z.Mul(circuit, &p.z, &H, ext)

	return p
}
