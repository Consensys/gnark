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

import "github.com/consensys/gnark/frontend"

// G1Jac point in Jacobian coords
type G1Jac struct {
	X, Y, Z *frontend.Constraint
}

// NewPointG1 creates a new point from interaces as coordinates
func NewPointG1(circuit *frontend.CS, x, y, z interface{}) *G1Jac {
	res := &G1Jac{
		X: circuit.ALLOCATE(x),
		Y: circuit.ALLOCATE(y),
		Z: circuit.ALLOCATE(z),
	}
	return res
}

// NewInfinityG1 returns a newly allocated point at infinity
func NewInfinityG1(circuit *frontend.CS) *G1Jac {
	res := &G1Jac{
		X: circuit.ALLOCATE(0),
		Y: circuit.ALLOCATE(1),
		Z: circuit.ALLOCATE(0),
	}
	return res
}

// ToProj sets p to the projective rep of p1 and return it
func (p *G1Jac) ToProj(circuit *frontend.CS, p1 *G1Jac) *G1Jac {
	p.X = circuit.MUL(p1.X, p1.Z)
	p.Y = p1.Y
	t := circuit.MUL(p1.Z, p1.Z)
	p.Z = circuit.MUL(p1.Z, t)
	return p
}

// Neg outputs -p
func (p *G1Jac) Neg(circuit *frontend.CS, p1 *G1Jac) *G1Jac {
	p.X = p1.X
	p.Y = circuit.SUB(0, &p1.Y)
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(circuit *frontend.CS, p1 *G1Jac) *G1Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V *frontend.Constraint

	Z1Z1 = circuit.MUL(p1.Z, p1.Z)

	Z2Z2 = circuit.MUL(p.Z, p.Z)

	U1 = circuit.MUL(p1.X, Z2Z2)

	U2 = circuit.MUL(p.X, Z1Z1)

	S1 = circuit.MUL(p1.Y, p.Z)
	S1 = circuit.MUL(S1, Z2Z2)

	S2 = circuit.MUL(p.Y, p1.Z)
	S2 = circuit.MUL(S2, Z1Z1)

	H = circuit.SUB(U2, U1)

	I = circuit.ADD(H, H)
	I = circuit.MUL(I, I)

	J = circuit.MUL(H, I)

	r = circuit.SUB(S2, S1)
	r = circuit.ADD(r, r)

	V = circuit.MUL(U1, I)

	p.X = circuit.MUL(r, r)
	p.X = circuit.SUB(p.X, J)
	p.X = circuit.SUB(p.X, V)
	p.X = circuit.SUB(p.X, V)

	p.Y = circuit.SUB(V, p.X)
	p.Y = circuit.MUL(p.Y, r)

	S1 = circuit.MUL(J, S1)
	S1 = circuit.ADD(S1, S1)

	p.Y = circuit.SUB(p.Y, S1)

	p.Z = circuit.ADD(p.Z, p1.Z)
	p.Z = circuit.MUL(p.Z, p.Z)
	p.Z = circuit.SUB(p.Z, Z1Z1)
	p.Z = circuit.SUB(p.Z, Z2Z2)
	p.Z = circuit.MUL(p.Z, H)

	return p
}

// Double doubles a point in jacobian coords
func (p *G1Jac) Double(circuit *frontend.CS, p1 *G1Jac) *G1Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T *frontend.Constraint

	XX = circuit.MUL(p.X, p.X)
	YY = circuit.MUL(p.Y, p.Y)
	YYYY = circuit.MUL(YY, YY)
	ZZ = circuit.MUL(p.Z, p.Z)
	S = circuit.ADD(p.X, YY)
	S = circuit.MUL(S, S)
	S = circuit.SUB(S, XX)
	S = circuit.SUB(S, YYYY)
	S = circuit.ADD(S, S)
	M = circuit.MUL(XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z = circuit.ADD(p.Z, p.Y)
	p.Z = circuit.MUL(p.Z, p.Z)
	p.Z = circuit.SUB(p.Z, YY)
	p.Z = circuit.SUB(p.Z, ZZ)
	p.X = circuit.MUL(M, M)
	T = circuit.ADD(S, S)
	p.X = circuit.SUB(p.X, T)
	p.Y = circuit.SUB(S, p.X)
	p.Y = circuit.MUL(p.Y, M)
	YYYY = circuit.MUL(YYYY, 8)
	p.Y = circuit.SUB(p.Y, YYYY)

	return p
}
