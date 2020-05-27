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
	x, y, z *frontend.Constraint
}

// NewPointG1 creates a new point from interaces as coordinates
func NewPointG1(circuit *frontend.CS, x, y, z interface{}) *G1Jac {
	res := &G1Jac{
		x: circuit.ALLOCATE(x),
		y: circuit.ALLOCATE(y),
		z: circuit.ALLOCATE(z),
	}
	return res
}

// NewInfinityG1 returns a newly allocated point at infinity
func NewInfinityG1(circuit *frontend.CS) *G1Jac {
	res := &G1Jac{
		x: circuit.ALLOCATE(0),
		y: circuit.ALLOCATE(1),
		z: circuit.ALLOCATE(0),
	}
	return res
}

// Neg outputs -p
func (p *G1Jac) Neg(circuit *frontend.CS) *G1Jac {
	p.y = circuit.SUB(0, &p.y)
	return p
}

// Add adds 2 point in Jacobian coordinates
// p=p, p1=a
func (p *G1Jac) Add(circuit *frontend.CS, p1 *G1Jac) *G1Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V *frontend.Constraint

	Z1Z1 = circuit.MUL(p1.z, p1.z)
	Z2Z2 = circuit.MUL(p.z, p.z)
	U1 = circuit.MUL(p1.x, Z2Z2)
	U2 = circuit.MUL(p.x, Z1Z1)
	S1 = circuit.MUL(p1.y, p.z)
	S1 = circuit.MUL(S1, Z2Z2)
	S2 = circuit.MUL(p.y, p1.z)
	S2 = circuit.MUL(S2, Z1Z1)
	H = circuit.SUB(U2, U1)
	I = circuit.ADD(H, H)
	I = circuit.MUL(I, I)
	J = circuit.MUL(H, I)
	r = circuit.SUB(S2, S1)
	V = circuit.MUL(U1, I)
	p.x = circuit.MUL(r, r)
	p.x = circuit.SUB(p.x, J)
	p.x = circuit.SUB(p.x, V)
	p.x = circuit.SUB(p.x, V)
	p.y = circuit.SUB(V, p.x)
	p.y = circuit.MUL(p.y, r)
	S1 = circuit.MUL(J, S1)
	S1 = circuit.ADD(S1, S1)
	p.y = circuit.SUB(p.y, S1)
	p.z = circuit.ADD(p.z, p1.z)
	p.z = circuit.MUL(p.z, p.z)
	p.z = circuit.SUB(p.z, Z1Z1)
	p.z = circuit.SUB(p.z, Z2Z2)
	p.z = circuit.MUL(p.z, H)

	return p
}

// Double doubles a point in jacobian coords
func (p *G1Jac) Double(circuit *frontend.CS, p1 *G1Jac) *G1Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T *frontend.Constraint

	XX = circuit.MUL(p.x, p.x)
	YY = circuit.MUL(p.y, p.y)
	YYYY = circuit.MUL(YY, YY)
	ZZ = circuit.MUL(p.z, p.z)
	S = circuit.ADD(p.x, YY)
	S = circuit.MUL(S, S)
	S = circuit.SUB(S, XX)
	S = circuit.SUB(S, YYYY)
	S = circuit.ADD(S, S)
	M = circuit.MUL(XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.z = circuit.ADD(p.z, p.y)
	p.z = circuit.MUL(p.z, p.z)
	p.z = circuit.SUB(p.z, YY)
	p.z = circuit.SUB(p.z, ZZ)
	p.x = circuit.MUL(M, M)
	T = circuit.ADD(S, S)
	p.x = circuit.SUB(p.x, T)
	p.y = circuit.SUB(S, p.x)
	p.y = circuit.MUL(p.y, M)
	YYYY = circuit.MUL(YYYY, 8)
	p.y = circuit.SUB(p.y, YYYY)

	return p
}
