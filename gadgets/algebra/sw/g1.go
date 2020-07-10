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
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// G1Proj point in projective coordinates
type G1Proj struct {
	X, Y, Z frontend.Variable
}

// G1Jac point in Jacobian coords
type G1Jac struct {
	X, Y, Z frontend.Variable
}

// G1Aff point in affine coords
type G1Aff struct {
	X, Y frontend.Variable
}

// NewPointG1 creates a new point from interfaces as coordinates
func NewPointG1(circuit *frontend.CS, x, y, z interface{}) *G1Jac {
	res := &G1Jac{
		X: circuit.ALLOCATE(x),
		Y: circuit.ALLOCATE(y),
		Z: circuit.ALLOCATE(z),
	}
	return res
}

// NewPointG1Aff creates a new affine point from interaces as coordinates
func NewPointG1Aff(circuit *frontend.CS, x, y interface{}) *G1Aff {
	res := &G1Aff{
		X: circuit.ALLOCATE(x),
		Y: circuit.ALLOCATE(y),
	}
	return res
}

// NewInfinityG1 returns a newly allocated point at infinity (in Jacobian)
func NewInfinityG1(circuit *frontend.CS) *G1Jac {
	res := &G1Jac{
		X: circuit.ALLOCATE(1),
		Y: circuit.ALLOCATE(1),
		Z: circuit.ALLOCATE(0),
	}
	return res
}

// NewInfinityProjG1 returns a newly allocated point at infinity (in projective)
func NewInfinityProjG1(circuit *frontend.CS) *G1Proj {
	res := &G1Proj{
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
	p.Y = circuit.SUB(0, p1.Y)
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G1Aff) Neg(circuit *frontend.CS, p1 *G1Aff) *G1Aff {
	p.X = p1.X
	p.Y = circuit.SUB(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Aff) AddAssign(circuit *frontend.CS, p1 *G1Aff) *G1Aff {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	var c1, c2 big.Int
	c1.SetInt64(1)
	c2.SetInt64(-1)
	l1 := frontend.LinearCombination{
		frontend.Term{Constraint: p1.Y, Coeff: c1},
		frontend.Term{Constraint: p.Y, Coeff: c2},
	}
	l2 := frontend.LinearCombination{
		frontend.Term{Constraint: p1.X, Coeff: c1},
		frontend.Term{Constraint: p.X, Coeff: c2},
	}
	l := circuit.DIV(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x := frontend.LinearCombination{
		frontend.Term{Constraint: circuit.MUL(l, l), Coeff: c1},
		frontend.Term{Constraint: p.X, Coeff: c2},
		frontend.Term{Constraint: p1.X, Coeff: c2},
	}

	// p.y = lambda(p.x-xr) - p.y
	t1 := circuit.MUL(p.X, l)
	t2 := circuit.MUL(l, _x)
	l3 := frontend.LinearCombination{
		frontend.Term{Constraint: t1, Coeff: c1},
		frontend.Term{Constraint: t2, Coeff: c2},
		frontend.Term{Constraint: p.Y, Coeff: c2},
	}
	p.Y = circuit.MUL(l3, 1)

	//p.x = xr
	p.X = circuit.MUL(_x, 1)
	return p
}

// Assign sets p to p1 and return it
func (p *G1Jac) Assign(circuit *frontend.CS, p1 *G1Jac) *G1Jac {
	p.X = circuit.ALLOCATE(p1.X)
	p.Y = circuit.ALLOCATE(p1.Y)
	p.Z = circuit.ALLOCATE(p1.Z)
	return p
}

// Assign sets p to p1 and return it
func (p *G1Aff) Assign(circuit *frontend.CS, p1 *G1Aff) *G1Aff {
	p.X = circuit.ALLOCATE(p1.X)
	p.Y = circuit.ALLOCATE(p1.Y)
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(circuit *frontend.CS, p1 *G1Jac) *G1Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V frontend.Variable

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

// DoubleAssign doubles the receiver point in jacobian coords and returns it
func (p *G1Jac) DoubleAssign(circuit *frontend.CS) *G1Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T frontend.Variable

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

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G1Aff) Select(circuit *frontend.CS, b frontend.Variable, p1, p2 *G1Aff) *G1Aff {

	p.X = circuit.SELECT(b, p1.X, p2.X)
	p.Y = circuit.SELECT(b, p1.Y, p2.Y)

	return p

}

// FromJac sets p to p1 in affine and returns it
func (p *G1Aff) FromJac(circuit *frontend.CS, p1 *G1Jac) *G1Aff {
	s := circuit.MUL(p1.Z, p1.Z)
	p.X = circuit.DIV(p1.X, s)
	p.Y = circuit.DIV(p1.Y, circuit.MUL(s, p1.Z))
	return p
}

// Double double a point in affine coords
func (p *G1Aff) Double(circuit *frontend.CS, p1 *G1Aff) *G1Aff {

	var t, d, c1, c2, c3 big.Int
	t.SetInt64(3)
	d.SetInt64(2)
	c1.SetInt64(1)
	c2.SetInt64(-2)
	c3.SetInt64(-1)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	x2 := circuit.MUL(p1.X, p1.X)
	circuit.MUL(p1.X, p1.X)
	l1 := frontend.LinearCombination{
		frontend.Term{Constraint: x2, Coeff: t},
	}
	l2 := frontend.LinearCombination{
		frontend.Term{Constraint: p1.Y, Coeff: d},
	}
	l := circuit.DIV(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x := frontend.LinearCombination{
		frontend.Term{Constraint: circuit.MUL(l, l), Coeff: c1},
		frontend.Term{Constraint: p1.X, Coeff: c2},
	}

	// p.y = lambda(p.x-xr) - p.y
	t1 := circuit.MUL(p1.X, l)
	t2 := circuit.MUL(l, _x)
	l3 := frontend.LinearCombination{
		frontend.Term{Constraint: t1, Coeff: c1},
		frontend.Term{Constraint: t2, Coeff: c3},
		frontend.Term{Constraint: p1.Y, Coeff: c3},
	}
	p.Y = circuit.MUL(l3, 1)

	//p.x = xr
	p.X = circuit.MUL(_x, 1)
	return p
}

// ScalarMul computes scalar*p1, affect the result to p, and returns it.
// n is the number of bits used for the scalar mul.
// TODO it doesn't work if the scalar if 1, because it ends up doing P-P at the end, involving division by 0
func (p *G1Aff) ScalarMul(circuit *frontend.CS, p1 *G1Aff, s interface{}, n int) *G1Aff {

	scalar := circuit.ALLOCATE(s)

	var base, res G1Aff
	base.Double(circuit, p1)
	res.Assign(circuit, p1)

	b := circuit.TO_BINARY(scalar, n)

	var tmp G1Aff

	// start from 1 and use right-to-left scalar multiplication to avoid bugs due to incomplete addition law
	// (I don't see how to avoid that)
	for i := 1; i <= n-1; i++ {
		tmp.Assign(circuit, &res).AddAssign(circuit, &base)
		res.Select(circuit, b[i], &tmp, &res)
		base.Double(circuit, &base)
	}

	// now check the lsb, if it's one, leave the result as is, otherwise substract P
	tmp.Neg(circuit, p1).AddAssign(circuit, &res)

	p.Select(circuit, b[0], &res, &tmp)

	return p

}
