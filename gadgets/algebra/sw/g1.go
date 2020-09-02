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
	"github.com/consensys/gurvy/bls377"
	"github.com/consensys/gurvy/bls377/fp"
	"github.com/consensys/gurvy/bw761/fr"
)

// G1Proj point in projective coordinates
type G1Proj struct {
	X, Y, Z frontend.Variable
}

// G1Jac point in Jacobian coords
type G1Jac struct {
	X, Y, Z frontend.Variable
}

// G1Affine point in affine coords
type G1Affine struct {
	X, Y frontend.Variable
}

func bls377FpTobw761fr(a *fp.Element) (r fr.Element) {
	for i, v := range a {
		r[i] = v
	}
	return
}

func (p *G1Jac) Assign(p1 *bls377.G1Jac) {
	p.X.Assign(bls377FpTobw761fr(&p1.X))
	p.Y.Assign(bls377FpTobw761fr(&p1.Y))
	p.Z.Assign(bls377FpTobw761fr(&p1.Z))
}

func (p *G1Jac) MUSTBE_EQ(cs *frontend.CS, other G1Jac) {
	cs.MUSTBE_EQ(p.X, other.X)
	cs.MUSTBE_EQ(p.Y, other.Y)
	cs.MUSTBE_EQ(p.Z, other.Z)
}

func (p *G1Affine) Assign(p1 *bls377.G1Affine) {
	p.X.Assign(bls377FpTobw761fr(&p1.X))
	p.Y.Assign(bls377FpTobw761fr(&p1.Y))
}

func (p *G1Affine) MUSTBE_EQ(cs *frontend.CS, other G1Affine) {
	cs.MUSTBE_EQ(p.X, other.X)
	cs.MUSTBE_EQ(p.Y, other.Y)
}

// ToProj sets p to the projective rep of p1 and return it
func (p *G1Jac) ToProj(cs *frontend.CS, p1 *G1Jac) *G1Jac {
	p.X = cs.MUL(p1.X, p1.Z)
	p.Y = p1.Y
	t := cs.MUL(p1.Z, p1.Z)
	p.Z = cs.MUL(p1.Z, t)
	return p
}

// Neg outputs -p
func (p *G1Jac) Neg(cs *frontend.CS, p1 *G1Jac) *G1Jac {
	p.X = p1.X
	p.Y = cs.SUB(0, p1.Y)
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G1Affine) Neg(cs *frontend.CS, p1 *G1Affine) *G1Affine {
	p.X = p1.X
	p.Y = cs.SUB(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Affine) AddAssign(cs *frontend.CS, p1 *G1Affine) *G1Affine {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	var c1, c2 big.Int
	c1.SetInt64(1)
	c2.SetInt64(-1)
	l1 := frontend.LinearCombination{
		frontend.Term{Variable: p1.Y, Coeff: c1},
		frontend.Term{Variable: p.Y, Coeff: c2},
	}
	l2 := frontend.LinearCombination{
		frontend.Term{Variable: p1.X, Coeff: c1},
		frontend.Term{Variable: p.X, Coeff: c2},
	}
	l := cs.DIV(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x := frontend.LinearCombination{
		frontend.Term{Variable: cs.MUL(l, l), Coeff: c1},
		frontend.Term{Variable: p.X, Coeff: c2},
		frontend.Term{Variable: p1.X, Coeff: c2},
	}

	// p.y = lambda(p.x-xr) - p.y
	t1 := cs.MUL(p.X, l)
	t2 := cs.MUL(l, _x)
	l3 := frontend.LinearCombination{
		frontend.Term{Variable: t1, Coeff: c1},
		frontend.Term{Variable: t2, Coeff: c2},
		frontend.Term{Variable: p.Y, Coeff: c2},
	}
	p.Y = cs.MUL(l3, 1)

	//p.x = xr
	p.X = cs.MUL(_x, 1)
	return p
}

// AssignToRefactor sets p to p1 and return it
func (p *G1Jac) AssignToRefactor(cs *frontend.CS, p1 *G1Jac) *G1Jac {
	p.X = cs.ALLOCATE(p1.X)
	p.Y = cs.ALLOCATE(p1.Y)
	p.Z = cs.ALLOCATE(p1.Z)
	return p
}

// AssignToRefactor sets p to p1 and return it
func (p *G1Affine) AssignToRefactor(cs *frontend.CS, p1 *G1Affine) *G1Affine {
	p.X = cs.ALLOCATE(p1.X)
	p.Y = cs.ALLOCATE(p1.Y)
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(cs *frontend.CS, p1 *G1Jac) *G1Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V frontend.Variable

	Z1Z1 = cs.MUL(p1.Z, p1.Z)

	Z2Z2 = cs.MUL(p.Z, p.Z)

	U1 = cs.MUL(p1.X, Z2Z2)

	U2 = cs.MUL(p.X, Z1Z1)

	S1 = cs.MUL(p1.Y, p.Z)
	S1 = cs.MUL(S1, Z2Z2)

	S2 = cs.MUL(p.Y, p1.Z)
	S2 = cs.MUL(S2, Z1Z1)

	H = cs.SUB(U2, U1)

	I = cs.ADD(H, H)
	I = cs.MUL(I, I)

	J = cs.MUL(H, I)

	r = cs.SUB(S2, S1)
	r = cs.ADD(r, r)

	V = cs.MUL(U1, I)

	p.X = cs.MUL(r, r)
	p.X = cs.SUB(p.X, J)
	p.X = cs.SUB(p.X, V)
	p.X = cs.SUB(p.X, V)

	p.Y = cs.SUB(V, p.X)
	p.Y = cs.MUL(p.Y, r)

	S1 = cs.MUL(J, S1)
	S1 = cs.ADD(S1, S1)

	p.Y = cs.SUB(p.Y, S1)

	p.Z = cs.ADD(p.Z, p1.Z)
	p.Z = cs.MUL(p.Z, p.Z)
	p.Z = cs.SUB(p.Z, Z1Z1)
	p.Z = cs.SUB(p.Z, Z2Z2)
	p.Z = cs.MUL(p.Z, H)

	return p
}

// DoubleAssign doubles the receiver point in jacobian coords and returns it
func (p *G1Jac) DoubleAssign(cs *frontend.CS) *G1Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T frontend.Variable

	XX = cs.MUL(p.X, p.X)
	YY = cs.MUL(p.Y, p.Y)
	YYYY = cs.MUL(YY, YY)
	ZZ = cs.MUL(p.Z, p.Z)
	S = cs.ADD(p.X, YY)
	S = cs.MUL(S, S)
	S = cs.SUB(S, XX)
	S = cs.SUB(S, YYYY)
	S = cs.ADD(S, S)
	M = cs.MUL(XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z = cs.ADD(p.Z, p.Y)
	p.Z = cs.MUL(p.Z, p.Z)
	p.Z = cs.SUB(p.Z, YY)
	p.Z = cs.SUB(p.Z, ZZ)
	p.X = cs.MUL(M, M)
	T = cs.ADD(S, S)
	p.X = cs.SUB(p.X, T)
	p.Y = cs.SUB(S, p.X)
	p.Y = cs.MUL(p.Y, M)
	YYYY = cs.MUL(YYYY, 8)
	p.Y = cs.SUB(p.Y, YYYY)

	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G1Affine) Select(cs *frontend.CS, b frontend.Variable, p1, p2 *G1Affine) *G1Affine {

	p.X = cs.SELECT(b, p1.X, p2.X)
	p.Y = cs.SELECT(b, p1.Y, p2.Y)

	return p

}

// FromJac sets p to p1 in affine and returns it
func (p *G1Affine) FromJac(cs *frontend.CS, p1 *G1Jac) *G1Affine {
	s := cs.MUL(p1.Z, p1.Z)
	p.X = cs.DIV(p1.X, s)
	p.Y = cs.DIV(p1.Y, cs.MUL(s, p1.Z))
	return p
}

// Double double a point in affine coords
func (p *G1Affine) Double(cs *frontend.CS, p1 *G1Affine) *G1Affine {

	var t, d, c1, c2, c3 big.Int
	t.SetInt64(3)
	d.SetInt64(2)
	c1.SetInt64(1)
	c2.SetInt64(-2)
	c3.SetInt64(-1)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	x2 := cs.MUL(p1.X, p1.X)
	cs.MUL(p1.X, p1.X)
	l1 := frontend.LinearCombination{
		frontend.Term{Variable: x2, Coeff: t},
	}
	l2 := frontend.LinearCombination{
		frontend.Term{Variable: p1.Y, Coeff: d},
	}
	l := cs.DIV(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x := frontend.LinearCombination{
		frontend.Term{Variable: cs.MUL(l, l), Coeff: c1},
		frontend.Term{Variable: p1.X, Coeff: c2},
	}

	// p.y = lambda(p.x-xr) - p.y
	t1 := cs.MUL(p1.X, l)
	t2 := cs.MUL(l, _x)
	l3 := frontend.LinearCombination{
		frontend.Term{Variable: t1, Coeff: c1},
		frontend.Term{Variable: t2, Coeff: c3},
		frontend.Term{Variable: p1.Y, Coeff: c3},
	}
	p.Y = cs.MUL(l3, 1)

	//p.x = xr
	p.X = cs.MUL(_x, 1)
	return p
}

// ScalarMul computes scalar*p1, affect the result to p, and returns it.
// n is the number of bits used for the scalar mul.
// TODO it doesn't work if the scalar if 1, because it ends up doing P-P at the end, involving division by 0
// TODO add a panic if scalar == 1
func (p *G1Affine) ScalarMul(cs *frontend.CS, p1 *G1Affine, s interface{}, n int) *G1Affine {

	scalar := cs.ALLOCATE(s)

	var base, res G1Affine
	base.Double(cs, p1)
	res.AssignToRefactor(cs, p1)

	b := cs.TO_BINARY(scalar, n)

	var tmp G1Affine

	// start from 1 and use right-to-left scalar multiplication to avoid bugs due to incomplete addition law
	// (I don't see how to avoid that)
	for i := 1; i <= n-1; i++ {
		tmp.AssignToRefactor(cs, &res).AddAssign(cs, &base)
		res.Select(cs, b[i], &tmp, &res)
		base.Double(cs, &base)
	}

	// now check the lsb, if it's one, leave the result as is, otherwise substract P
	tmp.Neg(cs, p1).AddAssign(cs, &res)

	p.Select(cs, b[0], &res, &tmp)

	return p

}
