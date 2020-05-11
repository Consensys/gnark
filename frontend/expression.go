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

package frontend

import (
	"math/big"
	"strconv"
)

// expression [of constraints] represents the lowest level of circuit design
// Inspired from ZCash specs
// When designing a circuit, one has access to (in increasing order of level):
// 	- constraint that generates new inputs (basic constraints)
// 	- gadgets (built out of basic constraints, such as boolean constraint)
// An expression is a mathematical expression in given number of variables that can be evaluated,
// and whose result is another wire. At most, quadratic operations appear in an expression.
// The goal of an expression is to exploit the R1cs struct in all way possible.
// For instance, a selection constraint b(y-x)=(x-z) (where z is the ouput), corresponds
// to the expression x-b(y-x), because evaluating this expression yields z.
// Though x-b(y-x) is not a r1cs: to convert it to a r1cs constraint, one needs a
// function toR1CS.
// Ex: toR1CS(x-b(y-x), z) -> b(y-x)=(x-z), it is now a R1cs.
// To evaluate an expression (for the computational graph to instantiate the variables),
// one also needs a function Compute.
// For the computatinal graph one needs to know which wires are used in a given expression
// Finally, when one equals two constraints, some wires might be merged and replaced,
// so one needs a function replaceWire(oldWire, newWire)
// The bound in the number of expressions is only limited by the fact that we use a r1cs system.
type expression interface {
	consumeWires()                            // used during the conversion to r1cs: tells what variables are consumed (useful for the post ordering)
	replaceWire(oldWire, newWire *wire)       // replace a wire in the expression (used when equal is called on two constraints)
	toR1CS(oneWire *wire, wires ...*wire) R1C // turns an expression into a r1cs (ex: toR1cs on a selection constraint x-b(y-x) yields: b(y-x)=z-x)
	string() string                           // implement string interface
}

// Multi Output expression
type moExpression interface {
	setConstraintID(id int64) // set the wire's constraintID to n for the wires that don't have this field set yet
	expression
}

type operationType int

const (
	mul operationType = iota
	div
)

// term expression of type coef*wire
type term struct {
	Wire      *wire
	Coeff     big.Int
	Operation operationType
}

func (t *term) consumeWires() {
	t.Wire.IsConsumed = true
}

func (t *term) replaceWire(oldWire, newWire *wire) {
	if t.Wire == oldWire {
		t.Wire = newWire
	}
}

func (t *term) toR1CS(oneWire *wire, wires ...*wire) R1C {
	var L, R, O LinearExpression
	switch t.Operation {
	case mul:
		L = LinearExpression{
			ToRefactorTerm{ID: t.Wire.WireID, Coeff: t.Coeff},
		}

		R = LinearExpression{
			ToRefactorTerm{ID: oneWire.WireID, Coeff: bigOne()},
		}

		O = LinearExpression{
			ToRefactorTerm{ID: wires[0].WireID, Coeff: bigOne()},
		}
	case div:
		L = LinearExpression{
			ToRefactorTerm{ID: t.Wire.WireID, Coeff: t.Coeff},
		}

		R = LinearExpression{
			ToRefactorTerm{ID: wires[0].WireID, Coeff: bigOne()},
		}

		O = LinearExpression{
			ToRefactorTerm{ID: oneWire.WireID, Coeff: bigOne()},
		}
	default:
		panic("unimplemented operation type")
	}

	return R1C{
		L:      L,
		R:      R,
		O:      O,
		Solver: SingleOutput,
	}
}

func (t *term) string() string {
	res := ""
	tmp := t.Coeff //.ToRegular()
	if t.Operation == mul {
		res = res + tmp.String() + t.Wire.String()
	} else {
		res = res + "(" + res + tmp.String() + t.Wire.String() + ")**-1"
	}
	return res
}

// linearExpression linear expression of constraints
type linearExpression []term

func (l *linearExpression) consumeWires() {
	for _, t := range *l {
		t.consumeWires()
	}
}

func (l *linearExpression) replaceWire(oldWire, newWire *wire) {

	// replace
	for _, t := range *l {
		if t.Wire == oldWire {
			t.Wire = newWire
		}
	}

	// reduce (sum the duplicates)
	for i := 0; i < len(*l); i++ {
		for j := i + 1; j < len(*l); j++ {
			if (*l)[j].Wire == (*l)[i].Wire {
				(*l)[i].Coeff.Add(&(*l)[i].Coeff, &(*l)[j].Coeff)
				if j == len(*l)-1 {
					*l = (*l)[:j]
				} else {
					*l = append((*l)[:j], (*l)[j+1:]...)
				}
				break // a wire can appear only twice if the reduce rule is respected
			}
		}
	}
}

func (l *linearExpression) toR1CS(constWire *wire, w ...*wire) R1C {

	left := LinearExpression{}
	for _, t := range *l {
		lwt := ToRefactorTerm{ID: t.Wire.WireID, Coeff: t.Coeff}
		left = append(left, lwt)
	}

	right := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: bigOne()},
	}

	o := LinearExpression{
		ToRefactorTerm{ID: w[0].WireID, Coeff: bigOne()},
	}

	return R1C{L: left, R: right, O: o, Solver: SingleOutput}
}

func (l *linearExpression) string() string {
	res := ""
	for _, t := range *l {
		res += t.string()
		res += "+"
	}
	res = res[:len(res)-1]
	return res
}

// quadraticExpression quadratic expression of constraints
type quadraticExpression struct {
	left, right linearExpression // in case of division, left is the denominator, right the numerator
	operation   operationType    // type op operation (left*right or right/left)
}

func (q *quadraticExpression) consumeWires() {
	q.left.consumeWires()
	q.right.consumeWires()
}

func (q *quadraticExpression) replaceWire(oldWire, newWire *wire) {
	for _, t := range q.left {
		if t.Wire == oldWire {
			t.Wire = newWire
		}
	}
	for _, t := range q.right {
		if t.Wire == oldWire {
			t.Wire = newWire
		}
	}
}

func (q *quadraticExpression) toR1CS(constWire *wire, w ...*wire) R1C {

	switch q.operation {
	case mul:
		L := LinearExpression{}
		for _, t := range q.left {
			L = append(L, ToRefactorTerm{ID: t.Wire.WireID, Coeff: t.Coeff})
		}

		R := LinearExpression{}
		for _, t := range q.right {
			R = append(R, ToRefactorTerm{ID: t.Wire.WireID, Coeff: t.Coeff})
		}

		O := LinearExpression{
			ToRefactorTerm{ID: w[0].WireID, Coeff: bigOne()},
		}

		return R1C{L: L, R: R, O: O, Solver: SingleOutput}
	case div:
		L := LinearExpression{}

		for _, t := range q.left {
			L = append(L, ToRefactorTerm{ID: t.Wire.WireID, Coeff: t.Coeff})
		}

		R := LinearExpression{
			ToRefactorTerm{ID: w[0].WireID, Coeff: bigOne()},
		}

		O := LinearExpression{}
		for _, t := range q.right {
			O = append(O, ToRefactorTerm{ID: t.Wire.WireID, Coeff: t.Coeff})
		}

		return R1C{L: L, R: R, O: O}
	default:
		panic("unimplemented operation")
	}
}

func (q *quadraticExpression) string() string {
	var res string
	if q.operation == mul {
		res = "("
		res = res + q.left.string() + ")*(" + q.right.string() + ")"
	} else {
		res = res + q.right.string() + "*" + q.left.string() + "^-1"
		return res
	}
	return res
}

// selectExpression expression used to select a value according to a boolean evaluation
// b(y-x)=(y-z)
type selectExpression struct {
	b, x, y *wire
}

func (s *selectExpression) consumeWires() {
	s.b.IsConsumed = true
	s.x.IsConsumed = true
	s.y.IsConsumed = true
}

func (s *selectExpression) replaceWire(oldWire, newWire *wire) {
	if s.b == oldWire {
		s.b = newWire
	}
	if s.x == oldWire {
		s.x = newWire
	}
	if s.y == oldWire {
		s.y = newWire
	}
}

func (s *selectExpression) toR1CS(constWire *wire, w ...*wire) R1C {

	var minusOne big.Int
	one := bigOne()
	minusOne.Neg(&one)

	L := LinearExpression{
		ToRefactorTerm{ID: s.b.WireID, Coeff: one},
	}

	R := LinearExpression{
		ToRefactorTerm{ID: s.y.WireID, Coeff: one},
		ToRefactorTerm{ID: s.x.WireID, Coeff: minusOne},
	}

	O := LinearExpression{
		ToRefactorTerm{ID: s.y.WireID, Coeff: one},
		ToRefactorTerm{ID: w[0].WireID, Coeff: minusOne},
	}
	return R1C{L: L, R: R, O: O, Solver: SingleOutput}
}

func (s *selectExpression) string() string {
	res := ""
	res = res + s.x.String() + "-" + s.b.String()
	res = res + "*(" + s.y.String() + "-" + s.x.String() + ")"
	return res
}

// xorExpression expression used to compute the xor between two variables
// (2*a)b = (a+b-c)
type xorExpression struct {
	a, b *wire
}

func (x *xorExpression) consumeWires() {
	x.a.IsConsumed = true
	x.b.IsConsumed = true
}

func (x *xorExpression) replaceWire(oldWire, newWire *wire) {

	if x.a == oldWire {
		x.a = newWire
	}
	if x.b == oldWire {
		x.b = newWire
	}
}

func (x *xorExpression) toR1CS(constWire *wire, w ...*wire) R1C {

	var minusOne, two big.Int
	one := bigOne()
	minusOne.Neg(&one)
	two.SetUint64(2)

	L := LinearExpression{
		ToRefactorTerm{ID: x.a.WireID, Coeff: two},
	}

	R := LinearExpression{
		ToRefactorTerm{ID: x.b.WireID, Coeff: one},
	}

	O := LinearExpression{
		ToRefactorTerm{ID: x.a.WireID, Coeff: one},
		ToRefactorTerm{ID: x.b.WireID, Coeff: one},
		ToRefactorTerm{ID: w[0].WireID, Coeff: minusOne},
	}

	return R1C{L: L, R: R, O: O, Solver: SingleOutput}
}

func (x *xorExpression) string() string {
	res := ""
	res = res + x.a.String() + "+" + x.b.String()
	res = res + "-2*" + x.a.String() + "*" + x.b.String()
	return res
}

// unpackExpression expression used to unpack a variable in binary (bits[i]*2^i = res)
type unpackExpression struct {
	bits []*wire
	res  *wire
}

func (u *unpackExpression) consumeWires() {
	u.res.IsConsumed = true
}

func (u *unpackExpression) replaceWire(oldWire, newWire *wire) {

	for i := range u.bits {
		if u.bits[i] == oldWire {
			u.bits[i] = newWire
		}
	}
	if u.res == oldWire {
		u.res = newWire
	}

}

func (u *unpackExpression) toR1CS(constWire *wire, w ...*wire) R1C {
	var two big.Int
	one := bigOne()
	two.SetUint64(2)

	// L
	left := LinearExpression{}
	acc := bigOne()
	for _, b := range u.bits {
		var tmp big.Int
		tmp.Set(&acc)
		left = append(left, ToRefactorTerm{ID: b.WireID, Coeff: tmp})
		acc.Mul(&acc, &two)
	}

	// R
	right := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: one},
	}

	// O
	o := LinearExpression{
		ToRefactorTerm{ID: u.res.WireID, Coeff: one},
	}

	return R1C{L: left, R: right, O: o, Solver: BinaryDec}
}

func (u *unpackExpression) setConstraintID(n int64) {
	for _, w := range u.bits {
		w.ConstraintID = n
	}
}

func (u *unpackExpression) string() string {

	res := ""
	for i, b := range u.bits {
		res += b.String() + "*2^" + strconv.Itoa(i) + "+"
	}
	res = res[:len(res)-1]
	res += " = " + u.res.String()
	return res
}

// packing expression
type packExpression struct {
	bits []*wire
}

func (p *packExpression) consumeWires() {
	for _, w := range p.bits {
		w.IsConsumed = true
	}
}

func (p *packExpression) replaceWire(oldWire, newWire *wire) {
	for i := range p.bits {
		if p.bits[i] == oldWire {
			p.bits[i] = newWire
		}
	}
}

func (p *packExpression) toR1CS(constWire *wire, w ...*wire) R1C {
	var two big.Int
	one := bigOne()
	two.SetUint64(2)

	// L
	left := LinearExpression{}
	acc := bigOne()
	for _, b := range p.bits {
		var tmp big.Int
		tmp.Set(&acc)
		lwtl := ToRefactorTerm{ID: b.WireID, Coeff: tmp}
		left = append(left, lwtl)
		acc.Mul(&acc, &two)
	}

	// R
	right := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: one},
	}

	// O
	o := LinearExpression{
		ToRefactorTerm{ID: w[0].WireID, Coeff: one},
	}

	return R1C{L: left, R: right, O: o, Solver: SingleOutput}
}

func (p *packExpression) string() string {
	res := ""
	for i, b := range p.bits {
		res += b.String() + "*2^" + strconv.Itoa(i) + "+"
	}
	res = res[:len(res)-1]
	return res
}

// boolean constraint
type booleanExpression struct {
	b *wire
}

func (b *booleanExpression) consumeWires() {
}

func (b *booleanExpression) replaceWire(oldWire, newWire *wire) {
	if b.b == oldWire {
		b.b = newWire
	}
}

func (b *booleanExpression) toR1CS(constWire *wire, w ...*wire) R1C {

	var minusOne, zero big.Int
	one := bigOne()
	minusOne.Neg(&one)

	L := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: one},
		ToRefactorTerm{ID: b.b.WireID, Coeff: minusOne},
	}

	R := LinearExpression{
		ToRefactorTerm{ID: b.b.WireID, Coeff: one},
	}

	O := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: zero},
	}

	return R1C{L: L, R: R, O: O}
}

func (b *booleanExpression) string() string {

	res := "(1-"
	res = res + b.b.String() + ")*(" + b.b.String() + ")=0"
	return res
}

// eqConstExp wire is equal to a constant
type eqConstantExpression struct {
	v big.Int
}

func (e *eqConstantExpression) consumeWires() {}

func (e *eqConstantExpression) replaceWire(oldWire, newWire *wire) {}

func (e *eqConstantExpression) toR1CS(constWire *wire, w ...*wire) R1C {

	// L
	L := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: e.v},
	}

	// R
	R := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: bigOne()},
	}

	// O
	O := LinearExpression{
		ToRefactorTerm{ID: w[0].WireID, Coeff: bigOne()},
	}

	return R1C{L: L, R: R, O: O, Solver: SingleOutput}
}

func (e *eqConstantExpression) string() string {
	_v := e.v //.ToRegular()
	return _v.String()
}

// implyExpression implication constraint: if b is 1 then a is 0
type implyExpression struct {
	b, a *wire
}

func (i *implyExpression) consumeWires() {
}

func (i *implyExpression) replaceWire(oldWire, newWire *wire) {
	if i.b == oldWire {
		i.b = newWire
	}
	if i.a == oldWire {
		i.a = newWire
	}
}

func (i *implyExpression) toR1CS(constWire *wire, w ...*wire) R1C {

	var one, minusOne, zero big.Int
	one.SetUint64(1)
	minusOne.Neg(&one)

	L := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: one},
		ToRefactorTerm{ID: i.b.WireID, Coeff: minusOne},
		ToRefactorTerm{ID: i.a.WireID, Coeff: minusOne},
	}

	R := LinearExpression{
		ToRefactorTerm{ID: i.a.WireID, Coeff: one},
	}

	O := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: zero},
	}

	return R1C{L: L, R: R, O: O, Solver: SingleOutput}
}

func (i *implyExpression) string() string {
	res := ""
	res = res + "(1 - " + i.b.String() + " - " + i.a.String() + ")*( " + i.a.String() + ")=0"
	return res
}

// lutExpression lookup table constraint, selects the i-th entry in the lookup table where i=2*bit1+bit0
// cf https://z.cash/technology/jubjub/
type lutExpression struct {
	b0, b1      *wire
	lookuptable [4]big.Int
}

func (win *lutExpression) consumeWires() {
	win.b0.IsConsumed = true
	win.b1.IsConsumed = true
}

func (win *lutExpression) replaceWire(oldWire, newWire *wire) {
	if win.b0 == oldWire {
		win.b0 = newWire
	}
	if win.b1 == oldWire {
		win.b1 = newWire
	}
}

func (win *lutExpression) toR1CS(constWire *wire, w ...*wire) R1C {
	var t0, t1, t2, t3 big.Int

	// L
	L := LinearExpression{
		ToRefactorTerm{ID: win.b0.WireID, Coeff: bigOne()},
	}

	t0.Neg(&win.lookuptable[0]).
		Add(&t0, &win.lookuptable[1])
	t1.Sub(&win.lookuptable[0], &win.lookuptable[1]).
		Sub(&t1, &win.lookuptable[2]).
		Add(&t1, &win.lookuptable[3])
	// R
	R := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: t0},
		ToRefactorTerm{ID: win.b1.WireID, Coeff: t1},
	}

	t2.Neg(&win.lookuptable[0])
	t3.Set(&win.lookuptable[0])
	t3.Sub(&t3, &win.lookuptable[2])
	// O
	O := LinearExpression{
		ToRefactorTerm{ID: constWire.WireID, Coeff: t2},
		ToRefactorTerm{ID: win.b1.WireID, Coeff: t3},
		ToRefactorTerm{ID: w[0].WireID, Coeff: bigOne()},
	}

	return R1C{L: L, R: R, O: O, Solver: SingleOutput}
}

func (win *lutExpression) string() string {

	var lookuptablereg [4]big.Int
	for i := 0; i < 4; i++ {
		lookuptablereg[i] = win.lookuptable[i] //.ToRegular()
	}

	res := "(" + win.b0.String() + ")*("
	res = res + "-" + lookuptablereg[0].String()
	res = res + "+" + lookuptablereg[0].String() + "*" + win.b1.String() + "+" + lookuptablereg[1].String()
	res = res + "-" + lookuptablereg[1].String() + "*" + win.b1.String()
	res = res + "-" + lookuptablereg[2].String() + "*" + win.b1.String()
	res = res + "+" + lookuptablereg[3].String() + "*" + win.b1.String() + ")="
	res = res + lookuptablereg[0].String() + "-" + lookuptablereg[0].String() + "*" + win.b1.String()
	res = res + "+" + lookuptablereg[2].String() + "*" + win.b1.String()
	return res
}
