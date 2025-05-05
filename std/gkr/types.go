package gkr

import "github.com/consensys/gnark/frontend"

type Variable int // Variable represents a value in a GKR circuit.

// A Gate is a low-degree multivariate polynomial
type Gate struct {
	Evaluate    GateFunction // Evaluate the polynomial function defining the gate
	nbIn        int          // number of inputs
	degree      int          // total degree of the polynomial
	solvableVar int          // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
}

// Degree returns the total degree of the gate's polynomial e.g. Degree(xy²) = 3
func (g *Gate) Degree() int {
	return g.degree
}

// SolvableVar returns the index of a variable of degree 1 in the gate's polynomial. If there is no such variable, it returns -1.
func (g *Gate) SolvableVar() int {
	return g.solvableVar
}

// NbIn returns the number of inputs to the gate (its fan-in)
func (g *Gate) NbIn() int {
	return g.nbIn
}

// GateAPI is a limited version of frontend.API,
// allowing ring arithmetic operations
type GateAPI interface {
	// ---------------------------------------------------------------------------------------------
	// Arithmetic

	// Add returns res = i1+i2+...in
	Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable

	// MulAcc sets and return a = a + (b*c).
	//
	// ! The method may mutate a without allocating a new result. If the input
	// is used elsewhere, then first initialize new variable, for example by
	// doing:
	//
	//     acopy := api.Mul(a, 1)
	//     acopy = api.MulAcc(acopy, b, c)
	//
	// ! But it may not modify a, always use MulAcc(...) result for correctness.
	MulAcc(a, b, c frontend.Variable) frontend.Variable

	// Neg returns -i
	Neg(i1 frontend.Variable) frontend.Variable

	// Sub returns res = i1 - i2 - ...in
	Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable

	// Mul returns res = i1 * i2 * ... in
	Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable

	// Println behaves like fmt.Println but accepts frontend.Variable as parameter
	// whose value will be resolved at runtime when computed by the solver
	Println(a ...frontend.Variable)
}
type GateFunction func(GateAPI, ...frontend.Variable) frontend.Variable
