// Package gkrgate contains the definition of a GKR gate
package gkrtypes

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
)

// A Gate is a low-degree multivariate polynomial
type Gate struct {
	evaluate    gkr.GateFunction // Evaluate the polynomial function defining the gate
	nbIn        int              // number of inputs
	degree      int              // total degree of the polynomial
	solvableVar int              // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
}

func New(f gkr.GateFunction, nbIn int, degree int, solvableVar int) *Gate {
	return &Gate{
		evaluate:    f,
		nbIn:        nbIn,
		degree:      degree,
		solvableVar: solvableVar,
	}
}

func (g *Gate) Evaluate(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return g.evaluate(api, in...)
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

type errorString string

func (e errorString) Error() string {
	return string(e)
}

const ErrZeroFunction = errorString("detected a zero function")

// some sample gates

// Identity gate: x -> x
func Identity() *Gate {
	return New(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return in[0]
	}, 1, 1, 0)
}

// Add2 gate: (x, y) -> x + y
func Add2() *Gate {
	return New(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Add(in[0], in[1])
	}, 2, 1, 0)
}

// Sub2 gate: (x, y) -> x - y
func Sub2() *Gate {
	return New(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Sub(in[0], in[1])
	}, 2, 1, 0)
}

// Neg gate: x -> -x
func Neg() *Gate {
	return New(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Neg(in[0])
	}, 1, 1, 0)
}

// Mul2 gate: (x, y) -> x * y
func Mul2() *Gate {
	return New(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Mul(in[0], in[1])
	}, 2, 2, -1)
}
