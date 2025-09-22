package gkr

import "github.com/consensys/gnark/frontend"

// Variable represents a value in a GKR circuit.
type Variable int

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

	// Exp returns res = iᵉ
	Exp(i frontend.Variable, e uint8) frontend.Variable

	// Println behaves like fmt.Println but accepts frontend.Variable as parameter
	// whose value will be resolved at runtime when computed by the solver
	Println(a ...frontend.Variable)
}

// GateFunction is a function that evaluates a polynomial over its inputs
// using the given GateAPI.
// It is used to define custom gates in GKR circuits.
type GateFunction func(GateAPI, ...frontend.Variable) frontend.Variable

// GateName is a string representing a (human-readable) name for a GKR gate.
type GateName string

const (
	// Identity gate: x -> x
	Identity GateName = "identity"

	// Add2 gate: (x, y) -> x + y
	Add2 GateName = "add2"

	// Sub2 gate: (x, y) -> x - y
	Sub2 GateName = "sub2"

	// Neg gate: x -> -x
	Neg GateName = "neg"

	// Mul2 gate: (x, y) -> x * y
	Mul2 GateName = "mul2"
)
