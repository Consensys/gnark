package gkr

import "github.com/consensys/gnark/frontend"

type Variable int // Variable represents a value in a GKR circuit.

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

type GateName string

const (
	Identity GateName = "identity" // Identity gate: x -> x
	Add2     GateName = "add2"     // Add2 gate: (x, y) -> x + y
	Sub2     GateName = "sub2"     // Sub2 gate: (x, y) -> x - y
	Neg      GateName = "neg"      // Neg gate: x -> -x
	Mul2     GateName = "mul2"     // Mul2 gate: (x, y) -> x * y
)
