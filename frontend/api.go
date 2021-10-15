package frontend

// API represents the available functions to circuit developers
type API interface {
	// Arithmetic
	Add(i1, i2 interface{}, in ...interface{}) Variable
	Sub(i1, i2 interface{}) Variable
	Neg(i1 interface{}) Variable
	Mul(i1, i2 interface{}, in ...interface{}) Variable
	Div(i1, i2 interface{}) Variable
	Inverse(v Variable) Variable

	// Bit operations
	ToBinary(a Variable, n ...int) []Variable
	FromBinary(b ...Variable) Variable
	Xor(a, b Variable) Variable
	Or(a, b Variable) Variable
	And(a, b Variable) Variable

	// Conditionals
	Select(b Variable, i1, i2 interface{}) Variable
	IsZero(a Variable) Variable

	// Constant returns a frontend.Variable representing a known value at compile time
	Constant(input interface{}) Variable

	// Assertions
	AssertIsEqual(i1, i2 interface{})
	AssertIsDifferent(i1, i2 interface{})
	AssertIsBoolean(v Variable)
	AssertIsLessOrEqual(v Variable, bound interface{})

	// Println behaves like fmt.Println but accepts frontend.Variable as parameter
	// whose value will be resolved at runtime when computed by the solver
	Println(a ...interface{})
}
