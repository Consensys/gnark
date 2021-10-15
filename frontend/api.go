package frontend

type API interface {
	Add(i1, i2 interface{}, in ...interface{}) Variable
	Sub(i1, i2 interface{}) Variable
	Neg(i1 interface{}) Variable

	Mul(i1, i2 interface{}, in ...interface{}) Variable

	Div(i1, i2 interface{}) Variable
	Inverse(v Variable) Variable

	Xor(a, b Variable) Variable
	Or(a, b Variable) Variable
	And(a, b Variable) Variable

	ToBinary(a Variable, n ...int) []Variable
	FromBinary(b ...Variable) Variable

	Select(b Variable, i1, i2 interface{}) Variable
	IsZero(a Variable) Variable

	Constant(input interface{}) Variable

	AssertIsEqual(i1, i2 interface{})
	AssertIsDifferent(i1, i2 interface{})
	AssertIsBoolean(v Variable)
	AssertIsLessOrEqual(v Variable, bound interface{})

	Println(a ...interface{})
}
