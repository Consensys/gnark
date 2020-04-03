package circuits

func init() {
	// circuit := frontend.New()

	// x := circuit.SECRET_INPUT("x")
	// y := circuit.SECRET_INPUT("y")
	// z := circuit.PUBLIC_INPUT("z")
	// m := circuit.MUL(x, x)
	// d := circuit.DIV(m, y)
	// circuit.MUSTBE_EQ(d, z)

	// // expected z
	// var expectedY, expectedZ big.Int
	// expectedY.SetUint64(10)
	// expectedZ.SetUint64(4)
	// // TODO mod div here
	// expectedZ.MulAssign(&expectedZ).Div(&expectedZ, &expectedY)

	// good := backend.NewAssignment()
	// good.Assign(backend.Secret, "x", 4)
	// good.Assign(backend.Secret, "y", 10)
	// good.Assign(backend.Public, "z", expectedZ)

	// bad := backend.NewAssignment()
	// bad.Assign(backend.Secret, "x", 4)
	// bad.Assign(backend.Secret, "y", 10)
	// bad.Assign(backend.Public, "z", 42)

	// r1cs := circuit.ToR1CS()
	// addEntry("div", r1cs, good, bad)
}
