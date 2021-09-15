package circuits

func init() {
	var circuit, good, bad xorCircuit

	good.B0.Assign(0)
	good.B1.Assign(1)
	good.Y0.Assign(1)

	bad.B0.Assign(1)
	bad.B1.Assign(1)
	bad.Y0.Assign(1)

	addEntry("xor01", &circuit, &good, &bad)
}
