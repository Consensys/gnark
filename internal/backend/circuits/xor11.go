package circuits

func init() {
	var circuit, good, bad, public xorCircuit

	good.B0.Assign(1)
	good.B1.Assign(1)
	good.Y0.Assign(0)

	bad.B0.Assign(1)
	bad.B1.Assign(0)
	bad.Y0.Assign(0)

	public.Y0.Assign(0)

	addEntry("xor11", &circuit, &good, &bad, &public)
}
