package frontend

// Variable is a circuit variable. All circuits and gadgets must declare their inputs
// as Variable . If frontend.Compile(circuit) is called, circuit's Variable will hold
// constraints used to build the constraint system and later on the R1CS
// if frontend.Compile() is not called (default value), a Variable can be assigned (Assign)
// a value, thus using circuit data's structure to statically assign inputs values before
// solving the R1CS (Prove) or Verifying a proof.
type Variable struct {
	constraintID int
	val          interface{}
}

// Assign value to self. Current implementation don't check if the variable was "compiled"
// through frontend.Compile(circuit)
func (cInput *Variable) Assign(value interface{}) {
	if cInput.val != nil {
		// TODO we may want to enforce that to the circuit-developper
		// panic("variable was already assigned")
	}
	if cInput.constraintID != 0 {
		// TODO we may want to enforce that to the circuit-developper
		// panic("can't assign value in a compiled circuit")
	}
	cInput.val = value
}

func (v Variable) id(cs *CS) int {
	if v.constraintID == 0 {
		panic("circuit not compiled")
	}
	return v.constraintID
}
