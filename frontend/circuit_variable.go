package frontend

import "github.com/consensys/gnark/internal/utils/debug"

// Variable is a circuit variable. All circuits and gadgets must declare their inputs
// as Variable . If frontend.Compile(circuit) is called, circuit's Variable will hold
// constraints used to build the constraint system and later on the R1CS
// if frontend.Compile() is not called (default value), a Variable can be assigned (Assign)
// a value, thus using circuit data's structure to statically assign inputs values before
// solving the R1CS (Prove) or Verifying a proof.
type Variable struct {
	cID int
	val interface{}
}

// Assign value to self. Current implementation don't check if the variable was "compiled"
// through frontend.Compile(circuit)
func (cInput *Variable) Assign(value interface{}) {
	if cInput.val != nil {
		// TODO we may want to enforce that to the circuit-developper
		// panic("variable was already assigned")
	}
	if cInput.cID != 0 {
		// TODO we may want to enforce that to the circuit-developper
		// panic("can't assign value in a compiled circuit")
	}
	cInput.val = value
}

// Set if the variable was compiled, overwrites its constraint attribute with other
func (cInput Variable) Set(other Variable) {
	if cInput.cID == 0 {
		panic("can't set variable -- circuit is not compiled")
	}
	cInput.cID = other.cID
	// cInput.constraint.Set(other.constraint)
}

func (cInput Variable) getExpressions(cs *CS) expression {
	debug.Assert(cInput.cID != 0, "circuit not compiled")
	return cs.Constraints[cInput.cID].exp
}

func (cInput Variable) id() int {
	debug.Assert(cInput.cID != 0, "circuit not compiled")
	return cInput.cID
}
func (cInput Variable) setOutputWire(cs *CS, wID int) {
	debug.Assert(cInput.cID != 0, "circuit not compiled")
	c := cs.Constraints[cInput.cID]
	c.wireID = wID
	cs.Constraints[cInput.cID] = c
}
func (cInput Variable) wireID(cs *CS) int {
	debug.Assert(cInput.cID != 0, "circuit not compiled")
	return cs.Constraints[cInput.cID].wireID
}
