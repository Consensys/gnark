package frontend

// Variable is a circuit variable. All circuits and gadgets must declare their inputs
// as Variable . If frontend.Compile(circuit) is called, circuit's Variable will hold
// constraints used to build the constraint system and later on the R1CS
// if frontend.Compile() is not called (default value), a Variable can be assigned (Assign)
// a value, thus using circuit data's structure to statically assign inputs values before
// solving the R1CS (Prove) or Verifying a proof.
type Variable struct {
	*constraint
	val interface{}
}

// Assign value to self. Current implementation don't check if the variable was "compiled"
// through frontend.Compile(circuit)
func (cInput *Variable) Assign(value interface{}) {
	if cInput.val != nil {
		// TODO we may want to enforce that to the circuit-developper
		// panic("variable was already assigned")
	}
	if cInput.constraint != nil {
		// TODO we may want to enforce that to the circuit-developper
		// panic("can't assign value in a compiled circuit")
	}
	cInput.val = value
}

// Set if the variable was compiled, overwrites its constraint attribute with other
func (cInput Variable) Set(other Variable) {
	if cInput.constraint == nil {
		panic("can't set variable -- circuit is not compiled")
	}
	cInput.constraint = other.constraint
}
func (cInput Variable) getExpressions() []expression {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	return cInput.constraint.getExpressions()
}
func (cInput Variable) addExpressions(e ...expression) {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	cInput.constraint.addExpressions(e...)
}

func (cInput Variable) id() uint64 {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	return cInput.constraint.id()
}
func (cInput Variable) setOutputWire(w *wire) {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	cInput.constraint.setOutputWire(w)
}
func (cInput Variable) getOutputWire() *wire {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	return cInput.constraint.getOutputWire()
}

// Tag for debugging purposes, allow to add a tag to a variable that was compiled
// see R1CS.Inspect()
func (cInput Variable) Tag(tag string) {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	cInput.constraint.Tag(tag)
}
