package frontend

type Variable struct {
	*constraint
	val interface{}
}

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

func (cInput Variable) Set(other Variable) {
	if cInput.constraint == nil {
		panic("can't set variable -- circuit is not compiled")
	}
	cInput.constraint.Set(other.constraint)
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
func (cInput Variable) setID(id uint64) {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	cInput.constraint.setID(id)
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

func (cInput Variable) Tag(tag string) {
	if cInput.constraint == nil {
		panic("circuit is not compiled")
	}
	cInput.constraint.Tag(tag)
}
