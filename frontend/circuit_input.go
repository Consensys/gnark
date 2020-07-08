package frontend

type circuitInput struct {
	val interface{}
}

func (cInput *circuitInput) Assign(value interface{}) {
	if cInput.val != nil {
		panic("val already set")
	}
	cInput.val = value
}

func (cInput *circuitInput) Set(CircuitVariable) {
	panic("not supported: this is not a constraint but a fixed value")
}
func (cInput *circuitInput) getExpressions() []expression {
	panic("not supported: this is not a constraint but a fixed value")
}
func (cInput *circuitInput) addExpressions(...expression) {
	panic("not supported: this is not a constraint but a fixed value")
}
func (cInput *circuitInput) setID(uint64) {
	panic("not supported: this is not a constraint but a fixed value")
}
func (cInput *circuitInput) id() uint64 {
	panic("not supported: this is not a constraint but a fixed value")
}
func (cInput *circuitInput) setOutputWire(*wire) {
	panic("not supported: this is not a constraint but a fixed value")
}
func (cInput *circuitInput) getOutputWire() *wire {
	panic("not supported: this is not a constraint but a fixed value")
}

func (cInput *circuitInput) Tag(string) {
	panic("not supported: this is not a constraint but a fixed value")
}
