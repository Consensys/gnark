package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type rangeCheckConstantCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *rangeCheckConstantCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	c1 := cs.Mul(circuit.X, circuit.Y)
	c2 := cs.Mul(c1, circuit.Y)

	cs.AssertIsLessOrEqual(c2, 161)
	return nil
}

func rangeCheckConstant() {
	var circuit, good, bad rangeCheckConstantCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.X.Assign(10)
	good.Y.Assign(4)

	bad.X.Assign(10)
	bad.Y.Assign(5)

	addEntry("range_constant", r1cs, &good, &bad)
}

type rangeCheckCircuit struct {
	X        frontend.Variable
	Y, Bound frontend.Variable `gnark:",public"`
}

func (circuit *rangeCheckCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	c1 := cs.Mul(circuit.X, circuit.Y)
	c2 := cs.Mul(c1, circuit.Y)

	cs.AssertIsLessOrEqual(c2, circuit.Bound)

	return nil
}

func rangeCheck() {

	var circuit, good, bad rangeCheckCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.X.Assign(10)
	good.Y.Assign(4)
	good.Bound.Assign(161)

	bad.X.Assign(10)
	bad.Y.Assign(5)
	bad.Bound.Assign(161)

	addEntry("range", r1cs, &good, &bad)
}

func init() {
	rangeCheckConstant()
	rangeCheck()
}
