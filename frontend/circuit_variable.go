package frontend

import "math/big"

// Variable is a circuit variable. All circuits must declare their inputs
// as Variable . If frontend.Compile(circuit) is called, circuit's Variable will hold
// constraints used to build the constraint system and later on the R1CS
// if frontend.Compile() is not called (default value), a Variable can be assigned (Assign)
// a value, thus using circuit data's structure to statically assign inputs values before
// solving the R1CS (Prove) or Verifying a proof.
type Variable struct {
	constraintID int
	val          interface{}
}

// Assign value to self. Doesn't check if the variable was "compiled" through frontend.Compile(circuit)
func (v *Variable) Assign(value interface{}) {
	if v.val != nil {
		panic("variable already assigned")
	}
	if v.constraintID != 0 {
		panic("circuit was compiled, can't be used as a witness")
	}
	v.val = value
}

func (v Variable) id() int {
	if v.constraintID == 0 {
		panic("circuit not compiled")
	}
	return v.constraintID
}

// Term coeff*c
type Term struct {
	Variable Variable
	Coeff    big.Int
}

// LinearCombination linear combination of constraints
type LinearCombination []Term
