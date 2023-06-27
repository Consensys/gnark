package constraint_test

import (
	"fmt"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

func ExampleSparseR1CS_GetSparseR1Cs() {
	// build a constraint system; this is (usually) done by the frontend package
	// for this Example we want to manipulate the constraints and output a string representation
	// and build the linear expressions "manually".
	// note: R1CS apis are more mature; SparseR1CS apis are going to change in the next release(s).
	scs := cs.NewSparseR1CS(0)
	blueprint := scs.AddBlueprint(&constraint.BlueprintGenericSparseR1C{})

	Y := scs.AddPublicVariable("Y")
	X := scs.AddSecretVariable("X")

	v0 := scs.AddInternalVariable() // X²

	// coefficients
	cOne := scs.FromInterface(1)
	cFive := scs.FromInterface(5)

	// X² == X * X
	scs.AddSparseR1C(constraint.SparseR1C{
		XA: uint32(X),
		XB: uint32(X),
		XC: uint32(v0),
		QO: constraint.CoeffIdMinusOne,
		QM: constraint.CoeffIdOne,
	}, blueprint)

	// X² + 5X + 5 == Y
	scs.AddSparseR1C(constraint.SparseR1C{
		XA: uint32(X),
		XB: uint32(v0),
		XC: uint32(Y),
		QO: constraint.CoeffIdMinusOne,
		QL: scs.AddCoeff(cFive),
		QR: scs.AddCoeff(cOne),
		QC: scs.AddCoeff(cFive),
	}, blueprint)

	// get the constraints
	constraints := scs.GetSparseR1Cs()

	for _, c := range constraints {
		fmt.Println(c.String(scs))
		// for more granularity use constraint.NewStringBuilder(r) that embeds a string.Builder
		// and has WriteLinearExpression and WriteTerm methods.
	}

	// Output:
	// 0 + 0 + -1⋅v0 + 1⋅(X×X) + 0 == 0
	// 5⋅X + v0 + -1⋅Y + 5 == 0
}
