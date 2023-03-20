package constraint_test

import (
	"fmt"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

func ExampleSparseR1CS_GetConstraints() {
	// build a constraint system; this is (usually) done by the frontend package
	// for this Example we want to manipulate the constraints and output a string representation
	// and build the linear expressions "manually".
	// note: R1CS apis are more mature; SparseR1CS apis are going to change in the next release(s).
	scs := cs.NewSparseR1CS(0)

	Y := scs.AddPublicVariable("Y")
	X := scs.AddSecretVariable("X")

	v0 := scs.AddInternalVariable() // X²

	// coefficients
	cZero := scs.FromInterface(0)
	cOne := scs.FromInterface(1)
	cMinusOne := scs.FromInterface(-1)
	cFive := scs.FromInterface(5)

	// X² == X * X
	scs.AddConstraint(constraint.SparseR1C{
		L: scs.MakeTerm(&cZero, X),
		R: scs.MakeTerm(&cZero, X),
		O: scs.MakeTerm(&cMinusOne, v0),
		M: [2]constraint.Term{
			scs.MakeTerm(&cOne, X),
			scs.MakeTerm(&cOne, X),
		},
		K: int(scs.MakeTerm(&cZero, 0).CID),
	})

	// X² + 5X + 5 == Y
	scs.AddConstraint(constraint.SparseR1C{
		R: scs.MakeTerm(&cOne, v0),
		L: scs.MakeTerm(&cFive, X),
		O: scs.MakeTerm(&cMinusOne, Y),
		M: [2]constraint.Term{
			scs.MakeTerm(&cZero, v0),
			scs.MakeTerm(&cZero, X),
		},
		K: int(scs.MakeTerm(&cFive, 0).CID),
	})

	// get the constraints
	constraints, r := scs.GetConstraints()

	for _, c := range constraints {
		fmt.Println(c.String(r))
		// for more granularity use constraint.NewStringBuilder(r) that embeds a string.Builder
		// and has WriteLinearExpression and WriteTerm methods.
	}

	// Output:
	// 0 + 0 + -1⋅v0 + 1⋅(X×X) + 0 == 0
	// 5⋅X + v0 + -1⋅Y + 5 == 0
}
