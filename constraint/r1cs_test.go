package constraint_test

import (
	"fmt"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

func ExampleR1CS_GetConstraints() {
	// build a constraint system; this is (usually) done by the frontend package
	// for this Example we want to manipulate the constraints and output a string representation
	// and build the linear expressions "manually".
	r1cs := cs.NewR1CS(0)

	ONE := r1cs.AddPublicVariable("1") // the "ONE" wire
	Y := r1cs.AddPublicVariable("Y")
	X := r1cs.AddSecretVariable("X")

	v0 := r1cs.AddInternalVariable() // X²
	v1 := r1cs.AddInternalVariable() // X³

	// coefficients
	cOne := r1cs.FromInterface(1)
	cFive := r1cs.FromInterface(5)

	// X² == X * X
	r1cs.AddConstraint(constraint.R1C{
		L: constraint.LinearExpression{r1cs.MakeTerm(&cOne, X)},
		R: constraint.LinearExpression{r1cs.MakeTerm(&cOne, X)},
		O: constraint.LinearExpression{r1cs.MakeTerm(&cOne, v0)},
	})

	// X³ == X² * X
	r1cs.AddConstraint(constraint.R1C{
		L: constraint.LinearExpression{r1cs.MakeTerm(&cOne, v0)},
		R: constraint.LinearExpression{r1cs.MakeTerm(&cOne, X)},
		O: constraint.LinearExpression{r1cs.MakeTerm(&cOne, v1)},
	})

	// Y == X³ + X + 5
	r1cs.AddConstraint(constraint.R1C{
		R: constraint.LinearExpression{r1cs.MakeTerm(&cOne, ONE)},
		L: constraint.LinearExpression{r1cs.MakeTerm(&cOne, Y)},
		O: constraint.LinearExpression{
			r1cs.MakeTerm(&cFive, ONE),
			r1cs.MakeTerm(&cOne, X),
			r1cs.MakeTerm(&cOne, v1),
		},
	})

	// get the constraints
	constraints, r := r1cs.GetConstraints()

	for _, r1c := range constraints {
		fmt.Println(r1c.String(r))
		// for more granularity use constraint.NewStringBuilder(r) that embeds a string.Builder
		// and has WriteLinearExpression and WriteTerm methods.
	}

	// Output:
	// X ⋅ X == v0
	// v0 ⋅ X == v1
	// Y ⋅ 1 == 5 + X + v1
}
