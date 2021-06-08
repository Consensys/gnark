package cs

import (
	"fmt"

	"github.com/consensys/gnark/internal/backend/compiled"
)

func printTerm(r *R1CS, t compiled.Term) {
	_, coeffID, id, _ := t.Unpack()
	c := r.Coefficients[coeffID]
	fmt.Printf("%s*%d ", c.String(), id)
}

func printLinearExp(r *R1CS, l compiled.LinearExpression) {
	for i := 0; i < len(l); i++ {
		printTerm(r, l[i])
		fmt.Printf("+")
	}
}

func printConstraint(r *R1CS, c compiled.R1C) {
	fmt.Printf("(")
	printLinearExp(r, c.L)
	fmt.Printf(")x(")
	printLinearExp(r, c.R)
	fmt.Printf(")=")
	printLinearExp(r, c.O)
}

func Printr1cs(r *R1CS) {
	for i := 0; i < len(r.Constraints); i++ {
		printConstraint(r, r.Constraints[i])
		fmt.Println("")
	}
}
