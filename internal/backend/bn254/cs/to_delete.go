package cs

import (
	"fmt"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// --------------------------------------------------------------------
// R1CS

func printTerm(r *R1CS, t compiled.Term) {
	coeffID, id, _ := t.Unpack()
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

// --------------------------------------------------------------------
// sparse r1cs

func sprintTerm(r *SparseR1CS, t compiled.Term) {
	// coeffValue, coeffID, id, _ := t.Unpack()
	// if coeffValue == -1 || coeffValue == 0 || coeffValue == 1 || coeffValue == 2 {
	// 	fmt.Printf("%d*%d ", coeffValue, id)
	// } else {
	// 	c := r.Coefficients[coeffID]
	// 	fmt.Printf("%s*%d ", c.String(), id)
	// }
	coeffID, id, _ := t.Unpack()
	c := r.Coefficients[coeffID]
	fmt.Printf("%s*%d ", c.String(), id)
}

func sprintSparseR1c(r *SparseR1CS, l compiled.SparseR1C) {
	sprintTerm(r, l.L)
	fmt.Printf("+")
	sprintTerm(r, l.R)
	fmt.Printf("+(")
	sprintTerm(r, l.M[0])
	fmt.Printf(")*(")
	sprintTerm(r, l.M[1])
	fmt.Printf(")+")
	sprintTerm(r, l.O)
	fmt.Printf("+")
	c := r.Coefficients[l.K]
	fmt.Printf("%s=0", c.String())
}

func SPrintr1cs(r *SparseR1CS) {
	for i := 0; i < len(r.Constraints); i++ {
		sprintSparseR1c(r, r.Constraints[i])
		fmt.Println("")
	}
	for i := 0; i < len(r.Assertions); i++ {
		sprintSparseR1c(r, r.Assertions[i])
		fmt.Println("")
	}
}
