package cs

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// r1cs
func (cs *R1CS) printTerm(t compiled.Term) string {
	coefID, varID, _ := t.Unpack()
	coef := cs.Coefficients[coefID]
	return fmt.Sprintf("%s*%d", coef.String(), varID)
}

func (cs *R1CS) printLinExp(l compiled.Variable) string {
	var sbb strings.Builder
	for i, t := range l.LinExp {
		sbb.WriteString(cs.printTerm(t))
		if i < len(l.LinExp)-1 {
			sbb.WriteString(" + ")
		}
	}
	return sbb.String()
}

func (cs *R1CS) Print() string {
	var sbb strings.Builder
	for i := 0; i < len(cs.Constraints); i++ {
		sbb.WriteString("(")
		sbb.WriteString(cs.printLinExp(cs.Constraints[i].L))
		sbb.WriteString(") * (")
		sbb.WriteString(cs.printLinExp(cs.Constraints[i].R))
		sbb.WriteString(" ) = ")
		sbb.WriteString(cs.printLinExp(cs.Constraints[i].O))
		sbb.WriteString("\n")
	}
	return sbb.String()
}

// // sparse r1cs
func (cs *SparseR1CS) printTerm(t compiled.Term) string {
	coefID, varID, _ := t.Unpack()
	coef := cs.Coefficients[coefID]
	return fmt.Sprintf("%s*%d", coef.String(), varID)

}

func (cs *SparseR1CS) Print() string {
	var sbb strings.Builder
	for i := 0; i < len(cs.Constraints); i++ {
		c := cs.Constraints[i]
		sbb.WriteString(cs.printTerm(c.L))
		sbb.WriteString(" + ")
		sbb.WriteString(cs.printTerm(c.R))
		sbb.WriteString(" + ( ")
		sbb.WriteString(cs.printTerm(c.M[0]))
		sbb.WriteString(" * ")
		sbb.WriteString(cs.printTerm(c.M[1]))
		sbb.WriteString(" ) + ")
		sbb.WriteString(cs.printTerm(c.O))
		sbb.WriteString(" + ")
		k := cs.Coefficients[c.K]
		sbb.WriteString(k.String())
		sbb.WriteString("\n")
	}
	return sbb.String()
}
