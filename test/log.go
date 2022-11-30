package test

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	"strconv"
	"strings"
)

func printConstraints(_cs frontend.CompiledConstraintSystem) {
	_r1cs := _cs.(*cs.R1CS)
	for _, constraint := range _r1cs.Constraints {
		fmt.Print("(")
		printVariable(constraint.L, _r1cs)
		fmt.Print(") * (")
		printVariable(constraint.R, _r1cs)
		fmt.Print(") - ")
		printVariable(constraint.O, _r1cs)
		fmt.Println(" = 0")
	}
}

func printVariable(le compiled.LinearExpression, _r1cs *cs.R1CS) {
	var sbb strings.Builder
	writeVariable(le, _r1cs, &sbb)
	fmt.Print(sbb.String())
}

func writeVariable(le compiled.LinearExpression, _r1cs *cs.R1CS, sbb *strings.Builder) {
	sbb.Grow(len(le) * len(" + (xx + xxxxxxxxxxxx"))

	for i := 0; i < len(le); i++ {
		if i > 0 {
			sbb.WriteString(" + ")
		}
		writeTerm(le[i], _r1cs, sbb)
	}
}

func writeTerm(t compiled.Term, _r1cs *cs.R1CS, sbb *strings.Builder) {
	// virtual == only a coeff, we discard the wire
	cID, vID, vis := t.Unpack()
	if vis == schema.Public && vID == 0 {
		sbb.WriteString(_r1cs.Coefficients[t.CoeffID()].Text(10))
		t.SetVariableVisibility(schema.Virtual)
		return
	}

	if cID == compiled.CoeffIdMinusOne {
		sbb.WriteString("-")
	} else if cID != compiled.CoeffIdOne {
		sbb.WriteString("%s*")
	}
	variableName(vID, &_r1cs.R1CS, sbb)
}

func variableName(id int, _r1cs *compiled.R1CS, sbb *strings.Builder) {
	if id < _r1cs.NbPublicVariables {
		sbb.WriteString(_r1cs.Public[id])
	} else if secretID := id - _r1cs.NbPublicVariables; secretID < _r1cs.NbSecretVariables {
		sbb.WriteString(_r1cs.Secret[secretID])
	} else {
		sbb.WriteString("v")
		sbb.WriteString(strconv.Itoa(id))
	}
}
