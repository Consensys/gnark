package compiled

import (
	"strings"
)

// LogEntry is used as a shared data structure between the frontend and the backend
// to represent string values (in logs or debug info) where a value is not known at compile time
// (which is the case for variables that need to be resolved in the R1CS)
type LogEntry struct {
	Format    string
	ToResolve []Term
}

func (l *LogEntry) WriteLinearExpression(le LinearExpression, sbb *strings.Builder) {
	sbb.Grow(len(le) * len(" + (xx + xxxxxxxxxxxx"))

	for i := 0; i < len(le); i++ {
		if i > 0 {
			sbb.WriteString(" + ")
		}
		l.WriteTerm(le[i], sbb)
	}
}

func (l *LogEntry) WriteTerm(t Term, sbb *strings.Builder) {
	// virtual == only a coeff, we discard the wire
	if t.VariableVisibility() == Public && t.VariableID() == 0 {
		sbb.WriteString("%s")
		t.SetVariableVisibility(Virtual)
		l.ToResolve = append(l.ToResolve, t)
		return
	}

	cID := t.CoeffID()
	if cID == CoeffIdMinusOne {
		sbb.WriteString("-%s")
	} else if cID == CoeffIdOne {
		sbb.WriteString("%s")
	} else {
		sbb.WriteString("%s*%s")
	}

	l.ToResolve = append(l.ToResolve, t)
}
