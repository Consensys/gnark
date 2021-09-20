package compiled

import (
	"runtime"
	"strconv"
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

func (l *LogEntry) WriteStack(sbb *strings.Builder) {
	// derived from: https://golang.org/pkg/runtime/#example_Frames
	// we stop when func name == Define as it is where the gnark circuit code should start

	// Ask runtime.Callers for up to 10 pcs
	pc := make([]uintptr, 10)
	n := runtime.Callers(3, pc)
	if n == 0 {
		// No pcs available. Stop now.
		// This can happen if the first argument to runtime.Callers is large.
		return
	}
	pc = pc[:n] // pass only valid pcs to runtime.CallersFrames
	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()
		fe := strings.Split(frame.Function, "/")
		function := fe[len(fe)-1]
		if strings.Contains(function, "frontend.(*ConstraintSystem)") {
			continue
		}

		sbb.WriteString(function)
		sbb.WriteByte('\n')
		sbb.WriteByte('\t')
		sbb.WriteString(frame.File)
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(frame.Line))
		sbb.WriteByte('\n')
		if !more {
			break
		}
		if strings.HasSuffix(function, "Define") {
			break
		}
	}
}
