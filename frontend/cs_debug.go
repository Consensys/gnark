package frontend

import (
	"strconv"
	"strings"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// TODO @gbotrel maybe rename to newLog if common with cs.Println
func (cs *ConstraintSystem) addDebugInfo(errName string, i ...interface{}) int {
	var debug compiled.LogEntry

	// TODO @gbotrel reserve capacity for the string builder
	const minLogSize = 500
	var sbb strings.Builder
	sbb.Grow(minLogSize)
	sbb.WriteString("[")
	sbb.WriteString(errName)
	sbb.WriteString("] ")

	for _, _i := range i {
		switch v := _i.(type) {
		case Variable:
			if len(v.linExp) > 1 {
				sbb.WriteString("(")
			}
			debug.WriteLinearExpression(v.linExp, &sbb)
			if len(v.linExp) > 1 {
				sbb.WriteString(")")
			}

		case string:
			sbb.WriteString(v)
		case int:
			sbb.WriteString(strconv.Itoa(v))
		case compiled.Term:
			debug.WriteTerm(v, &sbb)
		default:
			panic("unsupported log type")
		}
	}
	sbb.WriteByte('\n')
	debug.WriteStack(&sbb)
	debug.Format = sbb.String()

	cs.debugInfo = append(cs.debugInfo, debug)
	return len(cs.debugInfo) - 1
}
