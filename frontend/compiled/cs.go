package compiled

import (
	"fmt"
	"io"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/utils"
)

// ConstraintSystem contains common element between R1CS and ConstraintSystem
type ConstraintSystem struct {

	// schema of the circuit
	Schema *schema.Schema

	// number of wires
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// input wires names
	Public, Secret []string

	// logs (added with cs.Println, resolved when solver sets a value to a wire)
	Logs []LogEntry

	// debug info contains stack trace (including line number) of a call to a cs.API that
	// results in an unsolved constraint
	DebugInfo []LogEntry

	// maps constraint id to debugInfo id
	// several constraints may point to the same debug info
	MDebug map[int]int

	Counters []Counter // TODO @gbotrel no point in serializing these

	// maps wire id to hint
	// a wire may point to at most one hint
	MHints map[int]*Hint

	// each level contains independent constraints and can be parallelized
	// it is guaranteed that all dependncies for constraints in a level l are solved
	// in previous levels
	Levels [][]int

	CurveID ecc.ID
}

// GetNbVariables return number of internal, secret and public variables
func (cs *ConstraintSystem) GetNbVariables() (internal, secret, public int) {
	return cs.NbInternalVariables, cs.NbSecretVariables, cs.NbPublicVariables
}

// FrSize panics
func (cs *ConstraintSystem) FrSize() int { panic("not implemented") }

// GetNbCoefficients panics
func (cs *ConstraintSystem) GetNbCoefficients() int { panic("not implemented") }

// // CurveID returns ecc.UNKNOWN
// func (cs *CS) CurveID() ecc.ID { return ecc.UNKNOWN }

// WriteTo panics
func (cs *ConstraintSystem) WriteTo(w io.Writer) (n int64, err error) { panic("not implemented") }

// ReadFrom panics
func (cs *ConstraintSystem) ReadFrom(r io.Reader) (n int64, err error) { panic("not implemented") }

// ToHTML panics
func (cs *ConstraintSystem) ToHTML(w io.Writer) error { panic("not implemtened") }

// GetCounters return the collected constraint counters, if any
func (cs *ConstraintSystem) GetCounters() []Counter { return cs.Counters }

func (cs *ConstraintSystem) GetSchema() *schema.Schema { return cs.Schema }

func (cs *ConstraintSystem) GetConstraints() [][]string { panic("not implemented") }

// Counter contains measurements of useful statistics between two Tag
type Counter struct {
	From, To      string
	NbVariables   int
	NbConstraints int
	CurveID       ecc.ID
	BackendID     backend.ID
}

func (c Counter) String() string {
	return fmt.Sprintf("%s[%s] %s - %s: %d variables, %d constraints", c.BackendID, c.CurveID, c.From, c.To, c.NbVariables, c.NbConstraints)
}

func (cs *ConstraintSystem) Curve() ecc.ID {
	return cs.CurveID
}

func (cs *ConstraintSystem) AddDebugInfo(errName string, i ...interface{}) int {

	var l LogEntry

	const minLogSize = 500
	var sbb strings.Builder
	sbb.Grow(minLogSize)
	sbb.WriteString("[")
	sbb.WriteString(errName)
	sbb.WriteString("] ")

	for _, _i := range i {
		switch v := _i.(type) {
		case Variable:
			if len(v.LinExp) > 1 {
				sbb.WriteString("(")
			}
			l.WriteVariable(v, &sbb)
			if len(v.LinExp) > 1 {
				sbb.WriteString(")")
			}
		case string:
			sbb.WriteString(v)
		case Term:
			l.WriteTerm(v, &sbb)
		default:
			_v := utils.FromInterface(v)
			sbb.WriteString(_v.String())
		}
	}
	sbb.WriteByte('\n')
	debug.WriteStack(&sbb)
	l.Format = sbb.String()

	cs.DebugInfo = append(cs.DebugInfo, l)

	return len(cs.DebugInfo) - 1
}

// bitLen returns the number of bits needed to represent a fr.Element
func (cs *ConstraintSystem) BitLen() int {
	return cs.CurveID.Info().Fr.Bits
}
