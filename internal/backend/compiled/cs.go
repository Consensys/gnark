package compiled

import (
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
)

// CS contains common element between R1CS and CS
type CS struct {
	// number of wires
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// logs (added with cs.Println, resolved when solver sets a value to a wire)
	Logs []LogEntry

	// debug info contains stack trace (including line number) of a call to a cs.API that
	// results in an unsolved constraint
	DebugInfo []LogEntry

	// maps wire id to hint
	// a wire may point to at most one hint
	MHints map[int]Hint

	// maps constraint id to debugInfo id
	// several constraints may point to the same debug info
	MDebug map[int]int

	Counters []Counter // TODO @gbotrel no point in serializing these
}

// Visibility encodes a Variable (or wire) visibility
// Possible values are Unset, Internal, Secret or Public
type Visibility uint8

const (
	Unset Visibility = iota
	Internal
	Secret
	Public
	Virtual
)

// Hint represents a solver hint
// it enables the solver to compute a Wire with a function provided at solving time
// using pre-defined inputs
type Hint struct {
	ID     hint.ID            // hint function id
	Inputs []LinearExpression // terms to inject in the hint function
}

// GetNbVariables return number of internal, secret and public variables
func (cs *CS) GetNbVariables() (internal, secret, public int) {
	return cs.NbInternalVariables, cs.NbSecretVariables, cs.NbPublicVariables
}

// FrSize panics
func (cs *CS) FrSize() int { panic("not implemented") }

// GetNbCoefficients panics
func (cs *CS) GetNbCoefficients() int { panic("not implemented") }

// CurveID returns ecc.UNKNOWN
func (cs *CS) CurveID() ecc.ID { return ecc.UNKNOWN }

// WriteTo panics
func (cs *CS) WriteTo(w io.Writer) (n int64, err error) { panic("not implemented") }

// ReadFrom panics
func (cs *CS) ReadFrom(r io.Reader) (n int64, err error) { panic("not implemented") }

// ToHTML panics
func (cs *CS) ToHTML(w io.Writer) error { panic("not implemtened") }

// GetCounters return the collected constraint counters, if any
func (cs *CS) GetCounters() []Counter { return cs.Counters }

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
