package compiled

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/tinyfield"
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

	MHints             map[int]*Hint      // maps wireID to hint
	MHintsDependencies map[hint.ID]string // maps hintID to hint string identifier

	// each level contains independent constraints and can be parallelized
	// it is guaranteed that all dependncies for constraints in a level l are solved
	// in previous levels
	Levels [][]int

	// scalar field
	q      *big.Int
	bitLen int
}

// NewConstraintSystem initialize the common structure among constraint system
func NewConstraintSystem(scalarField *big.Int) ConstraintSystem {
	return ConstraintSystem{
		MDebug:             make(map[int]int),
		MHints:             make(map[int]*Hint),
		MHintsDependencies: make(map[hint.ID]string),
		q:                  new(big.Int).Set(scalarField),
		bitLen:             scalarField.BitLen(),
	}
}

// SetScalarField sets the scalar field on the constraint system object
//
// This is meant to be use at the deserialization step
func (cs *ConstraintSystem) SetScalarField(scalarField *big.Int) error {
	curveID := utils.FieldToCurve(scalarField)
	if curveID == ecc.UNKNOWN && scalarField.Cmp(tinyfield.Modulus()) != 0 {
		return fmt.Errorf("unsupported scalard field %s", scalarField.Text(16))
	}
	cs.q = new(big.Int).Set(scalarField)
	cs.bitLen = cs.q.BitLen()
	return nil
}

// GetNbVariables return number of internal, secret and public variables
func (cs *ConstraintSystem) GetNbVariables() (internal, secret, public int) {
	return cs.NbInternalVariables, cs.NbSecretVariables, cs.NbPublicVariables
}

func (cs *ConstraintSystem) Field() *big.Int {
	return new(big.Int).Set(cs.q)
}

// GetCounters return the collected constraint counters, if any
func (cs *ConstraintSystem) GetCounters() []Counter { return cs.Counters }

func (cs *ConstraintSystem) GetSchema() *schema.Schema { return cs.Schema }

// Counter contains measurements of useful statistics between two Tag
type Counter struct {
	From, To      string
	NbVariables   int
	NbConstraints int
	BackendID     backend.ID
}

func (c Counter) String() string {
	return fmt.Sprintf("%s %s - %s: %d variables, %d constraints", c.BackendID, c.From, c.To, c.NbVariables, c.NbConstraints)
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
		case LinearExpression:
			if len(v) > 1 {
				sbb.WriteString("(")
			}
			l.WriteVariable(v, &sbb)
			if len(v) > 1 {
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
func (cs *ConstraintSystem) FieldBitLen() int {
	return cs.bitLen
}
