package compiled

import (
	"fmt"
	"math/big"
	"runtime"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
)

// ConstraintSystem contains common element between R1CS and ConstraintSystem
type ConstraintSystem struct {
	// serialization header
	GnarkVersion string
	ScalarField  string

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
	DebugInfo       []LogEntry
	DebugStackPaths map[int]string    // maps unique id to a path (optimized for reading debug info stacks)
	debugPathsIds   map[string]uint32 // maps a path to an id (optimized for storing debug info stacks)
	debugPathId     uint32

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
		GnarkVersion:       gnark.Version.String(),
		ScalarField:        scalarField.Text(16),
		MDebug:             make(map[int]int),
		MHints:             make(map[int]*Hint),
		MHintsDependencies: make(map[hint.ID]string),
		DebugStackPaths:    make(map[int]string),
		debugPathsIds:      make(map[string]uint32),
		q:                  new(big.Int).Set(scalarField),
		bitLen:             scalarField.BitLen(),
	}
}

// CheckSerializationHeader parses the scalar field and gnark version headers
//
// This is meant to be use at the deserialization step, and will error for illegal values
func (cs *ConstraintSystem) CheckSerializationHeader() error {
	// check gnark version
	binaryVersion := gnark.Version
	objectVersion, err := semver.Parse(cs.GnarkVersion)
	if err != nil {
		return fmt.Errorf("when parsing gnark version: %w", err)
	}

	if binaryVersion.Compare(objectVersion) != 0 {
		log := logger.Logger()
		log.Warn().Str("binary", binaryVersion.String()).Str("object", objectVersion.String()).Msg("gnark version (binary) mismatch with constraint system. there are no guarantees on compatibilty")
	}

	// TODO @gbotrel maintain version changes and compare versions properly
	// (ie if major didn't change,we shouldn't have a compat issue)

	scalarField := new(big.Int)
	_, ok := scalarField.SetString(cs.ScalarField, 0)
	if !ok {
		return fmt.Errorf("when parsing serialized modulus: %s", cs.ScalarField)
	}
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

	// add the stack info
	// TODO @gbotrel duplicate with Debug.stack below
	l.Stack = cs.stack()

	if errName == "" {
		cs.DebugInfo = append(cs.DebugInfo, l)
		return len(cs.DebugInfo) - 1
	}

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

func (cs *ConstraintSystem) stack() (r []uint64) {
	if !debug.Debug {
		return
	}
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
		file := frame.File

		id, ok := cs.debugPathsIds[file]
		if !ok {
			id = cs.debugPathId
			cs.debugPathId++
			cs.debugPathsIds[file] = id
		}
		r = append(r, ((uint64(id) << 32) | uint64(frame.Line)))
		if !more {
			break
		}
		if strings.HasSuffix(function, "Define") {
			break
		}
	}

	return

}
