package constraint

import (
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
)

// ConstraintSystem interface that all constraint systems implement.
type ConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom
	CoeffEngine

	// IsSolved returns nil if given witness solves the constraint system and error otherwise
	IsSolved(witness *witness.Witness, opts ...backend.ProverOption) error

	// GetNbVariables return number of internal, secret and public Variables
	// Deprecated: use GetNbSecretVariables() instead
	GetNbVariables() (internal, secret, public int)

	GetNbInternalVariables() int
	GetNbSecretVariables() int
	GetNbPublicVariables() int

	GetNbConstraints() int
	GetNbCoefficients() int

	Field() *big.Int
	FieldBitLen() int

	// TODO @gbotrel this should probably go away. check playground usage.
	// GetSchema() *schema.Schema

	// GetConstraints return a human readable representation of the constraints
	// TODO @gbotrel restore -- playground uses it.
	// GetConstraints() [][]string

	AddPublicVariable(name string) int
	AddSecretVariable(name string) int
	AddInternalVariable() int

	// AddSolverHint adds a hint to the solver such that the output variables will be computed
	// using a call to output := f(input...) at solve time.
	AddSolverHint(f hint.Function, input []LinearExpression, nbOutput int) (internalVariables []int, err error)

	AddCommitment(c Commitment) error

	AddLog(l LogEntry)

	// MakeTerm returns a new Term. The constraint system may store coefficients in a map, so
	// calls to this function will grow the memory usage of the constraint system.
	MakeTerm(coeff *Coeff, variableID int) Term

	// AttachDebugInfo enables attaching debug information to multiple constraints.
	// This is more efficient than using the AddConstraint(.., debugInfo) since it will store the
	// debug information only once.
	AttachDebugInfo(debugInfo DebugInfo, constraintID []int)

	IsValid() error // TODO @gbotrel should take list of Validators
}

// CoeffEngine capability to perform arithmetic on Coeff
type CoeffEngine interface {
	FromInterface(interface{}) Coeff
	ToBigInt(*Coeff) *big.Int
	Mul(a, b *Coeff)
	Add(a, b *Coeff)
	Sub(a, b *Coeff)
	Neg(a *Coeff)
	Inverse(a *Coeff)
	One() Coeff
	IsOne(*Coeff) bool
	String(*Coeff) string
}

type Iterable interface {
	// WireIterator returns a new iterator to iterate over the wires of the implementer (usually, a constraint)
	WireIterator() func() int
}

var _ Iterable = &SparseR1C{}
var _ Iterable = &R1C{}

// System contains core elements for a constraint System
type System struct {
	// serialization header
	GnarkVersion string
	ScalarField  string

	// number of internal wires
	NbInternalVariables int

	// input wires names
	Public, Secret []string

	// logs (added with system.Println, resolved when solver sets a value to a wire)
	Logs []LogEntry

	// debug info contains stack trace (including line number) of a call to a system.API that
	// results in an unsolved constraint
	DebugInfo []LogEntry

	// maps constraint id to debugInfo id
	// several constraints may point to the same debug info
	MDebug map[int]int

	MHints             map[int]*Hint      // maps wireID to hint
	MHintsDependencies map[hint.ID]string // maps hintID to hint string identifier

	// each level contains independent constraints and can be parallelized
	// it is guaranteed that all dependncies for constraints in a level l are solved
	// in previous levels
	// TODO @gbotrel these are currently updated after we add a constraint.
	// but in case the object is built from a serialized reprensentation
	// we need to init the level builder lbWireLevel from the existing constraints.
	Levels [][]int

	// scalar field
	q      *big.Int `cbor:"-"`
	bitLen int      `cbor:"-"`

	// level builder
	lbWireLevel []int    `cbor:"-"` // at which level we solve a wire. init at -1.
	lbOutputs   []uint32 `cbor:"-"` // wire outputs for current constraint.

	CommitmentInfo Commitment
}

// NewSystem initialize the common structure among constraint system
func NewSystem(scalarField *big.Int) System {
	return System{
		GnarkVersion:       gnark.Version.String(),
		ScalarField:        scalarField.Text(16),
		MDebug:             make(map[int]int),
		MHints:             make(map[int]*Hint),
		MHintsDependencies: make(map[hint.ID]string),
		q:                  new(big.Int).Set(scalarField),
		bitLen:             scalarField.BitLen(),
	}
}

func (system *System) GetNbSecretVariables() int {
	return len(system.Secret)
}
func (system *System) GetNbPublicVariables() int {
	return len(system.Public)
}
func (system *System) GetNbInternalVariables() int {
	return system.NbInternalVariables
}

// CheckSerializationHeader parses the scalar field and gnark version headers
//
// This is meant to be use at the deserialization step, and will error for illegal values
func (system *System) CheckSerializationHeader() error {
	// check gnark version
	binaryVersion := gnark.Version
	objectVersion, err := semver.Parse(system.GnarkVersion)
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
	_, ok := scalarField.SetString(system.ScalarField, 16)
	if !ok {
		return fmt.Errorf("when parsing serialized modulus: %s", system.ScalarField)
	}
	curveID := utils.FieldToCurve(scalarField)
	if curveID == ecc.UNKNOWN && scalarField.Cmp(tinyfield.Modulus()) != 0 {
		return fmt.Errorf("unsupported scalard field %s", scalarField.Text(16))
	}
	system.q = new(big.Int).Set(scalarField)
	system.bitLen = system.q.BitLen()
	return nil
}

// GetNbVariables return number of internal, secret and public variables
func (system *System) GetNbVariables() (internal, secret, public int) {
	return system.NbInternalVariables, system.GetNbSecretVariables(), system.GetNbPublicVariables()
}

func (system *System) Field() *big.Int {
	return new(big.Int).Set(system.q)
}

func (system *System) AddDebugInfo(errName string, i ...interface{}) int {

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
			l.WriteVariable(LinearExpression{v}, &sbb)
		default:
			_v := utils.FromInterface(v)
			sbb.WriteString(_v.String())
		}
	}
	sbb.WriteByte('\n')
	// TODO this stack should not be stored as string, but as a slice of locations
	// to avoid overloading with lots of str duplicate the serialized constraint system
	debug.WriteStack(&sbb)
	l.Format = sbb.String()

	system.DebugInfo = append(system.DebugInfo, l)

	return len(system.DebugInfo) - 1
}

// bitLen returns the number of bits needed to represent a fr.Element
func (system *System) FieldBitLen() int {
	return system.bitLen
}

func (system *System) AddInternalVariable() (idx int) {
	idx = system.NbInternalVariables + system.GetNbPublicVariables() + system.GetNbSecretVariables()
	system.NbInternalVariables++
	return idx
}

func (system *System) AddPublicVariable(name string) (idx int) {
	idx = system.GetNbPublicVariables()
	system.Public = append(system.Public, name)
	return idx
}

func (system *System) AddSecretVariable(name string) (idx int) {
	idx = system.GetNbSecretVariables() + system.GetNbPublicVariables()
	system.Secret = append(system.Secret, name)
	return idx
}

func (system *System) AddSolverHint(f hint.Function, input []LinearExpression, nbOutput int) (internalVariables []int, err error) {
	if nbOutput <= 0 {
		return nil, fmt.Errorf("hint function must return at least one output")
	}

	// register the hint as dependency
	hintUUID, hintID := hint.UUID(f), hint.Name(f)
	if id, ok := system.MHintsDependencies[hintUUID]; ok {
		// hint already registered, let's ensure string id matches
		if id != hintID {
			return nil, fmt.Errorf("hint dependency registration failed; %s previously register with same UUID as %s", hintID, id)
		}
	} else {
		system.MHintsDependencies[hintUUID] = hintID
	}

	// prepare wires
	internalVariables = make([]int, nbOutput)
	for i := 0; i < len(internalVariables); i++ {
		internalVariables[i] = system.AddInternalVariable()
	}

	// associate these wires with the solver hint
	ch := &Hint{ID: hintUUID, Inputs: input, Wires: internalVariables}
	for _, vID := range internalVariables {
		system.MHints[vID] = ch
	}

	return
}

func (system *System) AddCommitment(c Commitment) error {
	if system.CommitmentInfo.Is() {
		return fmt.Errorf("currently only one commitment per circuit is supported")
	}

	system.CommitmentInfo = c

	return nil
}

func (system *System) AddLog(l LogEntry) {
	system.Logs = append(system.Logs, l)
}

func (system *System) AttachDebugInfo(debugInfo DebugInfo, constraintID []int) {
	system.DebugInfo = append(system.DebugInfo, LogEntry(debugInfo))
	id := len(system.DebugInfo) - 1
	for _, cID := range constraintID {
		system.MDebug[cID] = id
	}
}
