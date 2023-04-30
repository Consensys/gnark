package constraint

import (
	"fmt"
	"math/big"

	"github.com/blang/semver/v4"
	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/profile"
)

type SystemType uint16

const (
	SystemUnknown SystemType = iota
	SystemR1CS
	SystemSparseR1CS
)

// Instruction is the lowest element of a constraint system. It stores just enough data to
// reconstruct a constraint of any shape or a hint at solving time.
type Instruction struct {
	// BlueprintID maps this instruction to a blueprint
	BlueprintID BlueprintID

	// ConstraintOffset stores the starting constraint ID of this instruction.
	// Might not be strictly necessary; but speeds up solver for instructions that represents
	// multiple constraints.
	ConstraintOffset uint32

	// The constraint system stores a single []uint32 calldata slice. StartCallData
	// points to the starting index in the mentioned slice. This avoid storing a slice per
	// instruction (3 * uint64 in memory).
	StartCallData uint64
}

// System contains core elements for a constraint System
type System struct {
	// serialization header
	GnarkVersion string
	ScalarField  string

	Type SystemType

	Instructions []Instruction
	Blueprints   []Blueprint
	CallData     []uint32 // huge slice.

	// can be != than len(instructions)
	NbConstraints int

	// number of internal wires
	NbInternalVariables int

	// input wires names
	Public, Secret []string

	// logs (added with system.Println, resolved when solver sets a value to a wire)
	Logs []LogEntry

	// debug info contains stack trace (including line number) of a call to a system.API that
	// results in an unsolved constraint
	DebugInfo   []LogEntry
	SymbolTable debug.SymbolTable
	// maps constraint id to debugInfo id
	// several constraints may point to the same debug info
	MDebug map[int]int

	// maps hintID to hint string identifier
	MHintsDependencies map[solver.HintID]string

	// each level contains independent constraints and can be parallelized
	// it is guaranteed that all dependencies for constraints in a level l are solved
	// in previous levels
	// TODO @gbotrel these are currently updated after we add a constraint.
	// but in case the object is built from a serialized representation
	// we need to init the level builder lbWireLevel from the existing constraints.
	Levels [][]int

	// scalar field
	q      *big.Int `cbor:"-"`
	bitLen int      `cbor:"-"`

	// level builder
	lbWireLevel []int    `cbor:"-"` // at which level we solve a wire. init at -1.
	lbOutputs   []uint32 `cbor:"-"` // wire outputs for current constraint.

	CommitmentInfo []Commitment

	genericHint BlueprintID
}

// NewSystem initialize the common structure among constraint system
func NewSystem(scalarField *big.Int, capacity int, t SystemType) System {
	system := System{
		Type:               t,
		SymbolTable:        debug.NewSymbolTable(),
		MDebug:             map[int]int{},
		GnarkVersion:       gnark.Version.String(),
		ScalarField:        scalarField.Text(16),
		MHintsDependencies: make(map[solver.HintID]string),
		q:                  new(big.Int).Set(scalarField),
		bitLen:             scalarField.BitLen(),
		Instructions:       make([]Instruction, 0, capacity),
		CallData:           make([]uint32, 0, capacity*8),
		lbOutputs:          make([]uint32, 0, 256),
		lbWireLevel:        make([]int, 0, capacity),
		Levels:             make([][]int, 0, capacity/2),
	}
	system.genericHint = system.AddBlueprint(&BlueprintGenericHint{})
	return system
}

func (system *System) GetNbInstructions() int {
	return len(system.Instructions)
}

func (system *System) GetInstruction(id int) Instruction {
	return system.Instructions[id]
}

func (system *System) AddBlueprint(b Blueprint) BlueprintID {
	system.Blueprints = append(system.Blueprints, b)
	return BlueprintID(len(system.Blueprints) - 1)
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
	// (ie if major didn't change,we shouldn't have a compatibility issue)

	scalarField := new(big.Int)
	_, ok := scalarField.SetString(system.ScalarField, 16)
	if !ok {
		return fmt.Errorf("when parsing serialized modulus: %s", system.ScalarField)
	}
	curveID := utils.FieldToCurve(scalarField)
	if curveID == ecc.UNKNOWN && scalarField.Cmp(tinyfield.Modulus()) != 0 {
		return fmt.Errorf("unsupported scalar field %s", scalarField.Text(16))
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

func (system *System) AddSolverHint(f solver.Hint, input []LinearExpression, nbOutput int, options ...HintIdOption) (internalVariables []int, err error) {
	if nbOutput <= 0 {
		return nil, fmt.Errorf("hint function must return at least one output")
	}

	// register the hint as dependency
	ID := HintIds{solver.GetHintID(f), solver.GetHintName(f)}

	for i := range options {
		options[i](&ID)
	}

	if id, ok := system.MHintsDependencies[ID.UUID]; ok {
		// hint already registered, let's ensure string id matches
		if id != ID.Name {
			return nil, fmt.Errorf("hint dependency registration failed; %s previously register with same UUID as %s", ID.Name, id)
		}
	} else {
		system.MHintsDependencies[ID.UUID] = ID.Name
	}

	// prepare wires
	internalVariables = make([]int, nbOutput)
	for i := 0; i < len(internalVariables); i++ {
		internalVariables[i] = system.AddInternalVariable()
	}

	// associate these wires with the solver hint
	hm := HintMapping{
		HintID: ID.UUID,
		Inputs: input,
		OutputRange: struct {
			Start uint32
			End   uint32
		}{
			uint32(internalVariables[0]),
			uint32(internalVariables[len(internalVariables)-1]) + 1,
		},
	}

	instruction := system.compressHint(hm, system.genericHint)
	system.Instructions = append(system.Instructions, instruction)

	system.updateLevel(len(system.Instructions)-1, &hm)

	return
}

func (system *System) AddCommitment(c Commitment) error {
	system.CommitmentInfo = append(system.CommitmentInfo, c)
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

// VariableToString implements Resolver
func (system *System) VariableToString(vID int) string {
	nbPublic := system.GetNbPublicVariables()
	nbSecret := system.GetNbSecretVariables()

	if vID < nbPublic {
		return system.Public[vID]
	}
	vID -= nbPublic
	if vID < nbSecret {
		return system.Secret[vID]
	}
	vID -= nbSecret
	return fmt.Sprintf("v%d", vID) // TODO @gbotrel  vs strconv.Itoa.
}

// GetCallData re-slice the constraint system full calldata slice with the portion
// related to the instruction. This does not copy and caller should not modify.
func (cs *System) GetCallData(instruction Instruction) []uint32 {
	blueprint := cs.Blueprints[instruction.BlueprintID]
	nbInputs := blueprint.NbInputs()
	if nbInputs < 0 {
		// by convention, we store nbInputs < 0 for non-static input length.
		nbInputs = int(cs.CallData[instruction.StartCallData])
	}
	return cs.CallData[instruction.StartCallData : instruction.StartCallData+uint64(nbInputs)]
}

func (cs *System) AddR1C(c R1C, bID BlueprintID) int {
	profile.RecordConstraint()
	instruction := cs.compressR1C(&c, bID)
	cs.Instructions = append(cs.Instructions, instruction)

	cs.updateLevel(len(cs.Instructions)-1, &c)

	return cs.NbConstraints - 1
}

func (cs *System) AddSparseR1C(c SparseR1C, bID BlueprintID) int {
	profile.RecordConstraint()
	instruction := cs.compressSparseR1C(&c, bID)
	cs.Instructions = append(cs.Instructions, instruction)

	cs.updateLevel(len(cs.Instructions)-1, &c)

	return cs.NbConstraints - 1
}

func (cs *System) compressSparseR1C(c *SparseR1C, bID BlueprintID) Instruction {
	inst := Instruction{
		StartCallData:    uint64(len(cs.CallData)),
		ConstraintOffset: uint32(cs.NbConstraints),
		BlueprintID:      bID,
	}
	blueprint := cs.Blueprints[bID]
	calldata := blueprint.(BlueprintSparseR1C).CompressSparseR1C(c)
	cs.CallData = append(cs.CallData, calldata...)
	cs.NbConstraints += blueprint.NbConstraints()
	return inst
}

func (cs *System) compressR1C(c *R1C, bID BlueprintID) Instruction {
	inst := Instruction{
		StartCallData:    uint64(len(cs.CallData)),
		ConstraintOffset: uint32(cs.NbConstraints),
		BlueprintID:      bID,
	}
	blueprint := cs.Blueprints[bID]
	calldata := blueprint.(BlueprintR1C).CompressR1C(c)
	cs.CallData = append(cs.CallData, calldata...)
	cs.NbConstraints += blueprint.NbConstraints()
	return inst
}

func (cs *System) compressHint(hm HintMapping, bID BlueprintID) Instruction {
	inst := Instruction{
		StartCallData:    uint64(len(cs.CallData)),
		ConstraintOffset: uint32(cs.NbConstraints), // unused.
		BlueprintID:      bID,
	}
	blueprint := cs.Blueprints[bID]
	calldata := blueprint.(BlueprintHint).CompressHint(hm)
	cs.CallData = append(cs.CallData, calldata...)
	return inst
}

// GetNbConstraints returns the number of constraints
func (cs *System) GetNbConstraints() int {
	return cs.NbConstraints
}

func (cs *System) CheckUnconstrainedWires() error {
	// TODO @gbotrel
	return nil
}

func (cs *System) GetR1CIterator() R1CIterator {
	return R1CIterator{cs: cs}
}

func (cs *System) GetSparseR1CIterator() SparseR1CIterator {
	return SparseR1CIterator{cs: cs}
}

func (cs *System) NbCommitments() int {
	return len(cs.CommitmentInfo)
}
