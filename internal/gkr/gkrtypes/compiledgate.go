package gkrtypes

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

// GateOp represents an arithmetic operation in a compiled gate.
type GateOp uint8

const (
	OpAdd      GateOp = iota // result = src1 + src2 + ... (variadic)
	OpSub                    // result = src1 - src2 - ...
	OpMul                    // result = src1 * src2 * ...
	OpNeg                    // result = -src1
	OpMulAcc                 // result = src1 + (src2 * src3)
	OpSumExp17               // result = (src1 + src2 + src3)^17
)

// GateInstruction represents a single operation in a compiled gate.
// Each instruction produces a new variable (no explicit dst field).
// Index space layout:
//   - [0, nbConsts): constant values (from CompiledGate.Constants)
//   - [nbConsts, nbConsts+nbInputs): gate inputs
//   - [nbConsts+nbInputs, ...): instruction results
type GateInstruction struct {
	Op     GateOp
	Inputs []uint16 // indices into the unified value space
}

// CompiledGate represents a gate function compiled into a sequence of instructions.
// The compiled form is independent of curve-specific types and can be serialized.
// The index space is unified: constants (0..nbConsts-1), inputs (nbConsts..nbConsts+nbInputs-1),
// then instruction results.
type CompiledGate struct {
	Instructions []GateInstruction // sequence of operations
	Constants    []*big.Int        // constant values at indices [0, nbConsts)
}

// NbConstants returns the number of constants in the gate
func (g *CompiledGate) NbConstants() int {
	return len(g.Constants)
}

// String returns a human-readable representation of the operation
func (op GateOp) String() string {
	switch op {
	case OpAdd:
		return "add"
	case OpSub:
		return "sub"
	case OpMul:
		return "mul"
	case OpNeg:
		return "neg"
	case OpMulAcc:
		return "mulacc"
	case OpSumExp17:
		return "sumexp17"
	default:
		return "unknown"
	}
}

// gateCompiler is an implementation of gkr.GateAPI that records operations
// instead of executing them. This is used to compile gate functions into
// instruction sequences. During compilation, temporary indices are used:
//   - Constants: high indices (starting at 0x8000)
//   - Inputs: 0..nbInputs-1
//   - Results: nbInputs onwards
//
// After compilation, indices are remapped to: constants, inputs, results.
type gateCompiler struct {
	instructions  []GateInstruction // each instruction defines exactly one output variable
	constants     []*big.Int        // constant values pool
	constantIndex map[string]uint16 // map from constant value to its temp index (0x8000+)
	nbInputs      int
}

const constMarker = 0x8000

// compilationVar represents a variable during gate compilation.
type compilationVar struct {
	id uint16
}

func (gc *gateCompiler) addInstruction(op GateOp, inputs ...frontend.Variable) compilationVar {
	ins := make([]uint16, len(inputs))
	for i := range ins {
		ins[i] = gc.getVarID(inputs[i])
	}

	result := compilationVar{id: uint16(len(gc.instructions) + gc.nbInputs)}

	gc.instructions = append(gc.instructions, GateInstruction{
		Op:     op,
		Inputs: ins,
	})

	return result
}

func (gc *gateCompiler) addInstruction2Plus(op GateOp, i1, i2 frontend.Variable, in ...frontend.Variable) compilationVar {
	ins := make([]frontend.Variable, len(in)+2)
	ins[0] = i1
	ins[1] = i2
	copy(ins[2:], in)
	return gc.addInstruction(op, ins...)
}

// Add records an addition operation.
func (gc *gateCompiler) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.addInstruction2Plus(OpAdd, i1, i2, in...)
}

// MulAcc records a multiply-accumulate operation: a + (b * c)
func (gc *gateCompiler) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	return gc.addInstruction(OpMulAcc, a, b, c)
}

// Neg records a negation operation
func (gc *gateCompiler) Neg(i1 frontend.Variable) frontend.Variable {
	return gc.addInstruction(OpNeg, i1)
}

// Sub records a subtraction operation
func (gc *gateCompiler) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.addInstruction2Plus(OpSub, i1, i2, in...)
}

// Mul records a multiplication operation
func (gc *gateCompiler) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.addInstruction2Plus(OpMul, i1, i2, in...)
}

// Println is a no-op during recording
func (gc *gateCompiler) Println(a ...frontend.Variable) {
	// No-op: we don't need to record print statements
}

// SumExp17 records (a + b + c)^17 as a single instruction
func (gc *gateCompiler) SumExp17(a, b, c frontend.Variable) frontend.Variable {
	return gc.addInstruction(OpSumExp17, a, b, c)
}

// getVarID extracts or creates a temporary index from a value.
// Returns a temporary index: inputs at 0..nbInputs-1, constants at 0x8000+, results at nbInputs+.
func (gc *gateCompiler) getVarID(v frontend.Variable) uint16 {
	if rv, ok := v.(compilationVar); ok {
		return rv.id
	}

	// Otherwise, it must be a constant value
	// Convert to big.Int for curve-agnostic storage
	val := utils.FromInterface(v)

	// Check if we've seen this constant before
	key := val.String()
	if idx, exists := gc.constantIndex[key]; exists {
		return idx
	}

	// Add new constant to the pool with temp index 0x8000+
	tempIdx := uint16(len(gc.constants)) | constMarker
	gc.constants = append(gc.constants, new(big.Int).Set(&val))
	gc.constantIndex[key] = tempIdx
	return tempIdx
}

// GetInstructions returns the recorded instructions
func (gc *gateCompiler) GetInstructions() []GateInstruction {
	return gc.instructions
}

// GetNbInputs returns the number of inputs
func (gc *gateCompiler) GetNbInputs() int {
	return gc.nbInputs
}

// remapIndices transforms temporary indices to final layout: constants, inputs, results.
func (gc *gateCompiler) remapIndices() {
	nbConsts := uint16(len(gc.constants))

	// Remap all instruction inputs
	for i := range gc.instructions {
		for j := range gc.instructions[i].Inputs {
			if gc.instructions[i].Inputs[j]&constMarker != 0 {
				// constant
				gc.instructions[i].Inputs[j] &= ^uint16(constMarker)
			} else {
				// variable
				gc.instructions[i].Inputs[j] += nbConsts
			}
		}
	}
}

// CompileGateFunction compiles a gate function into a CompiledGate.
// The gate function should be of type gkr.GateFunction.
func CompileGateFunction(f gkr.GateFunction, nbInputs int) *CompiledGate {
	// Create compiling API
	compiler := gateCompiler{
		constantIndex: make(map[string]uint16),
		nbInputs:      nbInputs,
	}

	// Create input variables
	inputs := make([]frontend.Variable, nbInputs)
	for i := range uint16(nbInputs) {
		inputs[i] = compilationVar{i}
	}

	// Execute the gate function to record operations
	out := f(&compiler, inputs...)

	// All instructions after the output are no-ops. Prune them and the corresponding variables.
	// Henceforth we guarantee that the variable with the highest index is the gate output.
	lastEffectiveInstructionIndex := int(out.(compilationVar).id) - compiler.nbInputs
	compiler.instructions = compiler.instructions[:lastEffectiveInstructionIndex+1]

	// Remap indices from temporary layout to final layout
	compiler.remapIndices()

	return &CompiledGate{
		Instructions: compiler.GetInstructions(),
		Constants:    compiler.constants,
	}
}
