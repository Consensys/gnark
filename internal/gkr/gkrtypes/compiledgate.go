package gkrtypes

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/consensys/gnark/std/polynomial"
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
//   - [0, nbConsts): constant values (from GateBytecode.Constants)
//   - [nbConsts, nbConsts+nbInputs): gate inputs
//   - [nbConsts+nbInputs, ...): instruction results
type GateInstruction struct {
	Op     GateOp
	Inputs []uint16 // indices into the unified value space
}

// GateBytecode represents a gate executable compiled into a sequence of instructions.
// The compiled form is independent of curve-specific types and can be serialized.
// The index space is unified: constants (0..nbConsts-1), inputs (nbConsts..nbConsts+nbInputs-1),
// then instruction results.
type GateBytecode struct {
	Instructions []GateInstruction // sequence of operations
	Constants    []*big.Int        // constant values at indices [0, nbConsts)
}

// NbConstants returns the number of constants in the gate
func (g *GateBytecode) NbConstants() int {
	return len(g.Constants)
}

// EstimateDegree returns an upper bound on the degree of the gate
func (g *GateBytecode) EstimateDegree(nbIn int) int {
	frameSize := len(g.Constants) + nbIn
	deg := make([]int, frameSize+len(g.Instructions))
	for i := range nbIn {
		deg[i+len(g.Constants)] = 1
	}
	for i, inst := range g.Instructions {
		var curr int
		switch inst.Op {
		case OpAdd, OpSub, OpNeg, OpSumExp17:
			for _, in := range inst.Inputs {
				curr = max(curr, deg[in])
			}
		case OpMul:
			for _, in := range inst.Inputs {
				curr += deg[in]
			}
		case OpMulAcc: // a + b*c
			curr = max(deg[inst.Inputs[0]], deg[inst.Inputs[1]]+deg[inst.Inputs[2]])
		default:
			panic("unknown operation")
		}
		if inst.Op == OpSumExp17 {
			curr *= 17
		}
		deg[frameSize+i] = curr
	}
	return deg[len(deg)-1]
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


func (t *gateTester) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	res := new(big.Int).Set(i1.(*big.Int))
	res.Add(res, i2.(*big.Int))
	for _, v := range in {
		res.Add(res, v.(*big.Int))
	}
	return res.Mod(res, t.mod)
}

func (t *gateTester) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	prod := new(big.Int).Mul(b.(*big.Int), c.(*big.Int))
	res := new(big.Int).Add(a.(*big.Int), prod)
	return res.Mod(res, t.mod)
}

func (t *gateTester) Neg(i1 frontend.Variable) frontend.Variable {
	res := new(big.Int).Neg(i1.(*big.Int))
	return res.Mod(res, t.mod)
}

func (t *gateTester) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	res := new(big.Int).Set(i1.(*big.Int))
	res.Sub(res, i2.(*big.Int))
	for _, v := range in {
		res.Sub(res, v.(*big.Int))
	}
	return res.Mod(res, t.mod)
}

func (t *gateTester) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	res := new(big.Int).Mul(i1.(*big.Int), i2.(*big.Int))
	res.Mod(res, t.mod)
	for _, v := range in {
		res.Mul(res, v.(*big.Int))
		res.Mod(res, t.mod)
	}
	return res
}

func (t *gateTester) SumExp17(a, b, c frontend.Variable) frontend.Variable {
	sum := new(big.Int).Add(a.(*big.Int), b.(*big.Int))
	sum.Add(sum, c.(*big.Int))
	sum.Mod(sum, t.mod)
	res := new(big.Int).Exp(sum, big.NewInt(17), t.mod)
	return res
}

func (t *gateTester) IsZero(a frontend.Variable) bool {
	v := new(big.Int).Mod(a.(*big.Int), t.mod)
	return v.BitLen() == 0
}

func (t *gateTester) Equal(a, b frontend.Variable) bool {
	diff := t.Sub(a, b).(*big.Int)
	return diff.BitLen() == 0
}

func (t *gateTester) randomElement() *big.Int {
	res, err := crand.Int(crand.Reader, t.mod)
	if err != nil {
		panic(err)
	}
	return res
}

func (t *gateTester) randomVector(n int) polynomial.Polynomial {
	res := make([]frontend.Variable, n)
	for i := range res {
		res[i] = t.randomElement()
	}
	return res
}

// CompileGateFunction compiles a gate function into a GateBytecode.
// The gate function should be of type gkr.GateFunction.
func CompileGateFunction(f gkr.GateFunction, nbInputs int) (*GateBytecode, error) {
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
	if len(compiler.instructions) == 0 {
		return nil, errors.New("every gate must perform a non-trivial operation")
	}

	// All instructions after the output are no-ops. Prune them and the corresponding variables.
	// Henceforth we guarantee that the variable with the highest index is the gate output.
	lastEffectiveInstructionIndex := int(out.(compilationVar).id) - compiler.nbInputs
	compiler.instructions = compiler.instructions[:lastEffectiveInstructionIndex+1]

	// Remap indices from temporary layout to final layout
	compiler.remapIndices()

	return &GateBytecode{
		Instructions: compiler.GetInstructions(),
		Constants:    compiler.constants,
	}, nil
}

// ToSerializableCircuit converts a gadget circuit to a serializable circuit by compiling the gate functions.
// It also sets the gate metadata (Degree, SolvableVar) for both the input and output circuits.
func ToSerializableCircuit(mod *big.Int, c GadgetCircuit) SerializableCircuit {
	tester := gateTester{mod}

	var err error
	res := make(SerializableCircuit, len(c))
	for i := range c {
		res[i].Inputs = c[i].Inputs

		c[i].Gate.NbIn = len(c[i].Inputs)
		res[i].Gate.NbIn = c[i].Gate.NbIn

		if res[i].Gate.Evaluate, err = CompileGateFunction(c[i].Gate.Evaluate, c[i].Gate.NbIn); err != nil {
			panic(err)
		}

		c[i].Gate.Degree = len(tester.fitPoly(res[i].Gate.Evaluate.EstimateDegree(len(c[i].Inputs))))-1
		if res[i].Gate.Degree = tester.SetDegree(c[i].Gate); c[i].Gate.Degree == -1 {
			panic("cannot find degree for gate")
		}

		res[i].Gate.SolvableVar = -1
		for j := range c[i].Gate.NbIn {
			if tester.isAdditive(c[i].Gate, j) {
				res[i].Gate.SolvableVar = j
				break
			}
		}
		c[i].Gate.SolvableVar = res[i].Gate.SolvableVar

		tester.SetGate(res[i].Gate.Evaluate, c[i].Gate.NbIn)


		res[i].Gate.SolvableVar = c[i].Gate.SolvableVar
	}
	return res
}

type gateTester struct {
	mod *big.Int
}

// isAdditive returns whether xᵢ occurs only in a monomial of total degree 1 in g
func (t *gateTester) isAdditive(g *Gate[gkr.GateFunction], i int) bool {
	// fix all variables except the i-th one at random points
	// pick random value x1 for the i-th variable
	// check if f(-, 0, -) + f(-, 2*x1, -) = 2*f(-, x1, -)
	in := t.randomVector(g.NbIn)

	x := t.randomElement()
	in[i] = x

	y1 := g.Evaluate(t, in...)

	zero := new(big.Int)
	in[i] = zero
	y0 := g.Evaluate(t, in...)

	xDbl := t.Add(x, x)
	in[i] = xDbl
	y2 := g.Evaluate(t, in...)

	y2 = t.Sub(y2, y1)
	y1 = t.Sub(y1, y0)

	if !t.Equal(y1, y2) {
		return false // not linear
	}

	// check if the coefficient of xᵢ is nonzero and independent of the other variables
	if t.IsZero(y1) {
		return false
	}

	// compute the slope with another assignment for the other variables
	in = t.randomVector(g.NbIn)
	in[i] = zero
	y0 = g.Evaluate(t, in...)

	in[i] = x
	y1 = g.Evaluate(t, in...)
	y1 =  t.Sub(y1, y0)

	return t.Equal(y2, y1)
}

// fitPoly tries to fit a polynomial of degree less than degreeBound to the gate.
// degreeBound must be a power of 2.
// It returns the polynomial if successful, nil otherwise
func (t *gateTester) fitPoly(g *GadgetGate,degreeBound int) polynomial.Polynomial {

	// turn f univariate by defining p(x) as f(x, rx, ..., sx)
	// where r, s, ... are random constants
	fIn := make(polynomial.Polynomial, g.NbIn)
	consts := t.randomVector(g.NbIn-1)

	p := make(polynomial.Polynomial, degreeBound)

	x := t.randomVector(degreeBound)

	for i := range x {
		fIn[0] = x[i]
		for j := range consts {
			fIn[j+1].Mul(x[i], consts[j])
		}

		p[i].Set(t.f..evaluator.evaluate(fIn...))
	}

	// obtain p's coefficients
	p, err := interpolate(x, p)
	if err != nil {
		panic(err)
	}

	// check if p is equal to f. This not being the case means that f is of a degree higher than degreeBound
	fIn[0].MustSetRandom()
	for i := range consts {
		fIn[i+1].Mul(&fIn[0], &consts[i])
	}
	pAt := p.Eval(&fIn[0])
	fAt := *t.evaluator.evaluate(fIn...)
	if !pAt.Equal(&fAt) {
		return nil
	}

	// trim p
	lastNonZero := len(p) - 1
	for lastNonZero >= 0 && p[lastNonZero].IsZero() {
		lastNonZero--
	}
	return p[:lastNonZero+1]
}

// interpolate fits a polynomial of degree len(X) - 1 = len(Y) - 1 to the points (X[i], Y[i])
// Note that the runtime is O(len(X)³)
func interpolate(X, Y polynomial.Polynomial) (polynomial.Polynomial, error) {
if len(X) != len(Y) {
return nil, errors.New("same length expected for X and Y")
}

// solve the system of equations by Gaussian elimination
augmentedRows := make([]polynomial.Polynomial, len(X)) // the last column is the Y values
for i := range augmentedRows {
augmentedRows[i] = make(polynomial.Polynomial, len(X)+1)
augmentedRows[i][0].SetOne()
augmentedRows[i][1].Set(&X[i])
for j := 2; j < len(augmentedRows[i])-1; j++ {
augmentedRows[i][j].Mul(&augmentedRows[i][j-1], &X[i])
}
augmentedRows[i][len(augmentedRows[i])-1].Set(&Y[i])
}

// make the upper triangle
for i := range len(augmentedRows) - 1 {
// use row i to eliminate the ith element in all rows below
var negInv *big.Int
if augmentedRows[i][i].IsZero() {
return nil, errors.New("singular matrix")
}
negInv.Inverse(&augmentedRows[i][i])
negInv.Neg(negInv)
for j := i + 1; j < len(augmentedRows); j++ {
var c big.Int
c.Mul(augmentedRows[j][i], negInv)
// augmentedRows[j][i].SetZero() omitted
for k := i + 1; k < len(augmentedRows[i]); k++ {
var t *big.Int
t.Mul(augmentedRows[i][k], c)
augmentedRows[j][k].Add(augmentedRows[j][k], &)
}
}
}

// back substitution
res := make(polynomial.Polynomial, len(X))
for i := len(augmentedRows) - 1; i >= 0; i-- {
res[i] = augmentedRows[i][len(augmentedRows[i])-1]
for j := i + 1; j < len(augmentedRows[i])-1; j++ {
var t big.Int
t.Mul(res[j], augmentedRows[i][j])
res[i].Sub(res[i], &t)
}
res[i].Div(res[i], augmentedRows[i][i])
}

return res, nil
}

