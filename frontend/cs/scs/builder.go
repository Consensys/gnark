/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scs

import (
	"math/big"
	"reflect"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/circuitdefer"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"

	bls12377r1cs "github.com/consensys/gnark/constraint/bls12-377"
	bls12381r1cs "github.com/consensys/gnark/constraint/bls12-381"
	bls24315r1cs "github.com/consensys/gnark/constraint/bls24-315"
	bls24317r1cs "github.com/consensys/gnark/constraint/bls24-317"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	bw6633r1cs "github.com/consensys/gnark/constraint/bw6-633"
	bw6761r1cs "github.com/consensys/gnark/constraint/bw6-761"
	tinyfieldr1cs "github.com/consensys/gnark/constraint/tinyfield"
)

func NewBuilder(field *big.Int, config frontend.CompileConfig) (frontend.Builder, error) {
	return newBuilder(field, config), nil
}

type scs struct {
	cs constraint.SparseR1CS

	config frontend.CompileConfig

	tOne, tMinusOne constraint.Coeff

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[int]struct{}

	q *big.Int

	kvstore.Store
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
// TODO @gbotrel restore capacity option!
func newBuilder(field *big.Int, config frontend.CompileConfig) *scs {
	builder := scs{
		mtBooleans: make(map[int]struct{}),
		config:     config,
		Store:      kvstore.New(),
	}

	curve := utils.FieldToCurve(field)

	switch curve {
	case ecc.BLS12_377:
		builder.cs = bls12377r1cs.NewSparseR1CS(config.Capacity)
	case ecc.BLS12_381:
		builder.cs = bls12381r1cs.NewSparseR1CS(config.Capacity)
	case ecc.BN254:
		builder.cs = bn254r1cs.NewSparseR1CS(config.Capacity)
	case ecc.BW6_761:
		builder.cs = bw6761r1cs.NewSparseR1CS(config.Capacity)
	case ecc.BW6_633:
		builder.cs = bw6633r1cs.NewSparseR1CS(config.Capacity)
	case ecc.BLS24_315:
		builder.cs = bls24315r1cs.NewSparseR1CS(config.Capacity)
	case ecc.BLS24_317:
		builder.cs = bls24317r1cs.NewSparseR1CS(config.Capacity)
	default:
		if field.Cmp(tinyfield.Modulus()) == 0 {
			builder.cs = tinyfieldr1cs.NewSparseR1CS(config.Capacity)
			break
		}
		panic("not implemented")
	}

	builder.tOne = builder.cs.One()
	builder.tMinusOne = builder.cs.FromInterface(-1)

	builder.q = builder.cs.Field()
	if builder.q.Cmp(field) != 0 {
		panic("invalid modulus on cs impl") // sanity check
	}

	return &builder
}

func (builder *scs) Field() *big.Int {
	return builder.cs.Field()
}

func (builder *scs) FieldBitLen() int {
	return builder.cs.FieldBitLen()
}

// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0
type sparseR1C struct {
	xa, xb, xc         int              // wires
	qL, qR, qO, qM, qC constraint.Coeff // coefficients
	// TODO @gbotrel try impact with pointers here
}

// a + b == c
func (builder *scs) addAddGate(a, b, c expr.Term, debug ...constraint.DebugInfo) {
	qO := builder.tMinusOne
	if c.Coeff != builder.tOne {
		// slow path
		t := c.Coeff
		builder.cs.Neg(&t)
		qO = t
	}
	builder.addPlonkConstraint(sparseR1C{
		xa: a.VID,
		xb: b.VID,
		xc: c.VID,
		qL: a.Coeff,
		qR: b.Coeff,
		qO: qO,
	}, debug...)
}

// a * b == c
func (builder *scs) addMulGate(a, b, c expr.Term, debug ...constraint.DebugInfo) {
	qO := builder.tMinusOne
	if c.Coeff != builder.tOne {
		// slow path
		t := c.Coeff
		builder.cs.Neg(&t)
		qO = t
	}
	qM := a.Coeff
	builder.cs.Mul(&qM, &b.Coeff)
	builder.addPlonkConstraint(sparseR1C{
		xa: a.VID,
		xb: b.VID,
		xc: c.VID,
		qM: qM,
		qO: qO,
	}, debug...)
}

// addPlonkConstraint adds a sparseR1C to the underlying constraint system
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0
func (builder *scs) addPlonkConstraint(c sparseR1C, debug ...constraint.DebugInfo) {
	// TODO @gbotrel restore debug info
	// if len(debugID) > 0 {
	// 	builder.MDebug[len(builder.Constraints)] = debugID[0]
	// } else if debug.Debug {
	// 	builder.MDebug[len(builder.Constraints)] = constraint.NewDebugInfo("")
	// }

	// TODO @gbotrel doing a 2-step refactoring for now, frontend only need to update constraint/SparseR1C.
	L := builder.cs.MakeTerm(&c.qL, c.xa)
	R := builder.cs.MakeTerm(&c.qR, c.xb)
	O := builder.cs.MakeTerm(&c.qO, c.xc)
	U := builder.cs.MakeTerm(&c.qM, c.xa)
	V := builder.cs.MakeTerm(&builder.tOne, c.xb)
	K := builder.cs.MakeTerm(&c.qC, 0)
	K.MarkConstant()
	builder.cs.AddConstraint(constraint.SparseR1C{L: L, R: R, O: O, M: [2]constraint.Term{U, V}, K: K.CoeffID()}, debug...)
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (builder *scs) newInternalVariable() expr.Term {
	idx := builder.cs.AddInternalVariable()
	return expr.NewTerm(idx, builder.tOne)
}

// PublicVariable creates a new Public Variable
func (builder *scs) PublicVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddPublicVariable(f.FullName())
	return expr.NewTerm(idx, builder.tOne)
}

// SecretVariable creates a new Secret Variable
func (builder *scs) SecretVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddSecretVariable(f.FullName())
	return expr.NewTerm(idx, builder.tOne)
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public∥secret∥internal∥unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (builder *scs) reduce(l expr.LinearExpression) expr.LinearExpression {

	// ensure our linear expression is sorted, by visibility and by Variable ID
	sort.Sort(l)

	for i := 1; i < len(l); i++ {
		if l[i-1].VID == l[i].VID {
			// we have redundancy
			builder.cs.Add(&l[i-1].Coeff, &l[i].Coeff)
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

// to handle wires that don't exist (=coef 0) in a sparse constraint
func (builder *scs) zero() expr.Term {
	var a expr.Term
	return a
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (builder *scs) IsBoolean(v frontend.Variable) bool {
	if b, ok := builder.ConstantValue(v); ok {
		return b.IsUint64() && b.Uint64() <= 1
	}
	_, ok := builder.mtBooleans[int(v.(expr.Term).HashCode())] // TODO @gbotrel fixme this is sketchy
	return ok
}

// MarkBoolean sets (but do not constraint!) v to be boolean
// This is useful in scenarios where a variable is known to be boolean through a constraint
// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
func (builder *scs) MarkBoolean(v frontend.Variable) {
	if b, ok := builder.ConstantValue(v); ok {
		if !(b.IsUint64() && b.Uint64() <= 1) {
			panic("MarkBoolean called a non-boolean constant")
		}
		return
	}
	builder.mtBooleans[int(v.(expr.Term).HashCode())] = struct{}{} // TODO @gbotrel fixme this is sketchy
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}

func (builder *scs) Compile() (constraint.ConstraintSystem, error) {
	log := logger.Logger()
	log.Info().
		Int("nbConstraints", builder.cs.GetNbConstraints()).
		Msg("building constraint builder")

	// ensure all inputs and hints are constrained
	err := builder.cs.CheckUnconstrainedWires()
	if err != nil {
		log.Warn().Msg("circuit has unconstrained inputs")
		if !builder.config.IgnoreUnconstrainedInputs {
			return nil, err
		}
	}

	return builder.cs, nil
}

// ConstantValue returns the big.Int value of v.
// Will panic if v.IsConstant() == false
func (builder *scs) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	coeff, ok := builder.constantValue(v)
	if !ok {
		return nil, false
	}
	return builder.cs.ToBigInt(&coeff), true
}

func (builder *scs) constantValue(v frontend.Variable) (constraint.Coeff, bool) {
	if _, ok := v.(expr.Term); ok {
		return constraint.Coeff{}, false
	}
	return builder.cs.FromInterface(v), true
}

func (builder *scs) TOREFACTORMakeTerm(c *big.Int, vID int) constraint.Term {
	cc := builder.cs.FromInterface(c)
	return builder.cs.MakeTerm(&cc, vID)
}

// NewHint initializes internal variables whose value will be evaluated using
// the provided hint function at run time from the inputs. Inputs must be either
// variables or convertible to *big.Int. The function returns an error if the
// number of inputs is not compatible with f.
//
// The hint function is provided at the proof creation time and is not embedded
// into the circuit. From the backend point of view, the variable returned by
// the hint function is equivalent to the user-supplied witness, but its actual
// value is assigned by the solver, not the caller.
//
// No new constraints are added to the newly created wire and must be added
// manually in the circuit. Failing to do so leads to solver failure.
func (builder *scs) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {

	hintInputs := make([]constraint.LinearExpression, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case expr.Term:
			hintInputs[i] = constraint.LinearExpression{builder.cs.MakeTerm(&t.Coeff, t.VID)}
		default:
			c := utils.FromInterface(in)
			term := builder.TOREFACTORMakeTerm(&c, 0)
			term.MarkConstant()
			hintInputs[i] = constraint.LinearExpression{term}
		}
	}

	internalVariables, err := builder.cs.AddSolverHint(f, hintInputs, nbOutputs)
	if err != nil {
		return nil, err
	}

	// make the variables
	res := make([]frontend.Variable, len(internalVariables))
	for i, idx := range internalVariables {
		res[i] = expr.NewTerm(idx, builder.tOne)
	}
	return res, nil

}

// returns in split into a slice of compiledTerm and the sum of all constants in in as a bigInt
func (builder *scs) filterConstantSum(in []frontend.Variable) (expr.LinearExpression, big.Int) {
	res := make(expr.LinearExpression, 0, len(in))
	var b big.Int
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case expr.Term:
			res = append(res, t)
		default:
			n := utils.FromInterface(t)
			b.Add(&b, &n)
		}
	}
	return res, b
}

// returns in split into a slice of compiledTerm and the product of all constants in in as a coeff
func (builder *scs) filterConstantProd(in []frontend.Variable) (expr.LinearExpression, constraint.Coeff) {
	res := make(expr.LinearExpression, 0, len(in))
	b := builder.tOne
	for i := 0; i < len(in); i++ {
		if c, ok := builder.constantValue(in[i]); ok {
			builder.cs.Mul(&b, &c)
		} else {
			res = append(res, in[i].(expr.Term))
		}
	}
	return res, b
}

func (builder *scs) splitSum(acc expr.Term, r expr.LinearExpression) expr.Term {
	// floor case
	if len(r) == 0 {
		return acc
	}

	// constraint to add: acc + r[0] == o
	o := builder.newInternalVariable()
	builder.addAddGate(acc, r[0], o)
	return builder.splitSum(o, r[1:])
}

func (builder *scs) splitProd(acc expr.Term, r expr.LinearExpression) expr.Term {
	// floor case
	if len(r) == 0 {
		return acc
	}

	// constraint to add: acc * r[0] == o
	o := builder.newInternalVariable()
	builder.addMulGate(acc, r[0], o)
	return builder.splitProd(o, r[1:])
}

// newDebugInfo this is temporary to restore debug logs
// something more like builder.sprintf("my message %le %lv", l0, l1)
// to build logs for both debug and println
// and append some program location.. (see other todo in debug_info.go)
func (builder *scs) newDebugInfo(errName string, in ...interface{}) constraint.DebugInfo {
	for i := 0; i < len(in); i++ {
		// for inputs that are LinearExpressions or Term, we need to "Make" them in the backend.
		// TODO @gbotrel this is a duplicate effort with adding a constraint and should be taken care off

		switch t := in[i].(type) {
		case *expr.LinearExpression, expr.LinearExpression:
			// shouldn't happen
		case expr.Term:
			in[i] = builder.cs.MakeTerm(&t.Coeff, t.VID)
		case *expr.Term:
			in[i] = builder.cs.MakeTerm(&t.Coeff, t.VID)
		case constraint.Coeff:
			in[i] = builder.cs.String(&t)
		case *constraint.Coeff:
			in[i] = builder.cs.String(t)
		}
	}

	return builder.cs.NewDebugInfo(errName, in...)

}

func (builder *scs) Defer(cb func(frontend.API) error) {
	circuitdefer.Put(builder, cb)
}
