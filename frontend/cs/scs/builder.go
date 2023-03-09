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
	"fmt"
	"math/big"
	"reflect"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/frontend/schema"
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

	st     cs.CoeffTable
	config frontend.CompileConfig

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[int]struct{}

	q *big.Int
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
// TODO @gbotrel restore capacity option!
func newBuilder(field *big.Int, config frontend.CompileConfig) *scs {
	builder := scs{
		mtBooleans: make(map[int]struct{}),
		st:         cs.NewCoeffTable(),
		config:     config,
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
		panic("not implemtented")
	}

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

// addPlonkConstraint creates a constraint of the for al+br+clr+k=0
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0
func (builder *scs) addPlonkConstraint(xa, xb, xc expr.TermToRefactor, qL, qR, qM1, qM2, qO, qC int, debug ...constraint.DebugInfo) {
	// TODO @gbotrel the signature of this function is odd.. and confusing. need refactor.
	// TODO @gbotrel restore debug info
	// if len(debugID) > 0 {
	// 	builder.MDebug[len(builder.Constraints)] = debugID[0]
	// } else if debug.Debug {
	// 	builder.MDebug[len(builder.Constraints)] = constraint.NewDebugInfo("")
	// }

	xa.SetCoeffID(qL)
	xb.SetCoeffID(qR)
	xc.SetCoeffID(qO)

	u := xa
	v := xb
	u.SetCoeffID(qM1)
	v.SetCoeffID(qM2)
	L := builder.TOREFACTORMakeTerm(&builder.st.Coeffs[xa.CID], xa.VID)
	R := builder.TOREFACTORMakeTerm(&builder.st.Coeffs[xb.CID], xb.VID)
	O := builder.TOREFACTORMakeTerm(&builder.st.Coeffs[xc.CID], xc.VID)
	U := builder.TOREFACTORMakeTerm(&builder.st.Coeffs[u.CID], u.VID)
	V := builder.TOREFACTORMakeTerm(&builder.st.Coeffs[v.CID], v.VID)
	K := builder.TOREFACTORMakeTerm(&builder.st.Coeffs[qC], 0)
	K.MarkConstant()
	builder.cs.AddConstraint(constraint.SparseR1C{L: L, R: R, O: O, M: [2]constraint.Term{U, V}, K: K.CoeffID()}, debug...)
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (builder *scs) newInternalVariable() expr.TermToRefactor {
	idx := builder.cs.AddInternalVariable()
	return expr.NewTermToRefactor(idx, constraint.CoeffIdOne)
}

// PublicVariable creates a new Public Variable
func (builder *scs) PublicVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddPublicVariable(f.FullName())
	return expr.NewTermToRefactor(idx, constraint.CoeffIdOne)
}

// SecretVariable creates a new Secret Variable
func (builder *scs) SecretVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddSecretVariable(f.FullName())
	return expr.NewTermToRefactor(idx, constraint.CoeffIdOne)
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public∥secret∥internal∥unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (builder *scs) reduce(l expr.LinearExpressionToRefactor) expr.LinearExpressionToRefactor {

	// ensure our linear expression is sorted, by visibility and by Variable ID
	sort.Sort(l)

	c := new(big.Int)
	for i := 1; i < len(l); i++ {
		pcID, pvID := l[i-1].Unpack()
		ccID, cvID := l[i].Unpack()
		if pvID == cvID {
			// we have redundancy
			c.Add(&builder.st.Coeffs[pcID], &builder.st.Coeffs[ccID])
			c.Mod(c, builder.q)
			l[i-1].SetCoeffID(builder.st.CoeffID(c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

// to handle wires that don't exist (=coef 0) in a sparse constraint
func (builder *scs) zero() expr.TermToRefactor {
	var a expr.TermToRefactor
	return a
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (builder *scs) IsBoolean(v frontend.Variable) bool {
	if b, ok := builder.ConstantValue(v); ok {
		return b.IsUint64() && b.Uint64() <= 1
	}
	_, ok := builder.mtBooleans[int(v.(expr.TermToRefactor).CID|(int(v.(expr.TermToRefactor).VID)<<32))] // TODO @gbotrel fixme this is sketchy
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
	}
	builder.mtBooleans[int(v.(expr.TermToRefactor).CID|(int(v.(expr.TermToRefactor).VID)<<32))] = struct{}{} // TODO @gbotrel fixme this is sketchy
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

// ConstantValue returns the big.Int value of v. It
// panics if v.IsConstant() == false
func (builder *scs) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	switch t := v.(type) {
	case expr.TermToRefactor:
		return nil, false
	default:
		res := utils.FromInterface(t)
		return &res, true
	}
}

func (builder *scs) RecordConstraintsForLazy(key string, finished bool, s *[]frontend.Variable) {
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
		case expr.TermToRefactor:
			hintInputs[i] = constraint.LinearExpression{builder.TOREFACTORMakeTerm(&builder.st.Coeffs[t.CID], t.VID)}
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
		res[i] = expr.NewTermToRefactor(idx, constraint.CoeffIdOne)
	}
	return res, nil

}

// returns in split into a slice of compiledTerm and the sum of all constants in in as a bigInt
func (builder *scs) filterConstantSum(in []frontend.Variable) (expr.LinearExpressionToRefactor, big.Int) {
	res := make(expr.LinearExpressionToRefactor, 0, len(in))
	var b big.Int
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case expr.TermToRefactor:
			res = append(res, t)
		default:
			n := utils.FromInterface(t)
			b.Add(&b, &n)
		}
	}
	return res, b
}

// returns in split into a slice of compiledTerm and the product of all constants in in as a bigInt
func (builder *scs) filterConstantProd(in []frontend.Variable) (expr.LinearExpressionToRefactor, big.Int) {
	res := make(expr.LinearExpressionToRefactor, 0, len(in))
	var b big.Int
	b.SetInt64(1)
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case expr.TermToRefactor:
			res = append(res, t)
		default:
			n := utils.FromInterface(t)
			b.Mul(&b, &n).Mod(&b, builder.q)
		}
	}
	return res, b
}

func (builder *scs) splitSum(acc expr.TermToRefactor, r expr.LinearExpressionToRefactor) expr.TermToRefactor {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _ := acc.Unpack()
	cr, _ := r[0].Unpack()
	o := builder.newInternalVariable()
	builder.addPlonkConstraint(acc, r[0], o, cl, cr, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdMinusOne, constraint.CoeffIdZero)
	return builder.splitSum(o, r[1:])
}

func (builder *scs) splitProd(acc expr.TermToRefactor, r expr.LinearExpressionToRefactor) expr.TermToRefactor {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _ := acc.Unpack()
	cr, _ := r[0].Unpack()
	o := builder.newInternalVariable()
	builder.addPlonkConstraint(acc, r[0], o, constraint.CoeffIdZero, constraint.CoeffIdZero, cl, cr, constraint.CoeffIdMinusOne, constraint.CoeffIdZero)
	return builder.splitProd(o, r[1:])
}

func (builder *scs) Commit(v ...frontend.Variable) (frontend.Variable, error) {
	return nil, fmt.Errorf("not implemented")
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
		case *expr.LinearExpressionToRefactor, expr.LinearExpressionToRefactor:
			// shouldn't happen
		case expr.TermToRefactor:
			in[i] = builder.TOREFACTORMakeTerm(&builder.st.Coeffs[t.CID], t.VID)
		case *expr.TermToRefactor:
			in[i] = builder.TOREFACTORMakeTerm(&builder.st.Coeffs[t.CID], t.VID)
		case constraint.Coeff:
			in[i] = builder.cs.String(&t)
		case *constraint.Coeff:
			in[i] = builder.cs.String(t)
		}
	}

	return builder.cs.NewDebugInfo(errName, in...)

}
