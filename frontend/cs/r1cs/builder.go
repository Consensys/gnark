/*
Copyright © 2020 ConsenSys

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

package r1cs

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/field"
	"github.com/consensys/gnark/frontend/schema"
	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bls24317r1cs "github.com/consensys/gnark/internal/backend/bls24-317/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6633r1cs "github.com/consensys/gnark/internal/backend/bw6-633/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
	"github.com/consensys/gnark/internal/tinyfield"
	tinyfieldr1cs "github.com/consensys/gnark/internal/tinyfield/cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/profile"
)

// NewBuilder returns a new R1CS compiler
func NewBuilder(field *big.Int, config frontend.CompileConfig) (frontend.Builder, error) {
	curve := utils.FieldToCurve(field)
	switch curve {
	case ecc.BN254:
		return newBuilder[fr_bn254.Element](field, config), nil
	case ecc.BLS12_377:
		return newBuilder[fr_bls12377.Element](field, config), nil
	case ecc.BLS12_381:
		return newBuilder[fr_bls12381.Element](field, config), nil
	case ecc.BLS24_315:
		return newBuilder[fr_bls24315.Element](field, config), nil
	case ecc.BLS24_317:
		return newBuilder[fr_bls24317.Element](field, config), nil
	case ecc.BW6_761:
		return newBuilder[fr_bw6761.Element](field, config), nil
	case ecc.BW6_633:
		return newBuilder[fr_bw6633.Element](field, config), nil
	default:
		if field.Cmp(tinyfield.Modulus()) == 0 {
			return newBuilder[tinyfield.Element](field, config), nil
		}
		panic("not implemented yet")
	}
}

type r1cs[E field.El, ptE field.PtEl[E]] struct {
	compiled.ConstraintSystem[E, ptE]
	Constraints []compiled.R1C[E, ptE]

	config frontend.CompileConfig

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[uint64][]compiled.LinearExpression[E, ptE]

	q *big.Int
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newBuilder[E field.El, ptE field.PtEl[E]](field *big.Int, config frontend.CompileConfig) *r1cs[E, ptE] {
	system := r1cs[E, ptE]{
		ConstraintSystem: compiled.NewConstraintSystem[E, ptE](field),
		Constraints:      make([]compiled.R1C[E, ptE], 0, config.Capacity),
		mtBooleans:       make(map[uint64][]compiled.LinearExpression[E, ptE]),
		config:           config,
	}

	system.Public = make([]string, 1)
	system.Secret = make([]string, 0)

	// by default the circuit is given a public wire equal to 1
	system.Public[0] = "one"

	system.q = system.Field()

	return &system
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (system *r1cs[E, ptE]) newInternalVariable() compiled.LinearExpression[E, ptE] {
	idx := system.NbInternalVariables + system.NbPublicVariables + system.NbSecretVariables
	system.NbInternalVariables++
	return compiled.LinearExpression[E, ptE]{
		compiled.PackInt64[E, ptE](idx, 1, schema.Internal),
	}
}

func (system *r1cs[E, ptE]) VariableCount(t reflect.Type) int {
	return 1
}

// AddPublicVariable creates a new public Variable
func (system *r1cs[E, ptE]) AddPublicVariable(f *schema.Field) frontend.Variable {
	idx := len(system.Public)
	system.Public = append(system.Public, f.FullName)
	return compiled.LinearExpression[E, ptE]{
		compiled.PackInt64[E, ptE](idx, 1, schema.Public),
	}
}

// AddSecretVariable creates a new secret Variable
func (system *r1cs[E, ptE]) AddSecretVariable(f *schema.Field) frontend.Variable {
	idx := len(system.Secret) + system.NbPublicVariables
	system.Secret = append(system.Secret, f.FullName)
	return compiled.LinearExpression[E, ptE]{
		compiled.PackInt64[E, ptE](idx, 1, schema.Secret),
	}
}

func (system *r1cs[E, ptE]) one() compiled.LinearExpression[E, ptE] {
	return compiled.LinearExpression[E, ptE]{
		compiled.PackInt64[E, ptE](0, 1, schema.Public),
	}
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public∥secret∥internal∥unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (system *r1cs[E, ptE]) reduce(l compiled.LinearExpression[E, ptE]) compiled.LinearExpression[E, ptE] {
	// ensure our linear expression is sorted, by visibility and by Variable ID
	if !sort.IsSorted(l) { // may not help
		sort.Sort(l)
	}
	omittable := make([]int, 0, len(l))

	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		// if the coefficient is zero, we remove it
		if l[i].IsZero() {
			omittable = append(omittable, i)
			continue
		}
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			var newCoeff E
			ptE(&newCoeff).Add(&pcID, &ccID)
			l[i].SetCoeff(newCoeff)
			omittable = append(omittable, i-1)
		}
	}
	ll := make(compiled.LinearExpression[E, ptE], 0, len(l)-len(omittable))
	start := 0
	for k := 0; k < len(omittable); k++ {
		if omittable[k] != start-1 {
			ll = append(ll, l[start:omittable[k]]...)
			start = omittable[k] + 1
		}
	}
	ll = append(ll, l[start:]...)
	ll = system.compress(ll)
	return ll
}

// newR1C clones the linear expression associated with the Variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C[E field.El, ptE field.PtEl[E]](_l, _r, _o frontend.Variable) compiled.R1C[E, ptE] {
	l := _l.(compiled.LinearExpression[E, ptE])
	r := _r.(compiled.LinearExpression[E, ptE])
	o := _o.(compiled.LinearExpression[E, ptE])

	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less Variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if len(l) > len(r) {
		l, r = r, l
	}

	return compiled.R1C[E, ptE]{L: l.Clone(), R: r.Clone(), O: o.Clone()}
}

func (system *r1cs[E, ptE]) addConstraint(r1c compiled.R1C[E, ptE], debugID ...int) {
	profile.RecordConstraint()
	system.Constraints = append(system.Constraints, r1c)
	if len(debugID) > 0 {
		system.MDebug[len(system.Constraints)-1] = debugID[0]
	} else if debug.Debug {
		system.MDebug[len(system.Constraints)-1] = system.AddDebugInfo("")
	}
}

// MarkBoolean sets (but do not **constraint**!) v to be boolean
// This is useful in scenarios where a variable is known to be boolean through a constraint
// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
func (system *r1cs[E, ptE]) MarkBoolean(v frontend.Variable) {
	if b, ok := system.ConstantValue(v); ok {
		if !(b.IsUint64() && b.Uint64() <= 1) {
			panic("MarkBoolean called a non-boolean constant")
		}
		return
	}
	// v is a linear expression
	l := v.(compiled.LinearExpression[E, ptE])
	if !sort.IsSorted(l) {
		sort.Sort(l)
	}

	key := l.HashCode()
	list := system.mtBooleans[key]
	list = append(list, l)
	system.mtBooleans[key] = list
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (system *r1cs[E, ptE]) IsBoolean(v frontend.Variable) bool {
	if b, ok := system.ConstantValue(v); ok {
		return b.IsUint64() && b.Uint64() <= 1
	}
	// v is a linear expression
	l := v.(compiled.LinearExpression[E, ptE])
	if !sort.IsSorted(l) {
		sort.Sort(l)
	}

	key := l.HashCode()
	list, ok := system.mtBooleans[key]
	if !ok {
		return false
	}

	for _, v := range list {
		if v.Equal(l) {
			return true
		}
	}
	return false
}

// checkVariables perform post compilation checks on the Variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (system *r1cs[E, ptE]) checkVariables() error {

	// TODO @gbotrel add unit test for that.

	cptSecret := len(system.Secret)
	cptPublic := len(system.Public)
	cptHints := len(system.MHints)

	secretConstrained := make([]bool, cptSecret)
	publicConstrained := make([]bool, cptPublic)
	// one wire does not need to be constrained
	publicConstrained[0] = true
	cptPublic--

	mHintsConstrained := make(map[int]bool)

	// for each constraint, we check the linear expressions and mark our inputs / hints as constrained
	processLinearExpression := func(l compiled.LinearExpression[E, ptE]) {
		for _, t := range l {
			if t.IsZero() {
				// ignore zero coefficient, as it does not constraint the Variable
				// though, we may want to flag that IF the Variable doesn't appear else where
				continue
			}
			visibility := t.VariableVisibility()
			vID := t.WireID()

			switch visibility {
			case schema.Public:
				if vID != 0 && !publicConstrained[vID] {
					publicConstrained[vID] = true
					cptPublic--
				}
			case schema.Secret:
				vID -= system.NbPublicVariables
				if !secretConstrained[vID] {
					secretConstrained[vID] = true
					cptSecret--
				}
			case schema.Internal:

				if _, ok := system.MHints[vID]; ok {
					vID -= (system.NbPublicVariables + system.NbSecretVariables)
					if !mHintsConstrained[vID] {
						mHintsConstrained[vID] = true
						cptHints--
					}
				}
			}
		}
	}
	for _, r1c := range system.Constraints {
		processLinearExpression(r1c.L)
		processLinearExpression(r1c.R)
		processLinearExpression(r1c.O)

		if cptHints|cptSecret|cptPublic == 0 {
			return nil // we can stop.
		}

	}

	// something is a miss, we build the error string
	var sbb strings.Builder
	if cptSecret != 0 {
		sbb.WriteString(strconv.Itoa(cptSecret))
		sbb.WriteString(" unconstrained secret input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(secretConstrained) && cptSecret != 0; i++ {
			if !secretConstrained[i] {
				sbb.WriteString(system.Secret[i])
				sbb.WriteByte('\n')
				cptSecret--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptPublic != 0 {
		sbb.WriteString(strconv.Itoa(cptPublic))
		sbb.WriteString(" unconstrained public input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(publicConstrained) && cptPublic != 0; i++ {
			if !publicConstrained[i] {
				sbb.WriteString(system.Public[i])
				sbb.WriteByte('\n')
				cptPublic--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptHints != 0 {
		sbb.WriteString(strconv.Itoa(cptHints))
		sbb.WriteString(" unconstrained hints")
		sbb.WriteByte('\n')
		// TODO we may add more debug info here → idea, in NewHint, take the debug stack, and store in the hint map some
		// debugInfo to find where a hint was declared (and not constrained)
	}
	return errors.New(sbb.String())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}

// Compile constructs a rank-1 constraint sytem
func (cs *r1cs[E, ptE]) Compile() (frontend.CompiledConstraintSystem, error) {
	log := logger.Logger()
	log.Info().
		Int("nbConstraints", len(cs.Constraints)).
		Msg("building constraint system")

	// ensure all inputs and hints are constrained
	err := cs.checkVariables()
	if err != nil {
		log.Warn().Msg("circuit has unconstrained inputs")
		if !cs.config.IgnoreUnconstrainedInputs {
			return nil, err
		}
	}
	// wires = public wires  | secret wires | internal wires

	// setting up the result
	res := compiled.R1CS[E, ptE]{
		ConstraintSystem: cs.ConstraintSystem,
		Constraints:      cs.Constraints,
	}

	// sanity check
	if res.NbPublicVariables != len(cs.Public) || res.NbPublicVariables != cs.Schema.NbPublic+1 {
		panic("number of public variables is inconsitent") // it grew after the schema parsing?
	}
	if res.NbSecretVariables != len(cs.Secret) || res.NbSecretVariables != cs.Schema.NbSecret {
		panic("number of secret variables is inconsitent") // it grew after the schema parsing?
	}

	// build levels
	res.Levels = buildLevels(res)

	switch tres := any(res).(type) {
	case compiled.R1CS[fr_bn254.Element, *fr_bn254.Element]:
		return bn254r1cs.NewR1CS(tres, nil), nil
	case compiled.R1CS[fr_bls12377.Element, *fr_bls12377.Element]:
		return bls12377r1cs.NewR1CS(tres, nil), nil
	case compiled.R1CS[fr_bls12381.Element, *fr_bls12381.Element]:
		return bls12381r1cs.NewR1CS(tres, nil), nil
	case compiled.R1CS[fr_bls24315.Element, *fr_bls24315.Element]:
		return bls24315r1cs.NewR1CS(tres, nil), nil
	case compiled.R1CS[fr_bls24317.Element, *fr_bls24317.Element]:
		return bls24317r1cs.NewR1CS(tres, nil), nil
	case compiled.R1CS[fr_bw6633.Element, *fr_bw6633.Element]:
		return bw6633r1cs.NewR1CS(tres, nil), nil
	case compiled.R1CS[fr_bw6761.Element, *fr_bw6761.Element]:
		return bw6761r1cs.NewR1CS(tres, nil), nil
	case compiled.R1CS[tinyfield.Element, *tinyfield.Element]:
		return tinyfieldr1cs.NewR1CS(tres, nil), nil
	default:
		panic("not implemented")
	}
}

func (cs *r1cs[E, ptE]) SetSchema(s *schema.Schema) {
	if cs.Schema != nil {
		panic("SetSchema called multiple times")
	}
	cs.Schema = s
	cs.NbPublicVariables = s.NbPublic + 1
	cs.NbSecretVariables = s.NbSecret
}

func buildLevels[E field.El, ptE field.PtEl[E]](ccs compiled.R1CS[E, ptE]) [][]int {

	b := levelBuilder[E, ptE]{
		mWireToNode: make(map[int]int, ccs.NbInternalVariables), // at which node we resolved which wire
		nodeLevels:  make([]int, len(ccs.Constraints)),          // level of a node
		mLevels:     make(map[int]int),                          // level counts
		ccs:         ccs,
		nbInputs:    ccs.NbPublicVariables + ccs.NbSecretVariables,
	}

	// for each constraint, we're going to find its direct dependencies
	// that is, wires (solved by previous constraints) on which it depends
	// each of these dependencies is tagged with a level
	// current constraint will be tagged with max(level) + 1
	for cID, c := range ccs.Constraints {

		b.nodeLevel = 0

		b.processLE(c.L, cID)
		b.processLE(c.R, cID)
		b.processLE(c.O, cID)
		b.nodeLevels[cID] = b.nodeLevel
		b.mLevels[b.nodeLevel]++

	}

	levels := make([][]int, len(b.mLevels))
	for i := 0; i < len(levels); i++ {
		// allocate memory
		levels[i] = make([]int, 0, b.mLevels[i])
	}

	for n, l := range b.nodeLevels {
		levels[l] = append(levels[l], n)
	}

	return levels
}

type levelBuilder[E field.El, ptE field.PtEl[E]] struct {
	ccs      compiled.R1CS[E, ptE]
	nbInputs int

	mWireToNode map[int]int // at which node we resolved which wire
	nodeLevels  []int       // level per node
	mLevels     map[int]int // number of constraint per level

	nodeLevel int // current level
}

func (b *levelBuilder[E, ptE]) processLE(l compiled.LinearExpression[E, ptE], cID int) {

	for _, t := range l {
		wID := t.WireID()
		if wID < b.nbInputs {
			// it's a input, we ignore it
			continue
		}

		// if we know a which constraint solves this wire, then it's a dependency
		n, ok := b.mWireToNode[wID]
		if ok {
			if n != cID { // can happen with hints...
				// we add a dependency, check if we need to increment our current level
				if b.nodeLevels[n] >= b.nodeLevel {
					b.nodeLevel = b.nodeLevels[n] + 1 // we are at the next level at least since we depend on it
				}
			}
			continue
		}

		// check if it's a hint and mark all the output wires
		if h, ok := b.ccs.MHints[wID]; ok {

			for _, in := range h.Inputs {
				switch t := in.(type) {
				case compiled.LinearExpression[E, ptE]:
					b.processLE(t, cID)
				case compiled.Term[E, ptE]:
					b.processLE(compiled.LinearExpression[E, ptE]{t}, cID)
				}
			}

			for _, hwid := range h.Wires {
				b.mWireToNode[hwid] = cID
			}
			continue
		}

		// mark this wire solved by current node
		b.mWireToNode[wID] = cID
	}
}

// ConstantValue returns the big.Int value of v.
// Will panic if v.IsConstant() == false
func (system *r1cs[E, ptE]) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	if _v, ok := v.(compiled.LinearExpression[E, ptE]); ok {
		assertIsSet(_v)

		if len(_v) != 1 {
			return nil, false
		}
		coeff, vID, visibility := _v[0].Unpack()
		if !(vID == 0 && visibility == schema.Public) {
			return nil, false
		}
		ret := new(big.Int)
		ptE(&coeff).ToBigIntRegular(ret)
		return ret, true
		// return new(big.Int).Set(system.st.Coeffs[cID]), true
	}
	r := utils.FromInterface(v)
	return &r, true
}

// toVariable will return (and allocate if neccesary) a compiled.LinearExpression from given value
//
// if input is already a compiled.LinearExpression, does nothing
// else, attempts to convert input to a big.Int (see utils.FromInterface) and returns a toVariable compiled.LinearExpression
func (system *r1cs[E, ptE]) toVariable(input interface{}) frontend.Variable {

	switch t := input.(type) {
	case compiled.LinearExpression[E, ptE]:
		assertIsSet(t)
		return t
	default:
		n := utils.FromInterface(t)
		if n.IsUint64() && n.Uint64() == 1 {
			return system.one()
		}
		var nFr E
		ptE(&nFr).SetBigInt(&n)
		r := system.one()
		r[0].SetCoeff(nFr)
		return r
	}
}

// toVariables return frontend.Variable corresponding to inputs and the total size of the linear expressions
func (system *r1cs[E, ptE]) toVariables(in ...frontend.Variable) ([]compiled.LinearExpression[E, ptE], int) {
	r := make([]compiled.LinearExpression[E, ptE], 0, len(in))
	s := 0
	e := func(i frontend.Variable) {
		v := system.toVariable(i).(compiled.LinearExpression[E, ptE])
		r = append(r, v)
		s += len(v)
	}
	// e(i1)
	// e(i2)
	for i := 0; i < len(in); i++ {
		e(in[i])
	}
	return r, s
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
func (system *r1cs[E, ptE]) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	if nbOutputs <= 0 {
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

	hintInputs := make([]interface{}, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case compiled.LinearExpression[E, ptE]:
			assertIsSet(t)
			tmp := make(compiled.LinearExpression[E, ptE], len(t))
			copy(tmp, t)
			hintInputs[i] = tmp
		default:
			hintInputs[i] = utils.FromInterface(t)
		}
	}

	// prepare wires
	varIDs := make([]int, nbOutputs)
	res := make([]frontend.Variable, len(varIDs))
	for i := range varIDs {
		r := system.newInternalVariable()
		_, vID, _ := r[0].Unpack()
		varIDs[i] = vID
		res[i] = r
	}

	ch := &compiled.Hint[E, ptE]{ID: hintUUID, Inputs: hintInputs, Wires: varIDs}
	for _, vID := range varIDs {
		system.MHints[vID] = ch
	}

	return res, nil
}

func (system *r1cs[E, ptE]) compress(v compiled.LinearExpression[E, ptE]) compiled.LinearExpression[E, ptE] {
	if system.config.CompressThreshold <= 0 || len(v) < system.config.CompressThreshold {
		return v
	}

	one := system.one()
	res := system.newInternalVariable()
	system.addConstraint(newR1C[E, ptE](v, one, res))
	return res
}

// assertIsSet panics if the variable is unset
// this may happen if inside a Define we have
// var a variable
// cs.Mul(a, 1)
// since a was not in the circuit struct it is not a secret variable
func assertIsSet[E field.El, ptE field.PtEl[E]](l compiled.LinearExpression[E, ptE]) {
	// TODO PlonK scs doesn't have a similar check with compiled.Term == 0
	if len(l) == 0 {
		// errNoValue triggered when trying to access a variable that was not allocated
		errNoValue := errors.New("can't determine API input value")
		panic(errNoValue)
	}

}
