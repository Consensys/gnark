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
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/schema"
	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6633r1cs "github.com/consensys/gnark/internal/backend/bw6-633/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
)

func NewBuilder(curve ecc.ID, config frontend.CompileConfig) (frontend.Builder, error) {
	return newBuilder(curve, config), nil
}

type scs struct {
	compiled.ConstraintSystem
	Constraints []compiled.SparseR1C

	st     cs.CoeffTable
	config frontend.CompileConfig

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[int]struct{}
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newBuilder(curveID ecc.ID, config frontend.CompileConfig) *scs {
	system := scs{
		ConstraintSystem: compiled.ConstraintSystem{
			MDebug:             make(map[int]int),
			MHints:             make(map[int]*compiled.Hint),
			MHintsDependencies: make(map[hint.ID]string),
		},
		mtBooleans:  make(map[int]struct{}),
		Constraints: make([]compiled.SparseR1C, 0, config.Capacity),
		st:          cs.NewCoeffTable(),
		config:      config,
	}

	system.Public = make([]string, 0)
	system.Secret = make([]string, 0)

	system.CurveID = curveID

	return &system
}

// addPlonkConstraint creates a constraint of the for al+br+clr+k=0
//func (system *SparseR1CS) addPlonkConstraint(l, r, o frontend.Variable, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {
func (system *scs) addPlonkConstraint(l, r, o compiled.Term, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {

	if len(debugID) > 0 {
		system.MDebug[len(system.Constraints)] = debugID[0]
	}

	l.SetCoeffID(cidl)
	r.SetCoeffID(cidr)
	o.SetCoeffID(cido)

	u := l
	v := r
	u.SetCoeffID(cidm1)
	v.SetCoeffID(cidm2)

	//system.Constraints = append(system.Constraints, compiled.SparseR1C{L: _l, R: _r, O: _o, M: [2]compiled.Term{u, v}, K: k})
	system.Constraints = append(system.Constraints, compiled.SparseR1C{L: l, R: r, O: o, M: [2]compiled.Term{u, v}, K: k})
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (system *scs) newInternalVariable() compiled.Term {
	idx := system.NbInternalVariables + system.NbPublicVariables + system.NbSecretVariables
	system.NbInternalVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, schema.Internal)
}

// AddPublicVariable creates a new Public Variable
func (system *scs) AddPublicVariable(name string) frontend.Variable {
	idx := len(system.Public)
	system.Public = append(system.Public, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, schema.Public)
}

// AddSecretVariable creates a new Secret Variable
func (system *scs) AddSecretVariable(name string) frontend.Variable {
	idx := len(system.Secret) + system.NbPublicVariables
	system.Secret = append(system.Secret, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, schema.Secret)
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public∥secret∥internal∥unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (system *scs) reduce(l compiled.LinearExpression) compiled.LinearExpression {

	// ensure our linear expression is sorted, by visibility and by Variable ID
	sort.Sort(l)

	mod := system.CurveID.Info().Fr.Modulus()
	c := new(big.Int)
	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&system.st.Coeffs[pcID], &system.st.Coeffs[ccID])
			c.Mod(c, mod)
			l[i-1].SetCoeffID(system.st.CoeffID(c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

// to handle wires that don't exist (=coef 0) in a sparse constraint
func (system *scs) zero() compiled.Term {
	var a compiled.Term
	return a
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (system *scs) IsBoolean(v frontend.Variable) bool {
	if b, ok := system.ConstantValue(v); ok {
		return b.IsUint64() && b.Uint64() <= 1
	}
	_, ok := system.mtBooleans[int(v.(compiled.Term))]
	return ok
}

// MarkBoolean sets (but do not constraint!) v to be boolean
// This is useful in scenarios where a variable is known to be boolean through a constraint
// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
func (system *scs) MarkBoolean(v frontend.Variable) {
	if b, ok := system.ConstantValue(v); ok {
		if !(b.IsUint64() && b.Uint64() <= 1) {
			panic("MarkBoolean called a non-boolean constant")
		}
	}
	system.mtBooleans[int(v.(compiled.Term))] = struct{}{}
}

// checkVariables perform post compilation checks on the Variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (system *scs) checkVariables() error {

	// TODO @gbotrel add unit test for that.

	cptSecret := len(system.Secret)
	cptPublic := len(system.Public)
	cptHints := len(system.MHints)

	// compared to R1CS, we may have a circuit which does not have any inputs
	// (R1CS always has a constant ONE wire). Check the edge case and omit any
	// processing if so.
	if cptSecret+cptPublic+cptHints == 0 {
		return nil
	}

	secretConstrained := make([]bool, cptSecret)
	publicConstrained := make([]bool, cptPublic)

	mHintsConstrained := make(map[int]bool)

	// for each constraint, we check the terms and mark our inputs / hints as constrained
	processTerm := func(t compiled.Term) {

		// L and M[0] handles the same wire but with a different coeff
		visibility := t.VariableVisibility()
		vID := t.WireID()
		if t.CoeffID() != compiled.CoeffIdZero {
			switch visibility {
			case schema.Public:
				if !publicConstrained[vID] {
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
	for _, c := range system.Constraints {
		processTerm(c.L)
		processTerm(c.R)
		processTerm(c.M[0])
		processTerm(c.M[1])
		processTerm(c.O)
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

func (cs *scs) Compile() (frontend.CompiledConstraintSystem, error) {
	log := logger.Logger()
	log.Info().
		Str("curve", cs.CurveID.String()).
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

	res := compiled.SparseR1CS{
		ConstraintSystem: cs.ConstraintSystem,
		Constraints:      cs.Constraints,
	}
	// sanity check
	if res.NbPublicVariables != len(cs.Public) || res.NbPublicVariables != cs.Schema.NbPublic {
		panic("number of public variables is inconsitent") // it grew after the schema parsing?
	}
	if res.NbSecretVariables != len(cs.Secret) || res.NbSecretVariables != cs.Schema.NbSecret {
		panic("number of secret variables is inconsitent") // it grew after the schema parsing?
	}

	// build levels
	res.Levels = buildLevels(res)

	switch cs.CurveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BW6_633:
		return bw6633r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	default:
		panic("unknown curveID")
	}

}

func (cs *scs) SetSchema(s *schema.Schema) {
	if cs.Schema != nil {
		panic("SetSchema called multiple times")
	}
	cs.Schema = s
	cs.NbPublicVariables = s.NbPublic
	cs.NbSecretVariables = s.NbSecret
}

func buildLevels(ccs compiled.SparseR1CS) [][]int {

	b := levelBuilder{
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

		b.processTerm(c.L, cID)
		b.processTerm(c.R, cID)
		b.processTerm(c.O, cID)

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

type levelBuilder struct {
	ccs      compiled.SparseR1CS
	nbInputs int

	mWireToNode map[int]int // at which node we resolved which wire
	nodeLevels  []int       // level per node
	mLevels     map[int]int // number of constraint per level

	nodeLevel int // current level
}

func (b *levelBuilder) processTerm(t compiled.Term, cID int) {
	wID := t.WireID()
	if wID < b.nbInputs {
		// it's a input, we ignore it
		return
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
		return
	}

	// check if it's a hint and mark all the output wires
	if h, ok := b.ccs.MHints[wID]; ok {

		for _, in := range h.Inputs {
			switch t := in.(type) {
			case compiled.LinearExpression:
				for _, tt := range t {
					b.processTerm(tt, cID)
				}
			case compiled.Term:
				b.processTerm(t, cID)
			}
		}

		for _, hwid := range h.Wires {
			b.mWireToNode[hwid] = cID
		}

		return
	}

	// mark this wire solved by current node
	b.mWireToNode[wID] = cID

}

// ConstantValue returns the big.Int value of v. It
// panics if v.IsConstant() == false
func (system *scs) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	switch t := v.(type) {
	case compiled.Term:
		return nil, false
	default:
		res := utils.FromInterface(t)
		return &res, true
	}
}

func (system *scs) Backend() backend.ID {
	return backend.PLONK
}

// Tag creates a tag at a given place in a circuit. The state of the tag may contain informations needed to
// measure constraints, variables and coefficients creations through AddCounter
func (system *scs) Tag(name string) frontend.Tag {
	_, file, line, _ := runtime.Caller(1)

	return frontend.Tag{
		Name: fmt.Sprintf("%s[%s:%d]", name, filepath.Base(file), line),
		VID:  system.NbInternalVariables,
		CID:  len(system.Constraints),
	}
}

// AddCounter measures the number of constraints, variables and coefficients created between two tags
// note that the PlonK statistics are contextual since there is a post-compile phase where linear expressions
// are factorized. That is, measuring 2 times the "repeating" piece of circuit may give less constraints the second time
func (system *scs) AddCounter(from, to frontend.Tag) {
	system.Counters = append(system.Counters, compiled.Counter{
		From:          from.Name,
		To:            to.Name,
		NbVariables:   to.VID - from.VID,
		NbConstraints: to.CID - from.CID,
		CurveID:       system.CurveID,
		BackendID:     backend.PLONK,
	})
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
func (system *scs) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
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
		case compiled.Term:
			hintInputs[i] = t
		default:
			hintInputs[i] = utils.FromInterface(in)
		}
	}

	// prepare wires
	varIDs := make([]int, nbOutputs)
	res := make([]frontend.Variable, len(varIDs))
	for i := range varIDs {
		r := system.newInternalVariable()
		_, vID, _ := r.Unpack()
		varIDs[i] = vID
		res[i] = r
	}

	ch := &compiled.Hint{ID: hintUUID, Inputs: hintInputs, Wires: varIDs}
	for _, vID := range varIDs {
		system.MHints[vID] = ch
	}

	return res, nil
}

// returns in split into a slice of compiledTerm and the sum of all constants in in as a bigInt
func (system *scs) filterConstantSum(in []frontend.Variable) (compiled.LinearExpression, big.Int) {
	res := make(compiled.LinearExpression, 0, len(in))
	var b big.Int
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case compiled.Term:
			res = append(res, t)
		default:
			n := utils.FromInterface(t)
			b.Add(&b, &n)
		}
	}
	return res, b
}

// returns in split into a slice of compiledTerm and the product of all constants in in as a bigInt
func (system *scs) filterConstantProd(in []frontend.Variable) (compiled.LinearExpression, big.Int) {
	res := make(compiled.LinearExpression, 0, len(in))
	var b big.Int
	b.SetInt64(1)
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case compiled.Term:
			res = append(res, t)
		default:
			n := utils.FromInterface(t)
			b.Mul(&b, &n).Mod(&b, system.CurveID.Info().Fr.Modulus())
		}
	}
	return res, b
}

func (system *scs) splitSum(acc compiled.Term, r compiled.LinearExpression) compiled.Term {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _, _ := acc.Unpack()
	cr, _, _ := r[0].Unpack()
	o := system.newInternalVariable()
	system.addPlonkConstraint(acc, r[0], o, cl, cr, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, compiled.CoeffIdZero)
	return system.splitSum(o, r[1:])
}

func (system *scs) splitProd(acc compiled.Term, r compiled.LinearExpression) compiled.Term {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _, _ := acc.Unpack()
	cr, _, _ := r[0].Unpack()
	o := system.newInternalVariable()
	system.addPlonkConstraint(acc, r[0], o, compiled.CoeffIdZero, compiled.CoeffIdZero, cl, cr, compiled.CoeffIdMinusOne, compiled.CoeffIdZero)
	return system.splitProd(o, r[1:])
}
