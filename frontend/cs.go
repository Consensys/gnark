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

package frontend

import (
	"io"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// ConstraintSystem represents a Groth16 like circuit
//
// All the APIs to define a circuit (see Circuit.Define) like Add, Sub, Mul, ...
// may take as input interface{}
//
// these interfaces are either Variables (/LinearExpressions) or constants (big.Int, strings, uint, fr.Element)
type ConstraintSystem struct {
	// Variables (aka wires)
	// virtual variables do not result in a new circuit wire
	// they may only contain a linear expression
	public, secret, internal, virtual variables

	// list of constraints in the form a * b == c
	// a,b and c being linear expressions
	constraints []compiled.R1C

	// Coefficients in the constraints
	coeffs    []big.Int      // list of unique coefficients.
	coeffsIDs map[string]int // map to fast check existence of a coefficient (key = coeff.Text(16))

	// Hints
	mHints map[int]compiled.Hint // solver hints

	logs      []compiled.LogEntry // list of logs to be printed when solving a circuit. The logs are called with the method Println
	debugInfo []compiled.LogEntry // list of logs storing information about R1C

	mDebug map[int]int // maps constraint ID to debugInfo id

	curveID ecc.ID
}

type variables struct {
	variables []Variable
	booleans  map[int]struct{} // keep track of boolean variables (we constrain them once)
}

func (v *variables) new(cs *ConstraintSystem, visibility compiled.Visibility) Variable {
	idx := len(v.variables)
	variable := Variable{visibility: visibility, id: idx, linExp: cs.LinearExpression(compiled.Pack(idx, compiled.CoeffIdOne, visibility))}

	v.variables = append(v.variables, variable)
	return variable
}

// CompiledConstraintSystem ...
type CompiledConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom

	// GetNbVariables return number of internal, secret and public variables
	GetNbVariables() (internal, secret, public int)
	GetNbConstraints() int
	GetNbCoefficients() int

	CurveID() ecc.ID
	FrSize() int

	// ToHTML generates a human readable representation of the constraint system
	ToHTML(w io.Writer) error
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newConstraintSystem(curveID ecc.ID, initialCapacity ...int) ConstraintSystem {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	cs := ConstraintSystem{
		coeffs:      make([]big.Int, 4),
		coeffsIDs:   make(map[string]int),
		constraints: make([]compiled.R1C, 0, capacity),
		mDebug:      make(map[int]int),
		mHints:      make(map[int]compiled.Hint),
	}

	cs.coeffs[compiled.CoeffIdZero].SetInt64(0)
	cs.coeffs[compiled.CoeffIdOne].SetInt64(1)
	cs.coeffs[compiled.CoeffIdTwo].SetInt64(2)
	cs.coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	cs.public.variables = make([]Variable, 0)
	cs.public.booleans = make(map[int]struct{})

	cs.secret.variables = make([]Variable, 0)
	cs.secret.booleans = make(map[int]struct{})

	cs.internal.variables = make([]Variable, 0, capacity)
	cs.internal.booleans = make(map[int]struct{})

	cs.virtual.variables = make([]Variable, 0)
	cs.virtual.booleans = make(map[int]struct{})

	// by default the circuit is given on public wire equal to 1
	cs.public.variables[0] = cs.newPublicVariable()

	cs.curveID = curveID

	return cs
}

// NewHint initialize a variable whose value will be evaluated in the Prover by the constraint
// solver using the provided hint function
// hint function is provided at proof creation time and must match the hintID
// inputs must be either variables or convertible to big int
// /!\ warning /!\
// this doesn't add any constraint to the newly created wire
// from the backend point of view, it's equivalent to a user-supplied witness
// except, the solver is going to assign it a value, not the caller
func (cs *ConstraintSystem) NewHint(hintID hint.ID, inputs ...interface{}) Variable {
	// create resulting wire
	r := cs.newInternalVariable()

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]compiled.LinearExpression, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		t := cs.Constant(in)
		hintInputs[i] = t.linExp.Clone() // TODO @gbotrel check that we need to clone here ?
	}

	// add the hint to the constraint system
	cs.mHints[r.id] = compiled.Hint{ID: hintID, Inputs: hintInputs}

	return r
}

// bitLen returns the number of bits needed to represent a fr.Element
func (cs *ConstraintSystem) bitLen() int {
	switch cs.curveID {
	case ecc.BN254:
		return fr_bn254.Bits
	case ecc.BLS12_377:
		return fr_bls12377.Bits
	case ecc.BLS12_381:
		return fr_bls12381.Bits
	case ecc.BW6_761:
		return fr_bw6761.Bits
	case ecc.BLS24_315:
		return fr_bls24315.Bits
	default:
		panic("curve not implemented")
	}
}

func (cs *ConstraintSystem) one() Variable {
	return cs.public.variables[0]
}

// Term packs a variable and a coeff in a compiled.Term and returns it.
func (cs *ConstraintSystem) makeTerm(v Variable, coeff *big.Int) compiled.Term {
	return compiled.Pack(v.id, cs.coeffID(coeff), v.visibility)
}

// newR1C clones the linear expression associated with the variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C(l, r, o Variable) compiled.R1C {
	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if len(l.linExp) > len(r.linExp) {
		l, r = r, l
	}

	return compiled.R1C{L: l.linExp.Clone(), R: r.linExp.Clone(), O: o.linExp.Clone()}
}

// NbConstraints enables circuit profiling and helps debugging
// It returns the number of constraints created at the current stage of the circuit construction.
func (cs *ConstraintSystem) NbConstraints() int {
	return len(cs.constraints)
}

// LinearExpression packs a list of compiled.Term in a compiled.LinearExpression and returns it.
func (cs *ConstraintSystem) LinearExpression(terms ...compiled.Term) compiled.LinearExpression {
	res := make(compiled.LinearExpression, len(terms))
	for i, args := range terms {
		res[i] = args
	}
	return res
}

// reduces redundancy in linear expression
// It factorizes variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, variables are stored as public||secret||internal||unset
// for each visibility, the variables are sorted from lowest ID to highest ID
func (cs *ConstraintSystem) reduce(l compiled.LinearExpression) compiled.LinearExpression {
	// ensure our linear expression is sorted, by visibility and by variable ID
	if !sort.IsSorted(l) { // may not help
		sort.Sort(l)
	}

	var c big.Int
	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&cs.coeffs[pcID], &cs.coeffs[ccID])
			l[i-1].SetCoeffID(cs.coeffID(&c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}

	return l
}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (cs *ConstraintSystem) coeffID(b *big.Int) int {

	// if the coeff is a int64, and has value -1, 0, 1 or 2, we have a fast path.
	if b.IsInt64() {
		v := b.Int64()
		switch v {
		case -1:
			return compiled.CoeffIdMinusOne
		case 0:
			return compiled.CoeffIdZero
		case 1:
			return compiled.CoeffIdOne
		case 2:
			return compiled.CoeffIdTwo
		}
	}

	// if the coeff is already stored, fetch its ID from the cs.coeffsIDs map
	key := b.Text(16)
	if idx, ok := cs.coeffsIDs[key]; ok {
		return idx
	}

	// else add it in the cs.coeffs map and update the cs.coeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(cs.coeffs)
	cs.coeffs = append(cs.coeffs, bCopy)
	cs.coeffsIDs[key] = resID
	return resID
}

func (cs *ConstraintSystem) addConstraint(r1c compiled.R1C, debugID ...int) {
	cs.constraints = append(cs.constraints, r1c)
	if len(debugID) > 0 {
		cs.mDebug[len(cs.constraints)-1] = debugID[0]
	}
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (cs *ConstraintSystem) newInternalVariable() Variable {
	return cs.internal.new(cs, compiled.Internal)
}

// newPublicVariable creates a new public variable
func (cs *ConstraintSystem) newPublicVariable() Variable {
	return cs.public.new(cs, compiled.Public)
}

// newSecretVariable creates a new secret variable
func (cs *ConstraintSystem) newSecretVariable() Variable {
	return cs.secret.new(cs, compiled.Secret)
}

// newVirtualVariable creates a new virtual variable
// this will not result in a new wire in the constraint system
// and just represents a linear expression
func (cs *ConstraintSystem) newVirtualVariable() Variable {
	return cs.virtual.new(cs, compiled.Virtual)
}

// markBoolean marks the variable as boolean and return true
// if a constraint was added, false if the variable was already
// constrained as a boolean
func (cs *ConstraintSystem) markBoolean(v Variable) bool {
	switch v.visibility {
	case compiled.Internal:
		if _, ok := cs.internal.booleans[v.id]; ok {
			return false
		}
		cs.internal.booleans[v.id] = struct{}{}
	case compiled.Secret:
		if _, ok := cs.secret.booleans[v.id]; ok {
			return false
		}
		cs.secret.booleans[v.id] = struct{}{}
	case compiled.Public:
		if _, ok := cs.public.booleans[v.id]; ok {
			return false
		}
		cs.public.booleans[v.id] = struct{}{}
	case compiled.Virtual:
		if _, ok := cs.virtual.booleans[v.id]; ok {
			return false
		}
		cs.virtual.booleans[v.id] = struct{}{}
	default:
		panic("not implemented")
	}
	return true
}
