package frontend

import (
	"math/big"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// plonkConstraintSystem represents a plonk like system of constraints.
//
// All the APIs to define a circuit (see Circuit.Define) like Add, Sub, Mul, ...
// may take as input interface{}
//
// these interfaces are either Variables (/LinearExpressions) or constants (big.Int, strings, uint, fr.Element)
type plonkConstraintSystem struct {

	// input wires
	public, secret []string

	// internal wires
	internal int

	// list of constraints in the form a * b == c
	// a,b and c being linear expressions
	constraints []compiled.SparseR1C

	// Coefficients in the constraints
	coeffs         []big.Int      // list of unique coefficients.
	coeffsIDsLarge map[string]int // map to check existence of a coefficient (key = coeff.Bytes())
	coeffsIDsInt64 map[int64]int  // map to check existence of a coefficient (key = int64 value)

	// Hints
	mHints            map[int]compiled.Hint // solver hints
	mHintsConstrained map[int]bool          // marks hints compiled.Variables constrained status

	logs      []compiled.LogEntry // list of logs to be printed when solving a circuit. The logs are called with the method Println
	debugInfo []compiled.LogEntry // list of logs storing information about R1C

	mDebug map[int]int // maps constraint ID to debugInfo id

	counters []Counter // statistic counters

	curveID   ecc.ID
	backendID backend.ID
}

// addPlonkConstraint creates a constraint of the for al+br+clr+k=0
func (cs *plonkConstraintSystem) addPlonkConstraint(l, r, o Variable, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {

	if len(debugID) > 0 {
		cs.mDebug[len(cs.constraints)-1] = debugID[0]
	}

	_l := l.(compiled.Term)
	_r := r.(compiled.Term)
	_o := o.(compiled.Term)
	_l.SetCoeffID(cidl)
	_r.SetCoeffID(cidr)
	_o.SetCoeffID(cido)

	u := _l
	v := _r
	u.SetCoeffID(cidm1)
	v.SetCoeffID(cidm2)

	cs.constraints = append(cs.constraints, compiled.SparseR1C{L: _l, R: _r, O: _o, M: [2]compiled.Term{u, v}, K: k})
}

func (cs *plonkConstraintSystem) coeffID64(v int64) int {
	if resID, ok := cs.coeffsIDsInt64[v]; ok {
		return resID
	} else {
		var bCopy big.Int
		bCopy.SetInt64(v)
		resID := len(cs.coeffs)
		cs.coeffs = append(cs.coeffs, bCopy)
		cs.coeffsIDsInt64[v] = resID
		return resID
	}
}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (cs *plonkConstraintSystem) coeffID(b *big.Int) int {

	// if the coeff is a int64 we have a fast path.
	if b.IsInt64() {
		return cs.coeffID64(b.Int64())
	}

	// GobEncode is 3x faster than b.Text(16). Slightly slower than Bytes, but Bytes return the same
	// thing for -x and x .
	bKey, _ := b.GobEncode()
	key := string(bKey)

	// if the coeff is already stored, fetch its ID from the cs.coeffsIDs map
	if idx, ok := cs.coeffsIDsLarge[key]; ok {
		return idx
	}

	// else add it in the cs.coeffs map and update the cs.coeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(cs.coeffs)
	cs.coeffs = append(cs.coeffs, bCopy)
	cs.coeffsIDsLarge[key] = resID
	return resID
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (cs *plonkConstraintSystem) newInternalVariable() compiled.Term {
	idx := cs.internal
	cs.internal++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Internal)
}

// newPublicVariable creates a new public Variable
func (cs *plonkConstraintSystem) newPublicVariable(name string) compiled.Term {
	idx := len(cs.public)
	cs.public = append(cs.public, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Public)
}

// newPublicVariable creates a new secret Variable
func (cs *plonkConstraintSystem) newSecretVariable(name string) compiled.Term {
	idx := len(cs.secret)
	cs.public = append(cs.secret, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Secret)
}

func (cs *plonkConstraintSystem) addDebugInfo(errName string, i ...interface{}) int {
	var l compiled.LogEntry

	const minLogSize = 500
	var sbb strings.Builder
	sbb.Grow(minLogSize)
	sbb.WriteString("[")
	sbb.WriteString(errName)
	sbb.WriteString("] ")

	for _, _i := range i {
		switch v := _i.(type) {
		case string:
			sbb.WriteString(v)
		case int:
			sbb.WriteString(strconv.Itoa(v))
		case compiled.Term:
			l.WriteTerm(v, &sbb)
		default:
			panic("unsupported log type")
		}
	}
	sbb.WriteByte('\n')
	debug.WriteStack(&sbb)
	l.Format = sbb.String()

	cs.debugInfo = append(cs.debugInfo, l)
	return len(cs.debugInfo) - 1
}
