package test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	cs "github.com/consensys/gnark/constraint/tinyfield"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"io"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/utils"
)

// ignore witness size larger than this bound
const permutterBound = 3

// r1cs + sparser1cs
const nbSystems = 2

var builders [2]frontend.NewBuilder

func TestSolverConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping R1CS solver test with testing.Short() flag set")
		return
	}

	// idea is test circuits, we are going to test all possible values of the witness.
	// (hence the choice of a small modulus for the field size)
	//
	// we generate witnesses and compare with the output of big.Int test engine against
	// R1CS and SparseR1CS solvers

	names := map[string]interface{}{"and": nil, "or": nil}

	for name := range names /*circuits.Circuits*/ {
		t.Run(name, func(t *testing.T) {
			tc := circuits.Circuits[name]
			t.Parallel()
			err := consistentSolver(tc.Circuit, tc.HintFunctions)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// witness used for the permutter. It implements the Witness interface
// using mock methods (only the underlying vector is required).
type permutterWitness struct {
	vector any
}

func (pw *permutterWitness) WriteTo(w io.Writer) (int64, error) {
	return 0, nil
}

func (pw *permutterWitness) ReadFrom(r io.Reader) (int64, error) {
	return 0, nil
}

func (pw *permutterWitness) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (pw *permutterWitness) UnmarshalBinary([]byte) error {
	return nil
}

func (pw *permutterWitness) Public() (witness.Witness, error) {
	return pw, nil
}

func (pw *permutterWitness) Vector() any {
	return pw.vector
}

func (pw *permutterWitness) ToJSON(s *schema.Schema) ([]byte, error) {
	return nil, nil
}

func (pw *permutterWitness) FromJSON(s *schema.Schema, data []byte) error {
	return nil
}

func (pw *permutterWitness) Fill(nbPublic, nbSecret int, values <-chan any) error {
	return nil
}

func newPermutterWitness(pv tinyfield.Vector) witness.Witness {
	return &permutterWitness{
		vector: pv,
	}
}

type permutter struct {
	circuit           frontend.Circuit
	constraintSystems [2]constraint.ConstraintSystem
	witness           []tinyfield.Element
	hints             []solver.Hint
}

// note that circuit will be mutated and this is not thread safe
func (p *permutter) permuteAndTest(index int) error {

	for i := 0; i < len(tinyfieldElements); i++ {
		p.witness[index].SetUint64(tinyfieldElements[i])
		if index == len(p.witness)-1 {

			// we have a unique permutation
			var errorSystems [2]error
			var errorEngines [2]error

			// 2 constraints systems
			for k := 0; k < nbSystems; k++ {

				errorSystems[k] = p.solve(k)

				// solve the cs using test engine
				// first copy the witness in the circuit
				copyWitnessFromVector(p.circuit, p.witness)
				errorEngines[0] = isSolvedEngine(p.circuit, tinyfield.Modulus())

				copyWitnessFromVector(p.circuit, p.witness)
				errorEngines[1] = isSolvedEngine(p.circuit, tinyfield.Modulus(), SetAllVariablesAsConstants())

			}
			if (errorSystems[0] == nil) != (errorEngines[0] == nil) ||
				(errorSystems[1] == nil) != (errorEngines[0] == nil) ||
				(errorEngines[0] == nil) != (errorEngines[1] == nil) {
				return fmt.Errorf("errSCS :%s\nerrR1CS :%s\nerrEngine(const=false): %s\nerrEngine(const=true): %s\nwitness: %s",
					formatError(errorSystems[0]),
					formatError(errorSystems[1]),
					formatError(errorEngines[0]),
					formatError(errorEngines[1]),
					formatWitness(p.witness))
			}

		} else {
			// recurse
			if err := p.permuteAndTest(index + 1); err != nil {
				return err
			}
		}
	}
	return nil
}

func formatError(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func formatWitness(witness []tinyfield.Element) string {
	var sbb strings.Builder
	sbb.WriteByte('[')

	for i := 0; i < len(witness); i++ {
		sbb.WriteString(strconv.Itoa(int(witness[i].Uint64())))
		if i != len(witness)-1 {
			sbb.WriteString(", ")
		}
	}

	sbb.WriteByte(']')

	return sbb.String()
}

func (p *permutter) solve(i int) error {
	pw := newPermutterWitness(p.witness)
	_, err := p.constraintSystems[i].Solve(pw, solver.WithHints(p.hints...))
	return err
}

// isSolvedEngine behaves like test.IsSolved except it doesn't clone the circuit
func isSolvedEngine(c frontend.Circuit, field *big.Int, opts ...TestEngineOption) (err error) {
	e := &engine{
		curveID:   utils.FieldToCurve(field),
		q:         new(big.Int).Set(field),
		constVars: false,
		Store:     kvstore.New(),
	}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return fmt.Errorf("apply option: %w", err)
		}
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, string(debug.Stack()))
		}
	}()

	if err = c.Define(e); err != nil {
		return fmt.Errorf("define: %w", err)
	}
	if err = callDeferred(e); err != nil {
		return fmt.Errorf("")
	}

	return
}

// fill the "to" frontend.Circuit with values from the provided vector
// values are assumed to be ordered [public | secret]
func copyWitnessFromVector(to frontend.Circuit, from []tinyfield.Element) {
	i := 0
	schema.Walk(to, tVariable, func(f schema.LeafInfo, tInput reflect.Value) error {
		if f.Visibility == schema.Public {
			tInput.Set(reflect.ValueOf(from[i]))
			i++
		}
		return nil
	})

	schema.Walk(to, tVariable, func(f schema.LeafInfo, tInput reflect.Value) error {
		if f.Visibility == schema.Secret {
			tInput.Set(reflect.ValueOf(from[i]))
			i++
		}
		return nil
	})
}

func getCircuitName(circuit frontend.Circuit) string {
	for name, c := range circuits.Circuits {
		if c.Circuit == circuit {
			return name
		}
	}
	panic("not found")
}

// ConsistentSolver solves given circuit with all possible witness combinations using internal/tinyfield
//
// Since the goal of this method is to flag potential solver issues, it is not exposed as an API for now
func consistentSolver(circuit frontend.Circuit, hintFunctions []solver.Hint) error {

	p := permutter{
		circuit: circuit,
		hints:   hintFunctions,
	}

	// compile the systems
	for i := 0; i < nbSystems; i++ {

		ccs, err := frontend.Compile(tinyfield.Modulus(), builders[i], circuit)
		if err != nil {
			return err
		}

		diff := diffCs(ccs, i, circuit)

		if diff != "" {
			return errors.New(diff)
		}

		p.constraintSystems[i] = ccs

		if i == 0 { // the -1 is only for r1cs...
			n := ccs.GetNbPublicVariables() - 1 + ccs.GetNbSecretVariables()
			if n > permutterBound {
				return nil
			}
			p.witness = make([]tinyfield.Element, n)
		}

	}

	return p.permuteAndTest(0)
}

// [0, 1, ..., q - 1], with q == tinyfield.Modulus()
var tinyfieldElements []uint64

func init() {
	n := tinyfield.Modulus().Uint64()
	tinyfieldElements = make([]uint64, n)
	for i := uint64(0); i < n; i++ {
		tinyfieldElements[i] = i
	}

	builders[0] = r1cs.NewBuilder
	builders[1] = scs.NewBuilder
}

const andR1cs = "b2644c6f6773f6645479706501664c6576656c7382830001028103664d4465627567a0665075626c69638161316653656372657483634f7031634f7032635265736843616c6c44617461982c0c01020101010100030100000c01020101020100030200000a0101010101010201040a010101010001040103694465627567496e666ff66a426c75657072696e747382da00510527a0da00510528a06b5363616c61724669656c646232666b53796d626f6c5461626c65a26946756e6374696f6e73f6694c6f636174696f6e73f66c436f656666696369656e74738581008118198103811681182c6c476e61726b56657273696f6e6b302e382e312d616c7068616c496e737472756374696f6e7384a36b426c75657072696e744944016d537461727443616c6c446174610070436f6e73747261696e744f666673657400a36b426c75657072696e744944016d537461727443616c6c446174610c70436f6e73747261696e744f666673657401a36b426c75657072696e744944016d537461727443616c6c44617461181870436f6e73747261696e744f666673657402a36b426c75657072696e744944016d537461727443616c6c44617461182270436f6e73747261696e744f6666736574036d4e62436f6e73747261696e7473046e436f6d6d69746d656e74496e666ff6724d48696e7473446570656e64656e63696573a0734e62496e7465726e616c5661726961626c657301"
const andScs = "b2644c6f6773f6645479706502664c6576656c7382830001028103664d4465627567a0665075626c6963f66653656372657483634f7031634f7032635265736843616c6c446174619300010301010300010301030200010300000000694465627567496e666ff66a426c75657072696e747385da00510527a0da00510529a0da0051052ba0da0051052aa0da0051052ca06b5363616c61724669656c646232666b53796d626f6c5461626c65a26946756e6374696f6e73f6694c6f636174696f6e73f66c436f656666696369656e74738581008118198103811681182c6c476e61726b56657273696f6e6b302e382e312d616c7068616c496e737472756374696f6e7384a36b426c75657072696e744944046d537461727443616c6c446174610070436f6e73747261696e744f666673657400a36b426c75657072696e744944046d537461727443616c6c446174610370436f6e73747261696e744f666673657401a36b426c75657072696e744944026d537461727443616c6c446174610670436f6e73747261696e744f666673657402a36b426c75657072696e744944016d537461727443616c6c446174610a70436f6e73747261696e744f6666736574036d4e62436f6e73747261696e7473046e436f6d6d69746d656e74496e666ff6724d48696e7473446570656e64656e63696573a0734e62496e7465726e616c5661726961626c657301"
const orR1cs = "b2644c6f6773f6645479706501664c6576656c7382830001028103664d4465627567a0665075626c69638161316653656372657483634f7031634f7032635265736843616c6c4461746198300c01020101010100030100000c01020101020100030200000e010103010101020304010101020a010101010001040103694465627567496e666ff66a426c75657072696e747382da00510527a0da00510528a06b5363616c61724669656c646232666b53796d626f6c5461626c65a26946756e6374696f6e73f6694c6f636174696f6e73f66c436f656666696369656e74738581008118198103811681182c6c476e61726b56657273696f6e6b302e382e312d616c7068616c496e737472756374696f6e7384a36b426c75657072696e744944016d537461727443616c6c446174610070436f6e73747261696e744f666673657400a36b426c75657072696e744944016d537461727443616c6c446174610c70436f6e73747261696e744f666673657401a36b426c75657072696e744944016d537461727443616c6c44617461181870436f6e73747261696e744f666673657402a36b426c75657072696e744944016d537461727443616c6c44617461182670436f6e73747261696e744f6666736574036d4e62436f6e73747261696e7473046e436f6d6d69746d656e74496e666ff6724d48696e7473446570656e64656e63696573a0734e62496e7465726e616c5661726961626c657301"
const orScs = "b2644c6f6773f6645479706502664c6576656c7382830001028103664d4465627567a0665075626c6963f66653656372657483634f7031634f7032635265736843616c6c446174619818000103010103000103030301010000030200010300000000694465627567496e666ff66a426c75657072696e747385da00510527a0da00510529a0da0051052ba0da0051052aa0da0051052ca06b5363616c61724669656c646232666b53796d626f6c5461626c65a26946756e6374696f6e73f6694c6f636174696f6e73f66c436f656666696369656e74738581008118198103811681182c6c476e61726b56657273696f6e6b302e382e312d616c7068616c496e737472756374696f6e7384a36b426c75657072696e744944046d537461727443616c6c446174610070436f6e73747261696e744f666673657400a36b426c75657072696e744944046d537461727443616c6c446174610370436f6e73747261696e744f666673657401a36b426c75657072696e744944016d537461727443616c6c446174610670436f6e73747261696e744f666673657402a36b426c75657072696e744944016d537461727443616c6c446174610f70436f6e73747261696e744f6666736574036d4e62436f6e73747261696e7473046e436f6d6d69746d656e74496e666ff6724d48696e7473446570656e64656e63696573a0734e62496e7465726e616c5661726961626c657301"

func getCs(csIndex int, circuit frontend.Circuit) string {
	switch csIndex {
	case 0:
		if circuit == circuits.Circuits["and"].Circuit {
			return andR1cs
		}
		if circuit == circuits.Circuits["or"].Circuit {
			return orR1cs
		}
	case 1:
		if circuit == circuits.Circuits["and"].Circuit {
			return andScs
		}
		if circuit == circuits.Circuits["or"].Circuit {
			return orScs
		}
	}
	return "unrecognized circuit/cs"
}

func diffCs(__cs constraint.ConstraintSystem, csIndex int, circuit frontend.Circuit) string {

	_cs := __cs.(*cs.System)

	csHex := getCs(csIndex, circuit)
	if csHex == "unrecognized circuit/cs" {
		return csHex
	}
	var expectedCs cs.System

	b, err := hex.DecodeString(csHex)
	if err != nil {
		return err.Error()
	}
	_, err = expectedCs.ReadFrom(bytes.NewReader(b))
	if err != nil {
		return err.Error()
	}

	return cmp.Diff(_cs, &expectedCs, cmpopts.IgnoreFields(cs.System{}, diffIgnore...))
}

var diffIgnore = []string{
	"System.SymbolTable.mFunctions",
	"System.SymbolTable.mLocations",
	"System.q",
	"System.bitLen",
	"System.lbWireLevel",
	"System.lbOutputs",
	"System.genericHint",
	"CoeffTable.mCoeffs",
	"field",
}
