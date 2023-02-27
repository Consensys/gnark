package test

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/tinyfield"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/utils"
)

// ignore witness size larger than this bound
const permutterBound = 3

// r1cs + sparser1cs
const nbSystems = 2

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

	for name := range circuits.Circuits {
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
// using mock methods (only the undererlying vector is required).
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
	r1cs              *cs.R1CS
	scs               *cs.SparseR1CS
	constraintSystems [2]constraint.ConstraintSystem
	witness           []tinyfield.Element
	hints             []hint.Function

	// used to avoid allocations in R1CS solver
	a, b, c []tinyfield.Element
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

			// solve the cs using R1CS solver
			// errR1CS := p.solveR1CS()
			// errSCS := p.solveSCS()

			// // solve the cs using test engine
			// // first copy the witness in the circuit
			// copyWitnessFromVector(p.circuit, p.witness)
			// errEngine1 := isSolvedEngine(p.circuit, tinyfield.Modulus())

			// copyWitnessFromVector(p.circuit, p.witness)
			// errEngine2 := isSolvedEngine(p.circuit, tinyfield.Modulus(), SetAllVariablesAsConstants())

			// if (errR1CS == nil) != (errEngine1 == nil) ||
			// 	(errSCS == nil) != (errEngine1 == nil) ||
			// 	(errEngine1 == nil) != (errEngine2 == nil) {
			// 	return fmt.Errorf("errSCS :%s\nerrR1CS :%s\nerrEngine(const=false): %s\nerrEngine(const=true): %s\nwitness: %s",
			// 		formatError(errSCS),
			// 		formatError(errR1CS),
			// 		formatError(errEngine1),
			// 		formatError(errEngine2),
			// 		formatWitness(p.witness))
			// }
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

func (p *permutter) solveSCS() error {
	pw := newPermutterWitness(p.witness)
	_, err := p.scs.Solve(pw, backend.WithHints(p.hints...))
	return err
}

func (p *permutter) solveR1CS() error {
	pw := newPermutterWitness(p.witness)
	_, err := p.r1cs.Solve(pw, backend.WithHints(p.hints...))
	return err
}

func (p *permutter) solve(i int) error {
	pw := newPermutterWitness(p.witness)
	_, err := p.constraintSystems[i].Solve(pw, backend.WithHints(p.hints...))
	return err
}

// isSolvedEngine behaves like test.IsSolved except it doesn't clone the circuit
func isSolvedEngine(c frontend.Circuit, field *big.Int, opts ...TestEngineOption) (err error) {
	e := &engine{
		curveID:    utils.FieldToCurve(field),
		q:          new(big.Int).Set(field),
		apiWrapper: func(a frontend.API) frontend.API { return a },
		constVars:  false,
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

	api := e.apiWrapper(e)
	err = c.Define(api)

	return
}

// fill the "to" frontend.Circuit with values from the provided vector
// values are assumed to be ordered [public | secret]
func copyWitnessFromVector(to frontend.Circuit, from []tinyfield.Element) {
	i := 0
	schema.Walk(to, tVariable, func(f schema.LeafInfo, tInput reflect.Value) error {
		if f.Visibility == schema.Public {
			tInput.Set(reflect.ValueOf((from[i])))
			i++
		}
		return nil
	})

	schema.Walk(to, tVariable, func(f schema.LeafInfo, tInput reflect.Value) error {
		if f.Visibility == schema.Secret {
			tInput.Set(reflect.ValueOf((from[i])))
			i++
		}
		return nil
	})
}

// ConsistentSolver solves given circuit with all possible witness combinations using internal/tinyfield
//
// Since the goal of this method is to flag potential solver issues, it is not exposed as an API for now
func consistentSolver(circuit frontend.Circuit, hintFunctions []hint.Function) error {

	p := permutter{
		circuit: circuit,
		hints:   hintFunctions,
	}

	// compile R1CS
	ccs, err := frontend.Compile(tinyfield.Modulus(), r1cs.NewBuilder, circuit)
	if err != nil {
		return err
	}
	p.constraintSystems[0] = ccs

	p.r1cs = ccs.(*cs.R1CS)

	// witness len
	n := len(p.r1cs.Public) - 1 + len(p.r1cs.Secret)
	if n > permutterBound {
		return nil
	}

	p.a = make([]tinyfield.Element, p.r1cs.GetNbConstraints())
	p.b = make([]tinyfield.Element, p.r1cs.GetNbConstraints())
	p.c = make([]tinyfield.Element, p.r1cs.GetNbConstraints())
	p.witness = make([]tinyfield.Element, n)

	// compile SparseR1CS
	ccs, err = frontend.Compile(tinyfield.Modulus(), scs.NewBuilder, circuit)
	if err != nil {
		return err
	}
	p.constraintSystems[1] = ccs

	p.scs = ccs.(*cs.SparseR1CS)
	if (len(p.scs.Public) + len(p.scs.Secret)) != n {
		return errors.New("mismatch of witness size for same circuit")
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
}
