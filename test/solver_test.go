package test

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/stretchr/testify/assert"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/tinyfield/cs"
	"github.com/consensys/gnark/internal/utils"
)

// ignore witness size larger than this bound
const permutterBound = 3

type myCircuit struct {
	One frontend.Variable
}

func (c *myCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.One, 1)
	commit, err := api.Compiler().Commit(c.One)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commit, 0)
	return nil
}

func TestWhichApi(t *testing.T) {
	circuit := myCircuit{}
	assignment := myCircuit{One: 1}

	_r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(t, err)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)

	pk, vk, err := groth16.Setup(_r1cs)
	assert.NoError(t, err)

	proof, err := groth16.Prove(_r1cs, pk, witness)
	assert.NoError(t, err)

	public, err := witness.Public()
	assert.NoError(t, err)
	assert.NoError(t, groth16.Verify(proof, vk, public))

}

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

type permutter struct {
	circuit frontend.Circuit
	r1cs    *cs.R1CS
	scs     *cs.SparseR1CS
	witness []tinyfield.Element
	hints   []hint.Function

	// used to avoid allocations in R1CS solver
	a, b, c []tinyfield.Element
}

// note that circuit will be mutated and this is not thread safe
func (p *permutter) permuteAndTest(index int) error {

	for i := 0; i < len(tinyfieldElements); i++ {
		p.witness[index].SetUint64(tinyfieldElements[i])
		if index == len(p.witness)-1 {
			// we have a unique permutation

			// solve the cs using R1CS solver
			errR1CS := p.solveR1CS()
			errSCS := p.solveSCS()

			// solve the cs using test engine
			// first copy the witness in the circuit
			copyWitnessFromVector(p.circuit, p.witness)
			errEngine1 := isSolvedEngine(p.circuit, tinyfield.Modulus())

			copyWitnessFromVector(p.circuit, p.witness)
			errEngine2 := isSolvedEngine(p.circuit, tinyfield.Modulus(), SetAllVariablesAsConstants())

			if (errR1CS == nil) != (errEngine1 == nil) ||
				(errSCS == nil) != (errEngine1 == nil) ||
				(errEngine1 == nil) != (errEngine2 == nil) {
				return fmt.Errorf("errSCS :%s\nerrR1CS :%s\nerrEngine(const=false): %s\nerrEngine(const=true): %s\nwitness: %s",
					formatError(errSCS),
					formatError(errR1CS),
					formatError(errEngine1),
					formatError(errEngine2),
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

func (p *permutter) solveSCS() error {
	opt, err := backend.NewProverConfig(backend.WithHints(p.hints...))
	if err != nil {
		return err
	}

	_, err = p.scs.Solve(p.witness, opt)
	return err
}

func (p *permutter) solveR1CS() error {
	opt, err := backend.NewProverConfig(backend.WithHints(p.hints...))
	if err != nil {
		return err
	}

	for i := 0; i < len(p.r1cs.Constraints); i++ {
		p.a[i].SetZero()
		p.b[i].SetZero()
		p.c[i].SetZero()
	}
	_, err = p.r1cs.Solve(p.witness, p.a, p.b, p.c, opt)
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
	schema.Parse(to, tVariable, func(f *schema.Field, tInput reflect.Value) error {
		if f.Visibility == schema.Public {
			tInput.Set(reflect.ValueOf((from[i])))
			i++
		}
		return nil
	})

	schema.Parse(to, tVariable, func(f *schema.Field, tInput reflect.Value) error {
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

	p.r1cs = ccs.(*cs.R1CS)

	// witness len
	n := p.r1cs.NbPublicVariables - 1 + p.r1cs.NbSecretVariables
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

	p.scs = ccs.(*cs.SparseR1CS)
	if (p.scs.NbPublicVariables + p.scs.NbSecretVariables) != n {
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
