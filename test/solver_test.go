package test

import (
	"fmt"
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

// ConsistentSolver solves given circuit with all possible witness combinations using internal/tinyfield
//
// Since the goal of this method is to flag potential solver issues, it is not exposed as an API for now
func (assert *Assert) ConsistentSolver(circuit frontend.Circuit, hintFunctions []hint.Function) {

	// compile R1CS
	ccs, err := frontend.Compile(tinyfield.Modulus(), r1cs.NewBuilder, circuit)
	assert.NoError(err)

	r1cs := ccs.(*cs.R1CS)

	// witness len
	n := r1cs.NbPublicVariables - 1 + r1cs.NbSecretVariables
	if n > 3 {
		// TODO @gbotrel do that more elengantly
		assert.t.Log("ignoring witness too large")
		return
	}

	witness := make([]tinyfield.Element, n)

	// compile SparseR1CS
	ccs, err = frontend.Compile(tinyfield.Modulus(), scs.NewBuilder, circuit)
	assert.NoError(err)

	scs := ccs.(*cs.SparseR1CS)
	if (scs.NbPublicVariables + scs.NbSecretVariables) != n {
		panic("mismatch of witness size for same circuit")
	}

	assert.permuteAndTest(circuit, hintFunctions, r1cs, witness, scs, 0)

}

func TestR1CSSolver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping R1CS solver test with testing.Short() flag set")
		return
	}

	// idea is test circuits, we are going to test all possible values of the witness.
	// (hence the choice of a small modulus for the field size)
	//
	// we generate witnesses and compare with the output of big.Int test engine against R1CS (tiny field) solver

	for name := range circuits.Circuits {
		t.Run(name, func(t *testing.T) {
			if name == "range_constant" {
				return
			}

			tc := circuits.Circuits[name]
			assert := NewAssert(t)
			assert.ConsistentSolver(tc.Circuit, tc.HintFunctions)

		})
	}
}

var digits []uint64

func init() {
	n := tinyfield.Modulus().Uint64()
	digits = make([]uint64, n)
	for i := uint64(0); i < n; i++ {
		digits[i] = i
	}
}

// note that circuit will be mutated and this is not thread safe
func (assert *Assert) permuteAndTest(circuit frontend.Circuit, hints []hint.Function,
	r1cs *cs.R1CS, witness []tinyfield.Element,
	scs *cs.SparseR1CS,
	index int) {

	for i := 0; i < len(digits); i++ {
		witness[index].SetUint64(digits[i])
		if index == len(witness)-1 {
			// we have a unique permutation

			// solve the cs using R1CS solver
			errR1CS := isSolvedR1CS(r1cs, witness, backend.WithHints(hints...))
			errSCS := isSolvedSCS(scs, witness, backend.WithHints(hints...))

			// solve the cs using test engine
			// first copy the witness in the circuit
			copyWitnessFromVector(circuit, witness)

			errEngine := isSolvedEngine(circuit, tinyfield.Modulus())

			if (errR1CS == nil) != (errEngine == nil) || (errSCS == nil) != (errEngine == nil) {
				strSCS := "<nil>"
				if errSCS != nil {
					strSCS = errSCS.Error()
				}
				strR1CS := "<nil>"
				if errR1CS != nil {
					strR1CS = errR1CS.Error()
				}
				strEngine := "<nil>"
				if errEngine != nil {
					strEngine = errEngine.Error()
				}
				assert.FailNowf("errSCS != errR1CS != errEngine", "errSCS :%s\nerrR1CS :%s\nerrEngine: %s\nwitness: %s",
					strSCS,
					strR1CS,
					strEngine,
					witnessToStr(witness))
			}
		} else {
			// recurse
			assert.permuteAndTest(circuit, hints, r1cs, witness, scs, index+1)
		}
	}
}

func witnessToStr(witness []tinyfield.Element) string {
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

func isSolvedSCS(scs *cs.SparseR1CS, witness []tinyfield.Element, opts ...backend.ProverOption) error {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return err
	}

	_, err = scs.Solve(witness, opt)
	return err
}

func isSolvedR1CS(cs *cs.R1CS, witness []tinyfield.Element, opts ...backend.ProverOption) error {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return err
	}

	a := make([]tinyfield.Element, len(cs.Constraints))
	b := make([]tinyfield.Element, len(cs.Constraints))
	c := make([]tinyfield.Element, len(cs.Constraints))
	_, err = cs.Solve(witness, a, b, c, opt)
	return err
}

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

func copyWitnessFromVector(to frontend.Circuit, from []tinyfield.Element) {
	i := 0
	schema.Parse(to, tVariable, func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		if visibility == schema.Public {
			tInput.Set(reflect.ValueOf((from[i])))
			i++
		}
		return nil
	})

	schema.Parse(to, tVariable, func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		if visibility == schema.Secret {
			tInput.Set(reflect.ValueOf((from[i])))
			i++
		}
		return nil
	})
}
