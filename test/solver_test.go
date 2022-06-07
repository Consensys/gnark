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
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/internal/tinyfield"
	"github.com/consensys/gnark/internal/tinyfield/cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestR1CSSolver(t *testing.T) {

	// idea is test circuits, we are going to test all possible values of the witness.
	// (hence the choice of a small modulus for the field size)
	//
	// we generate witnesses and compare with the output of big.Int test engine against R1CS (tiny field) solver

	for name := range circuits.Circuits {
		t.Run(name, func(t *testing.T) {
			if name == "range_constant" {
				return
			}

			assert := require.New(t)

			tc := circuits.Circuits[name]

			c := shallowClone(tc.Circuit)
			// t.Parallel()

			ccs, err := frontend.Compile(tinyfield.Modulus(), r1cs.NewBuilder, tc.Circuit)
			assert.NoError(err)

			cs := ccs.(*cs.R1CS)

			// witness len
			n := cs.NbPublicVariables - 1 + cs.NbSecretVariables
			if n > 3 {
				t.Log("ignoring", name)
				return // ignore
			}

			t.Logf("len(witness) == %d", n)
			witness := make([]tinyfield.Element, n)

			permuteAndTest(assert, c, tc.HintFunctions, cs, witness, 0)
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
func permuteAndTest(assert *require.Assertions, circuit frontend.Circuit, hints []hint.Function, cs *cs.R1CS, _w []tinyfield.Element, index int) {

	for i := 0; i < len(digits); i++ {
		_w[index].SetUint64(digits[i])
		if index == len(_w)-1 {
			// we have a unique permutation

			// solve the cs using R1CS solver
			errSolver := isSolved(cs, _w, backend.WithHints(hints...))

			// solve the cs using test engine
			// first copy the witness in the circuit
			copyWitnessFromVector(circuit, _w)

			errEngine := isSolvedEngine(circuit, tinyfield.Modulus())

			if (errSolver == nil) != (errEngine == nil) {
				strSolver := "<nil>"
				if errSolver != nil {
					strSolver = errSolver.Error()
				}
				strEngine := "<nil>"
				if errEngine != nil {
					strEngine = errEngine.Error()
				}
				assert.FailNowf("errSolver != errEngine", "errSolver :%s\nerrEngine: %s\nwitness: %s",
					strSolver,
					strEngine,
					witnessToStr(_w))
			}
		} else {
			// recurse
			permuteAndTest(assert, circuit, hints, cs, _w, index+1)
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

func isSolved(cs *cs.R1CS, witness []tinyfield.Element, opts ...backend.ProverOption) error {
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
