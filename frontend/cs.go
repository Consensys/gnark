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
	"math/big"

	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/backend/r1cs/r1c"
	"github.com/consensys/gurvy"
)

// CS represents a Groth16 like circuit
type CS struct {
	PublicInputsNames []string         // entry i: name of the public input whose ID is i
	SecretInputsName  []string         // entry i: name of the private input whose ID is i
	PublicInputs      []Variable       // entry i: public input whose ID is i
	SecretInputs      []Variable       // entry i: private input whose ID is i
	Variables         []Variable       // entry i: intermediate wire whose ID is i
	Coeffs            []big.Int        // list of coefficients
	Gates             []Gate           // list of groth16 gates (perhaps even PLONK gate if we interface it?)
	Constraints       []Gate           // list of constraints (it differs from gate because it does not yield any new value)
	wireTags          map[int][]string // optional tags -- debug info
}

// newCS outputs a new circuit
// TODO set bounds for slices capacity (as in the previous version)
func newCS() CS {

	var res CS

	res.PublicInputsNames = make([]string, 0, 10)
	res.PublicInputs = make([]Variable, 0, 10)

	res.SecretInputsName = make([]string, 0, 10)
	res.SecretInputs = make([]Variable, 0, 10)

	res.Variables = make([]Variable, 0, 50)

	res.Coeffs = make([]big.Int, 0, 30)

	res.Gates = make([]Gate, 0, 50)

	// first entry of circuit is ONE_WIRE
	res.PublicInputsNames = append(res.PublicInputsNames, "ONE_WIRE")
	res.PublicInputs = append(res.PublicInputs, Variable{false, Public, 0, nil})

	res.wireTags = make(map[int][]string)

	return res
}

// ToR1cs casting to R1CS
func (c *CS) toR1cs(id gurvy.ID) r1cs.R1CS {

	// wires = intermediateVariables | secret inputs | public inputs

	// id's of public (resp. secret) inputs are shifted to len(intermediateVariables) (resp. len(intermediateVariables)+len(secretInputs))
	offset := len(c.Variables)
	for i := 0; i < len(c.SecretInputs); i++ {
		c.SecretInputs[i].ID += offset
	}
	offset = len(c.Variables) + len(c.SecretInputs)
	for i := 0; i < len(c.PublicInputs); i++ {
		c.PublicInputs[i].ID += offset
	}

	// same job for the variables in the gates
	for i := 0; i < len(c.Gates); i++ {
		c.Gates[i].updateID(len(c.Variables), Secret)
		c.Gates[i].updateID(len(c.Variables)+len(c.SecretInputs), Public)
	}
	// same job for the variables in the constraints
	for i := 0; i < len(c.Constraints); i++ {
		c.Constraints[i].updateID(len(c.Variables), Secret)
		c.Constraints[i].updateID(len(c.Variables)+len(c.SecretInputs), Public)
	}

	// setting up the result
	var res r1cs.UntypedR1CS

	res.NbWires = len(c.Variables) + len(c.PublicInputs) + len(c.SecretInputs)
	res.NbPublicWires = len(c.PublicInputs)
	res.NbSecretWires = len(c.SecretInputs)
	res.SecretWires = make([]string, len(c.SecretInputs))
	copy(res.SecretWires, c.SecretInputsName)
	res.PublicWires = make([]string, len(c.PublicInputs))
	copy(res.PublicWires, c.PublicInputsNames)

	res.NbConstraints = len(c.Gates) + len(c.Constraints)
	res.NbCOConstraints = len(c.Gates)
	res.Coefficients = make([]big.Int, len(c.Coeffs))
	copy(res.Coefficients, c.Coeffs)
	res.Constraints = make([]r1c.R1C, len(c.Gates)+len(c.Constraints))

	// computational constraints (= gates)
	for i := 0; i < len(c.Gates); i++ {
		l := r1c.LinearExpression{}
		for _, e := range c.Gates[i].L {
			l = append(l, r1c.Pack(e.Variable.ID, e.Coeff, 3))
		}
		r := r1c.LinearExpression{}
		for _, e := range c.Gates[i].R {
			r = append(r, r1c.Pack(e.Variable.ID, e.Coeff, 3))
		}
		o := r1c.LinearExpression{}
		for _, e := range c.Gates[i].O {
			o = append(o, r1c.Pack(e.Variable.ID, e.Coeff, 3))
		}
		res.Constraints[i] = r1c.R1C{L: l, R: r, O: o, Solver: c.Gates[i].S}
	}

	// constraints (boolean, mustbeeq, etc)
	offset = len(c.Gates)
	for i := 0; i < len(c.Constraints); i++ {
		l := r1c.LinearExpression{}
		for _, e := range c.Constraints[i].L {
			l = append(l, r1c.Pack(e.Variable.ID, e.Coeff, 3))
		}
		r := r1c.LinearExpression{}
		for _, e := range c.Constraints[i].R {
			r = append(r, r1c.Pack(e.Variable.ID, e.Coeff, 3))
		}
		o := r1c.LinearExpression{}
		for _, e := range c.Constraints[i].O {
			o = append(o, r1c.Pack(e.Variable.ID, e.Coeff, 3))
		}
		res.Constraints[i+offset] = r1c.R1C{L: l, R: r, O: o, Solver: c.Constraints[i].S}
	}

	// wire tags
	res.WireTags = make(map[int][]string)
	for k, v := range c.wireTags {
		res.WireTags[k] = make([]string, len(v))
		copy(res.WireTags[k], v)
	}

	if id == gurvy.UNKNOWN {
		return &res
	}

	return res.ToR1CS(id)
}

// GetCoeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (c *CS) GetCoeffID(b *big.Int) int {
	var idx int
	idx = -1
	for i, v := range c.Coeffs {
		if v.Cmp(b) == 0 {
			idx = i
			return idx
		}
	}

	idx = len(c.Coeffs)
	var toAppend big.Int
	toAppend.Set(b)
	c.Coeffs = append(c.Coeffs, toAppend)

	return idx
}

// Tag assign a key to a Variable to be able to monitor it when the system is solved
func (c *CS) Tag(v Variable, tag string) {

	// TODO do we allOoutputw inputs to be tagged? anyway returns an error instead of panicing
	if v.Visibility != Internal {
		panic("inputs cannot be tagged")
	}

	for _, v := range c.wireTags {
		for _, t := range v {
			if tag == t {
				panic("duplicate tag " + tag)
			}
		}
	}
	c.wireTags[v.ID] = append(c.wireTags[v.ID], tag)
}

// creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's ID to the number of wires, and returns it
func (c *CS) newInternalVariable() Variable {

	var res Variable

	res.Visibility = Internal
	res.ID = len(c.Variables)
	c.Variables = append(c.Variables, res)

	return res
}

// getOneVariable returns the special "one_wire" of the circuit
func (c *CS) getOneVariable() Variable {
	return c.PublicInputs[0]
}
