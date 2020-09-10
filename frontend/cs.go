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
	publicInputsNames []string         // entry i: name of the public input whose ID is i
	secretInputsName  []string         // entry i: name of the private input whose ID is i
	PublicInputs      []Variable       // entry i: public input whose ID is i
	secretInputs      []Variable       // entry i: private input whose ID is i
	variables         []Variable       // entry i: intermediate wire whose ID is i
	coeffs            []big.Int        // list of coefficients
	gates             []gate           // list of groth16 gates (perhaps even PLONK gate if we interface it?)
	constraints       []gate           // list of constraints (it differs from gate because it does not yield any new value)
	wireTags          map[int][]string // optional tags -- debug info
}

const initialCapacity = 1e6 // TODO that must be tuned. -build tags?

// newCS outputs a new circuit
func newCS() CS {

	var res CS

	res.publicInputsNames = make([]string, 0)
	res.PublicInputs = make([]Variable, 0)

	res.secretInputsName = make([]string, 0)
	res.secretInputs = make([]Variable, 0)

	res.variables = make([]Variable, 0, initialCapacity)

	res.coeffs = make([]big.Int, 0) // the coeffs are indexed, most of them are 0,+-1,+-2,+-3, no need for enormous capacity

	res.gates = make([]gate, 0, initialCapacity)
	res.constraints = make([]gate, 0, initialCapacity)

	// first entry of circuit is ONE_WIRE
	res.publicInputsNames = append(res.publicInputsNames, "ONE_WIRE")
	res.PublicInputs = append(res.PublicInputs, Variable{false, Public, 0, nil})

	res.wireTags = make(map[int][]string)

	return res
}

// ToR1cs casting to R1CS
func (c *CS) toR1cs(id gurvy.ID) r1cs.R1CS {

	// wires = intermediatevariables | secret inputs | public inputs

	// id's of internal variables are shifted to -1 (because we start from 1 to len(c.variables)+1)
	offset := -1
	for i := 0; i < len(c.variables); i++ {
		c.variables[i].id += offset
	}

	// id's of public (resp. secret) inputs are shifted to len(intermediatevariables) (resp. len(intermediatevariables)+len(secretInputs))
	offset = len(c.variables)
	for i := 0; i < len(c.secretInputs); i++ {
		c.secretInputs[i].id += offset
	}
	offset = len(c.variables) + len(c.secretInputs)
	for i := 0; i < len(c.PublicInputs); i++ {
		c.PublicInputs[i].id += offset
	}

	// same job for the variables in the gates
	for i := 0; i < len(c.gates); i++ {
		c.gates[i].updateID(-1, Internal)
		c.gates[i].updateID(len(c.variables), Secret)
		c.gates[i].updateID(len(c.variables)+len(c.secretInputs), Public)
	}
	// same job for the variables in the constraints
	for i := 0; i < len(c.constraints); i++ {
		c.constraints[i].updateID(-1, Internal)
		c.constraints[i].updateID(len(c.variables), Secret)
		c.constraints[i].updateID(len(c.variables)+len(c.secretInputs), Public)
	}

	// setting up the result
	var res r1cs.UntypedR1CS

	res.NbWires = len(c.variables) + len(c.PublicInputs) + len(c.secretInputs)
	res.NbPublicWires = len(c.PublicInputs)
	res.NbSecretWires = len(c.secretInputs)
	res.SecretWires = make([]string, len(c.secretInputs))
	copy(res.SecretWires, c.secretInputsName)
	res.PublicWires = make([]string, len(c.PublicInputs))
	copy(res.PublicWires, c.publicInputsNames)

	res.NbConstraints = len(c.gates) + len(c.constraints)
	res.NbCOConstraints = len(c.gates)
	res.Coefficients = make([]big.Int, len(c.coeffs))
	copy(res.Coefficients, c.coeffs)
	res.Constraints = make([]r1c.R1C, len(c.gates)+len(c.constraints))

	// computational constraints (= gates)
	for i := 0; i < len(c.gates); i++ {
		l := r1c.LinearExpression{}
		for _, e := range c.gates[i].L {
			l = append(l, r1c.Pack(e.Variable.id, e.Coeff, 3))
		}
		r := r1c.LinearExpression{}
		for _, e := range c.gates[i].R {
			r = append(r, r1c.Pack(e.Variable.id, e.Coeff, 3))
		}
		o := r1c.LinearExpression{}
		for _, e := range c.gates[i].O {
			o = append(o, r1c.Pack(e.Variable.id, e.Coeff, 3))
		}
		res.Constraints[i] = r1c.R1C{L: l, R: r, O: o, Solver: c.gates[i].S}
	}

	// constraints (boolean, mustbeeq, etc)
	offset = len(c.gates)
	for i := 0; i < len(c.constraints); i++ {
		l := r1c.LinearExpression{}
		for _, e := range c.constraints[i].L {
			l = append(l, r1c.Pack(e.Variable.id, e.Coeff, 3))
		}
		r := r1c.LinearExpression{}
		for _, e := range c.constraints[i].R {
			r = append(r, r1c.Pack(e.Variable.id, e.Coeff, 3))
		}
		o := r1c.LinearExpression{}
		for _, e := range c.constraints[i].O {
			o = append(o, r1c.Pack(e.Variable.id, e.Coeff, 3))
		}
		res.Constraints[i+offset] = r1c.R1C{L: l, R: r, O: o, Solver: c.constraints[i].S}
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
	for i, v := range c.coeffs {
		if v.Cmp(b) == 0 {
			idx = i
			return idx
		}
	}

	idx = len(c.coeffs)
	var toAppend big.Int
	toAppend.Set(b)
	c.coeffs = append(c.coeffs, toAppend)

	return idx
}

// Tag assign a key to a variable to be able to monitor it when the system is solved
func (c *CS) Tag(v Variable, tag string) {

	c.checkIsAllocated(v)

	// TODO do we allOoutputw inputs to be tagged? anyway returns an error instead of panicing
	if v.visibility != Internal {
		panic("inputs cannot be tagged")
	}

	for _, v := range c.wireTags {
		for _, t := range v {
			if tag == t {
				panic("duplicate tag " + tag)
			}
		}
	}
	c.wireTags[v.id-1] = append(c.wireTags[v.id], tag)
}

// NewInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (c *CS) NewInternalVariable() Variable {

	var res Variable

	res.visibility = Internal

	// the id 0 is reserved to check if a variable is not allocated (in case
	// one write "var a frontend.Variable" without adding "cs.Allocate(a)" after.
	res.id = len(c.variables) + 1

	c.variables = append(c.variables, res)

	return res
}

// getOneVariable returns the special "one_wire" of the circuit
func (c *CS) getOneVariable() Variable {
	return c.PublicInputs[0]
}

// checks if the variable is recorded in the circuit
func (c *CS) checkIsAllocated(v Variable) {
	if v.id == 0 && v.visibility == Internal {
		panic("variable non allocated")
	}
}
