package gkrtesting

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	gkrbls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	gkrbls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	gkrbn254 "github.com/consensys/gnark/internal/gkr/bn254"
	gkrbw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

func must(g *gkrtypes.GateBytecode, err error) *gkrtypes.GateBytecode {
	if err != nil {
		panic(err)
	}
	return g
}

// Exported compiled gates for tests that need SerializableGate (bytecode gates)
var (
	IdentityGate *gkrtypes.SerializableGate
	Add2Gate     *gkrtypes.SerializableGate
	Mul2Gate     *gkrtypes.SerializableGate
)

func init() {
	IdentityGate = &gkrtypes.SerializableGate{
		Evaluate:    must(gkrtypes.CompileGateFunction(gkrtypes.Identity, 1)),
		NbIn:        1,
		Degree:      1,
		SolvableVar: 0,
	}
	Add2Gate = &gkrtypes.SerializableGate{
		Evaluate:    must(gkrtypes.CompileGateFunction(gkrtypes.Add2, 2)),
		NbIn:        2,
		Degree:      1,
		SolvableVar: 0,
	}
	Mul2Gate = &gkrtypes.SerializableGate{
		Evaluate:    must(gkrtypes.CompileGateFunction(gkrtypes.Mul2, 2)),
		NbIn:        2,
		Degree:      2,
		SolvableVar: -1,
	}
}

// Cache for circuits and gates.
// The main functionality is to cache whole circuits, but this package needs to use its own gate registry, in order to avoid import cycles.
// Cache is used in tests for the per-curve GKR packages, but they in turn provide gate degree discovery functions to the gkrgates package.
type Cache struct {
	circuits map[string]gkrtypes.GadgetCircuit
	gates    map[string]gkr.GateFunction
}

func mimcGate(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
	sum := api.Add(input[0], input[1]) //.Add(&sum, &m.ark)  TODO: add ark
	res := api.Mul(sum, sum)           // sum^2
	res = api.Mul(res, sum)            // sum^3
	res = api.Mul(res, res)            // sum^6
	res = api.Mul(res, sum)            // sum^7

	return res
}

func selectInput3Gate(_ gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return in[2]
}

func NewCache() *Cache {
	gates := make(map[string]gkr.GateFunction, 7)
	gates[""] = gkrtypes.Identity
	gates["identity"] = gkrtypes.Identity
	gates["add2"] = gkrtypes.Add2
	gates["sub2"] = gkrtypes.Sub2
	gates["neg"] = gkrtypes.Neg
	gates["mul2"] = gkrtypes.Mul2
	gates["mimc"] = mimcGate
	gates["select-input-3"] = selectInput3Gate

	return &Cache{
		circuits: make(map[string]gkrtypes.GadgetCircuit),
		gates:    gates,
	}
}

// JSONWire is the JSON serialization format for circuit wires (gate name + inputs)
type JSONWire struct {
	Gate   string `json:"gate"`   // gate name, empty for input wires
	Inputs []int  `json:"inputs"` // indices of input wires
}

// JSONCircuit is the JSON serialization format for circuits
type JSONCircuit []JSONWire

func (c *Cache) GetCircuit(path string) gkrtypes.GadgetCircuit {
	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	if circuit, ok := c.circuits[path]; ok {
		return circuit
	}

	var bytes []byte
	if bytes, err = os.ReadFile(path); err != nil {
		panic(err)
	}

	// Unmarshal from JSON format (gate names as strings)
	var jsonCircuit JSONCircuit
	if err = json.Unmarshal(bytes, &jsonCircuit); err != nil {
		panic(err)
	}

	// Convert JSON format to GadgetCircuit
	circuit := make(gkrtypes.GadgetCircuit, len(jsonCircuit))
	for i, wJSON := range jsonCircuit {
		gate := c.GetGate(wJSON.Gate)

		circuit[i] = gkrtypes.GadgetWire{
			Gate:   &gkrtypes.Gate[gkr.GateFunction]{Evaluate: gate},
			Inputs: wJSON.Inputs,
		}
	}

	c.circuits[path] = circuit

	return circuit
}

func (c *Cache) RegisterGate(name string, gate gkr.GateFunction) {
	if _, ok := c.gates[name]; ok {
		panic("gate already registered")
	}
	c.gates[name] = gate
}

func (c *Cache) GetGate(name string) gkr.GateFunction {
	if gate, ok := c.gates[name]; ok {
		return gate
	}
	panic("gate not found: " + name)
}

func MiMCCircuit(numRounds int) gkrtypes.GadgetCircuit {
	c := make(gkrtypes.GadgetCircuit, numRounds+2)
	idGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	mimc := &gkrtypes.GadgetGate{Evaluate: mimcGate}

	c[0] = gkrtypes.GadgetWire{Gate: idGate}
	c[1] = gkrtypes.GadgetWire{Gate: idGate}

	for i := 2; i < len(c); i++ {
		c[i] = gkrtypes.GadgetWire{Gate: mimc, Inputs: []int{i - 1, 0}}
	}
	return c
}

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof  interface{}     `json:"finalEvalProof"`
	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
}

type HashDescription map[string]interface{}
type TestCaseInfo struct {
	Hash    HashDescription `json:"hash"`
	Circuit string          `json:"circuit"`
	Input   [][]interface{} `json:"input"`
	Output  [][]interface{} `json:"output"`
	Proof   PrintableProof  `json:"proof"`
}

func (c *Cache) ReadTestCaseInfo(filePath string) (info TestCaseInfo, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()
	err = json.NewDecoder(f).Decode(&info)
	return
}

func NoGateCircuit() gkrtypes.GadgetCircuit {
	return gkrtypes.GadgetCircuit{
		{
			Gate: &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity},
		},
	}
}

func SingleAddGateCircuit() gkrtypes.GadgetCircuit {
	idGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	return gkrtypes.GadgetCircuit{
		{Gate: idGate},
		{Gate: idGate},
		{Gate: &gkrtypes.GadgetGate{Evaluate: gkrtypes.Add2}, Inputs: []int{0, 1}},
	}
}

func SingleMulGateCircuit() gkrtypes.GadgetCircuit {
	idGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	return gkrtypes.GadgetCircuit{
		{Gate: idGate},
		{Gate: idGate},
		{Gate: &gkrtypes.GadgetGate{Evaluate: gkrtypes.Mul2}, Inputs: []int{0, 1}},
	}
}

func SingleInputTwoIdentityGatesCircuit() gkrtypes.GadgetCircuit {
	idGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	return gkrtypes.GadgetCircuit{
		{Gate: idGate},
		{Gate: idGate, Inputs: []int{0}},
		{Gate: idGate, Inputs: []int{0}},
	}
}

func SingleInputTwoIdentityGatesComposedCircuit() gkrtypes.GadgetCircuit {
	idGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	return gkrtypes.GadgetCircuit{
		{Gate: idGate},
		{Gate: idGate, Inputs: []int{0}},
		{Gate: idGate, Inputs: []int{1}},
	}
}

func APowNTimesBCircuit(n int) gkrtypes.GadgetCircuit {
	c := make(gkrtypes.GadgetCircuit, n+2)
	idGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	mulGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Mul2}

	c[0] = gkrtypes.GadgetWire{Gate: idGate}
	c[1] = gkrtypes.GadgetWire{Gate: idGate}

	for i := 2; i < len(c); i++ {
		c[i] = gkrtypes.GadgetWire{Gate: mulGate, Inputs: []int{i - 1, 0}}
	}
	return c
}

func SingleMimcCipherGateCircuit() gkrtypes.GadgetCircuit {
	idGate := &gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	return gkrtypes.GadgetCircuit{
		{Gate: idGate},
		{Gate: idGate},
		{Gate: &gkrtypes.GadgetGate{Evaluate: mimcGate}, Inputs: []int{0, 1}},
	}
}
