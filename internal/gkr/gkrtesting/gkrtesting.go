package gkrtesting

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

// Cache for circuits and gates.
// The main functionality is to cache whole circuits, but this package needs to use its own gate registry, in order to avoid import cycles.
// Cache is used in tests for the per-curve GKR packages, but they in turn provide gate degree discovery functions to the gkrgates package.
type Cache struct {
	field    *big.Int
	circuits map[string]circuits
	gates    map[string]gkr.GateFunction
	lock     sync.Mutex
}

type circuits struct {
	proverCircuit   gkrtypes.SerializableCircuit
	verifierCircuit gkrtypes.GadgetCircuit
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

func NewCache(field *big.Int) *Cache {
	gates := make(map[string]gkr.GateFunction, 7)
	gates[""] = nil
	gates["identity"] = gkrtypes.Identity
	gates["add2"] = gkrtypes.Add2
	gates["sub2"] = gkrtypes.Sub2
	gates["neg"] = gkrtypes.Neg
	gates["mul2"] = gkrtypes.Mul2
	gates["mimc"] = mimcGate
	gates["select-input-3"] = selectInput3Gate

	return &Cache{
		field:    field,
		circuits: make(map[string]circuits),
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

func (c *Cache) GetCircuit(path string) (gkrtypes.SerializableCircuit, gkrtypes.GadgetCircuit) {
	c.lock.Lock()
	defer c.lock.Unlock()

	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	if circuit, ok := c.circuits[path]; ok {
		return circuit.proverCircuit, circuit.verifierCircuit
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
			Gate:   gkrtypes.Gate[gkr.GateFunction]{Evaluate: gate},
			Inputs: wJSON.Inputs,
		}
	}
	pCircuit := gkrtypes.CompileCircuit(circuit, c.field)

	c.circuits[path] = circuits{
		proverCircuit:   pCircuit,
		verifierCircuit: circuit,
	}

	return pCircuit, circuit
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
	mimc := gkrtypes.GadgetGate{Evaluate: mimcGate}

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
		{},
	}
}

func SingleAddGateCircuit() gkrtypes.GadgetCircuit {
	return gkrtypes.GadgetCircuit{
		{},
		{},
		{Gate: gkrtypes.GadgetGate{Evaluate: gkrtypes.Add2}, Inputs: []int{0, 1}},
	}
}

func SingleMulGateCircuit() gkrtypes.GadgetCircuit {
	return gkrtypes.GadgetCircuit{
		{},
		{},
		{Gate: gkrtypes.GadgetGate{Evaluate: gkrtypes.Mul2}, Inputs: []int{0, 1}},
	}
}

func SingleInputTwoIdentityGatesCircuit() gkrtypes.GadgetCircuit {
	idGate := gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	return gkrtypes.GadgetCircuit{
		{},
		{Gate: idGate, Inputs: []int{0}},
		{Gate: idGate, Inputs: []int{0}},
	}
}

func SingleInputTwoIdentityGatesComposedCircuit() gkrtypes.GadgetCircuit {
	idGate := gkrtypes.GadgetGate{Evaluate: gkrtypes.Identity}
	return gkrtypes.GadgetCircuit{
		{},
		{Gate: idGate, Inputs: []int{0}},
		{Gate: idGate, Inputs: []int{1}},
	}
}

func APowNTimesBCircuit(n int) gkrtypes.GadgetCircuit {
	c := make(gkrtypes.GadgetCircuit, n+2)
	mulGate := gkrtypes.GadgetGate{Evaluate: gkrtypes.Mul2}

	for i := 2; i < len(c); i++ {
		c[i] = gkrtypes.GadgetWire{Gate: mulGate, Inputs: []int{i - 1, 0}}
	}
	return c
}

func SingleMimcCipherGateCircuit() gkrtypes.GadgetCircuit {
	return gkrtypes.GadgetCircuit{
		{},
		{},
		{Gate: gkrtypes.GadgetGate{Evaluate: mimcGate}, Inputs: []int{0, 1}},
	}
}
