package gkrtesting

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

// Cache for circuits and gates.
// The main functionality is to cache whole circuits, but this package needs to use its own gate registry, in order to avoid import cycles.
// Cache is used in tests for the per-curve GKR packages, but they in turn provide gate degree discovery functions to the gkrgates package.
type Cache struct {
	circuits map[string]gkrtypes.RegisteredCircuit
	gates    map[gkr.GateName]*gkrtypes.RegisteredGate
}

func NewCache() *Cache {
	gates := make(map[gkr.GateName]*gkrtypes.RegisteredGate, 7)
	gates[gkr.Identity] = gkrtypes.Identity()
	gates[gkr.Add2] = gkrtypes.Add2()
	gates[gkr.Sub2] = gkrtypes.Sub2()
	gates[gkr.Neg] = gkrtypes.Neg()
	gates[gkr.Mul2] = gkrtypes.Mul2()
	mimcF := func(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
		sum := api.Add(input[0], input[1]) //.Add(&sum, &m.ark)  TODO: add ark
		res := api.Mul(sum, sum)           // sum^2
		res = api.Mul(res, sum)            // sum^3
		res = api.Mul(res, res)            // sum^6
		res = api.Mul(res, sum)            // sum^7

		return res
	}
	mimcCompiled, err := gkrtypes.CompileGateFunction(mimcF, 2)
	if err != nil {
		panic(err)
	}
	gates["mimc"] = gkrtypes.NewGate(mimcF, mimcCompiled, 2, 7, -1, gnark.Curves())
	gates["select-input-3"] = gkrtypes.NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return in[2]
	}, &gkrtypes.GateBytecode{}, 3, 1, 0, gnark.Curves())

	return &Cache{
		circuits: make(map[string]gkrtypes.RegisteredCircuit),
		gates:    gates,
	}
}

func (c *Cache) GetCircuit(path string) gkrtypes.RegisteredCircuit {
	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	var ok bool
	var circuit gkrtypes.RegisteredCircuit
	if circuit, ok = c.circuits[path]; ok {
		return circuit
	}

	var bytes []byte
	if bytes, err = os.ReadFile(path); err != nil {
		panic(err)
	}
	var circuitInfo gkrtypes.SerializableCircuit
	if err = json.Unmarshal(bytes, &circuitInfo); err != nil {
		panic(err)
	}

	// Build gate map from bytecode to registered gates
	gateMap := make(map[*gkrtypes.GateBytecode]*gkrtypes.RegisteredGate)
	for _, wire := range circuitInfo {
		if wire.Gate.Executable != nil {
			// For each bytecode gate, find the matching registered gate from our cache
			for _, gate := range c.gates {
				if gate.Executable.Bytecode == wire.Gate.Executable {
					gateMap[wire.Gate.Executable] = gate
					break
				}
			}
		}
	}

	// Convert serializable circuit to registered circuit with both executables
	circuit = gkrtypes.ConvertCircuit[*gkrtypes.GateBytecode, gkrtypes.BothExecutables](
		gkrtypes.Circuit[*gkrtypes.GateBytecode](circuitInfo),
		func(bytecode *gkrtypes.GateBytecode) gkrtypes.BothExecutables {
			if gate, ok := gateMap[bytecode]; ok {
				return gate.Executable
			}
			panic("gate not found in cache")
		},
	)

	c.circuits[path] = circuit

	return circuit
}

func (c *Cache) RegisterGate(name gkr.GateName, gate *gkrtypes.RegisteredGate) {
	if _, ok := c.gates[name]; ok {
		panic("gate already registered")
	}
	c.gates[name] = gate
}

func (c *Cache) GetGate(name gkr.GateName) *gkrtypes.RegisteredGate {
	if gate, ok := c.gates[name]; ok {
		return gate
	}
	panic("gate not found")
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
