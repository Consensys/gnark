package gkrtesting

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	gadget "github.com/consensys/gnark/internal/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrgate"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/std/gkr"
)

// Cache for circuits and gates.
// The main functionality is to cache whole circuits, but this package needs to use its own gate registry, in order to avoid import cycles.
// Cache is used in tests for the per-curve GKR packages, but they in turn provide gate degree discovery functions to the gkrgates package.
type Cache struct {
	circuits map[string]gadget.Circuit
	gates    map[gkr.GateName]*gkrgate.Gate
}

func NewCircuitCache() *Cache {
	gates := make(map[gkr.GateName]*gkrgate.Gate, 7)
	gates[gkr.Identity] = gkrgate.Identity()
	gates[gkr.Add2] = gkrgate.Add2()
	gates[gkr.Sub2] = gkrgate.Sub2()
	gates[gkr.Neg] = gkrgate.Neg()
	gates[gkr.Mul2] = gkrgate.Mul2()
	gates["select-input-3"] = gkrgate.New(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return in[2]
	}, 3, 1, 0)

	return &Cache{
		circuits: make(map[string]gadget.Circuit),
		gates:    gates,
	}
}

func (c *Cache) Get(path string) (circuit gadget.Circuit) {
	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	var ok bool
	if circuit, ok = c.circuits[path]; ok {
		return
	}

	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var circuitInfo gkrinfo.Circuit
		if err = json.Unmarshal(bytes, &circuitInfo); err == nil {
			circuit, err = gadget.CircuitInfoToCircuit(circuitInfo, c.GetGate)
			if err == nil {
				c.circuits[path] = circuit
			} else {
				panic(err)
			}
		}
	}

	return
}

func (c *Cache) RegisterGate(name gkr.GateName, gate *gkrgate.Gate) {
	if _, ok := c.gates[name]; ok {
		panic("gate already registered")
	}
	c.gates[name] = gate
}

func (c *Cache) GetGate(name gkr.GateName) *gkrgate.Gate {
	if gate, ok := c.gates[name]; ok {
		return gate
	}
	panic("gate not found")
}
