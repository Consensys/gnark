package gkrtesting

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/std/gkr"
)

// Cache for circuits and gates.
// The main functionality is to cache whole circuits, but this package needs to use its own gate registry, in order to avoid import cycles.
// Cache is used in tests for the per-curve GKR packages, but they in turn provide gate degree discovery functions to the gkrgates package.
type Cache struct {
	circuits map[string]gkrtypes.Circuit
	gates    map[gkr.GateName]*gkrtypes.Gate
}

func NewCache() *Cache {
	gates := make(map[gkr.GateName]*gkrtypes.Gate, 7)
	gates[gkr.Identity] = gkrtypes.Identity()
	gates[gkr.Add2] = gkrtypes.Add2()
	gates[gkr.Sub2] = gkrtypes.Sub2()
	gates[gkr.Neg] = gkrtypes.Neg()
	gates[gkr.Mul2] = gkrtypes.Mul2()
	gates["select-input-3"] = gkrtypes.New(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return in[2]
	}, 3, 1, 0)

	return &Cache{
		circuits: make(map[string]gkrtypes.Circuit),
		gates:    gates,
	}
}

func (c *Cache) GetCircuit(path string) (circuit gkrtypes.Circuit) {
	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	var ok bool
	if circuit, ok = c.circuits[path]; ok {
		return
	}

	var bytes []byte
	if bytes, err = os.ReadFile(path); err != nil {
		panic(err)
	}
	var circuitInfo gkrinfo.Circuit
	if err = json.Unmarshal(bytes, &circuitInfo); err != nil {
		panic(err)
	}
	if circuit, err = gkrtypes.CircuitInfoToCircuit(circuitInfo, c.GetGate); err != nil {
		panic(err)
	}
	c.circuits[path] = circuit

	return
}

func (c *Cache) RegisterGate(name gkr.GateName, gate *gkrtypes.Gate) {
	if _, ok := c.gates[name]; ok {
		panic("gate already registered")
	}
	c.gates[name] = gate
}

func (c *Cache) GetGate(name gkr.GateName) *gkrtypes.Gate {
	if gate, ok := c.gates[name]; ok {
		return gate
	}
	panic("gate not found")
}
