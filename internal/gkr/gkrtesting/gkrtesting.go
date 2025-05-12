package gkrtesting

import (
	"encoding/json"
	"os"
	"path/filepath"

	gadget "github.com/consensys/gnark/internal/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrgate"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/std/gkr"
)

type CircuitCache struct {
	m       map[string]gadget.Circuit
	getGate func(gkr.GateName) *gkrgate.Gate
}

func NewCircuitCache(getGate func(gkr.GateName) *gkrgate.Gate) *CircuitCache {
	return &CircuitCache{
		m:       make(map[string]gadget.Circuit),
		getGate: getGate,
	}
}

func (c *CircuitCache) Get(path string) (circuit gadget.Circuit) {
	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	var ok bool
	if circuit, ok = c.m[path]; ok {
		return
	}
	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var circuitInfo gkrinfo.Circuit
		if err = json.Unmarshal(bytes, &circuitInfo); err == nil {
			c.m[path], err = gadget.CircuitInfoToCircuit(circuitInfo, c.getGate)
		}
	}

	if err != nil {
		panic(err)
	}
	return
}
