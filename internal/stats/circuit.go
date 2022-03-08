package stats

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/circuits"
)

// note this is deprecated in favor of registerSnippet but stays to detect regressions in internal/

// registerCircuit circuit will be added to statistics tests
func registerCircuit(name string, circuit frontend.Circuit, curves []ecc.ID) {
	if _, ok := AllCircuits[name]; ok {
		panic("circuit " + name + " already registered")
	}

	AllCircuits[name] = Circuit{circuit, curves}
}

func init() {
	// register internal circuits
	for name, circuit := range circuits.Circuits {
		registerCircuit(name, circuit.Circuit, circuit.Curves)
	}
}
