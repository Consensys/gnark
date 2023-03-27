package gkr

import (
	"github.com/consensys/gnark/std/gkr/hash"
	"github.com/consensys/gnark/std/gkr/snark/polynomial"

	"github.com/consensys/gnark/frontend"
)

// CreateMimcCircuit creates a GKR circuit for Mimc
func CreateMimcCircuit() Circuit {
	nLayers := hash.MimcRounds
	layers := make([]Layer, hash.MimcRounds)

	for i := 0; i < nLayers-1; i++ {
		layers[i] = Layer{
			Gates: []Gate{
				CipherGate(hash.Arks[i]),
				CopyGate(),
			},
			StaticTable: []StaticTableGenerator{
				GetCipherTable,
				GetCopyTable,
			},
			BG:        1,
			DegHL:     2,
			DegHR:     8,
			DegHPrime: 8,
		}
	}

	layers[nLayers-1] = Layer{
		Gates:       []Gate{CipherGate(hash.Arks[nLayers-1])},
		StaticTable: []StaticTableGenerator{GetFinalCipherTable},
		BG:          1,
		DegHL:       2,
		DegHR:       8,
		DegHPrime:   8,
	}

	return Circuit{
		Layers: layers,
		BGOut:  0,
	}

}

// CreateMimcCircuit creates a GKR circuit for Mimc
func CreateMimcCircuitBatch(batch int) Circuit {
	nLayers := 13
	layers := make([]Layer, 13)

	for i := 0; i < nLayers-1; i++ {
		layers[i] = Layer{
			Gates: []Gate{
				CipherGate(hash.Arks[i+batch*nLayers]),
				CopyGate(),
			},
			StaticTable: []StaticTableGenerator{
				GetCipherTable,
				GetCopyTable,
			},
			BG:        1,
			DegHL:     2,
			DegHR:     8,
			DegHPrime: 8,
		}
	}

	layers[nLayers-1] = Layer{
		Gates:       []Gate{CipherGate(hash.Arks[nLayers-1+batch*nLayers])},
		StaticTable: []StaticTableGenerator{GetFinalCipherTable},
		BG:          1,
		DegHL:       2,
		DegHR:       8,
		DegHPrime:   8,
	}

	return Circuit{
		Layers: layers,
		BGOut:  0,
	}

}

// GetCopyTable returns a prefolded copy table for the intermediate rounds
func GetCopyTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		0,
		0,
		Q[0],
		0,
	})
}

// GetCipherTable returns a prefolded cipher table for the intermediate rounds
func GetCipherTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		0,
		0,
		cs.Sub(1, Q[0]),
		0,
	})
}

// GetFinalCipherTable returns a prefolded cipher table for the intermediate rounds
func GetFinalCipherTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		0, 0, 1, 0,
	})
}
