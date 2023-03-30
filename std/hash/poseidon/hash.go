package poseidon

import (
	"github.com/consensys/gnark/frontend"
)

// PoseidonHash contains the params of the Mimc hash func and the curves on which it is implemented
type PoseidonHash struct {
	data []frontend.Variable // state storage. data is updated when Write() is called. Sum sums the data.
	api  frontend.API        // underlying constraint system
}

// NewPoseidonHash returns a MiMC instance, than can be used in a gnark circuit
func NewPoseidonHash(api frontend.API) *PoseidonHash {
	return &PoseidonHash{data: make([]frontend.Variable, 0), api: api}
}

// Write adds more data to the running hash.
func (h *PoseidonHash) Write(data ...frontend.Variable) {
	h.data = append(h.data, data...)
}

// Reset resets the Hash to its initial state.
func (h *PoseidonHash) Reset() {
	h.data = nil
}

// Sum hash (in r1cs form) using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition.
// See github.com/consensys/gnark-crypto for reference implementation.
func (h *PoseidonHash) Sum() frontend.Variable {

	//h.Write(data...)s
	result := Poseidon(h.api, h.data...)
	h.data = nil
	return result
}
