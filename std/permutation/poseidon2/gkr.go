package poseidon2

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
	"hash"
	"math/big"
)

// Gkr implements a GKR version of the Poseidon2 permutation with fan-in 2
type Gkr struct {
	Hash
	Ins         []frontend.Variable
	Outs        []frontend.Variable
	plainHasher hash.Hash
}

type gkrGate struct {
}

func (g gkrGate) Evaluate(api frontend.API, variable ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (g gkrGate) Degree() int {
	//TODO implement me
	panic("implement me")
}

func gkrPermutation(api *gkr.API, h *Hash) {

}

type gkrMatMulExternalInPlaceGate *Hash

// SHA256 hash of the hash parameters - as a unique identifier
// Note that the identifier is only unique with respect to the size parameters
// t, d, rF, rP
func (h *Hash) hash(curve ecc.ID) []byte {
	hasher := sha256.New()
	writeAsByte := func(i int) {
		if i > 255 || i < 0 {
			panic("uint8 expected")
		}
		hasher.Write([]byte{byte(i)})
	}
	writeAsTwoBytes := func(i int) {
		if i > 65535 || i < 0 {
			panic("uint16 expected")
		}
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(i))
		hasher.Write(buf[:])
	}
	writeAsTwoBytes(int(curve))
	writeAsByte(h.params.t)
	writeAsByte(h.params.d)
	writeAsByte(h.params.rF)
	writeAsByte(h.params.rP)
	return hasher.Sum(nil)
}

// extRoundSBox applies the external matrix mul, then adds the round key, then applies the sBox
type extRoundSBox struct {
	roundKey *big.Int
	d        int
}

func (g *extRoundSBox) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	//y := api.Add(api.Mul(x[0], 2), x[1], g.roundKey)
	//return sBox(api, g.d)
	return nil
}

func (g *extRoundSBox) Degree() int {
	return g.d
}
