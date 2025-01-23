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

// extKeySBoxGate applies the external matrix mul, then adds the round key, then applies the sBox
// because of its symmetry, we don't need to define distinct x1 and x2 versions of it
type extKeySBoxGate struct {
	roundKey *big.Int
	d        int
}

func (g *extKeySBoxGate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return power(api, api.Add(api.Mul(x[0], 2), x[1], g.roundKey), g.d)
	//var g gkr.Gate = &extKeyGate2{}
}

func (g *extKeySBoxGate) Degree() int {
	return g.d
}

// for x1, the partial round gates are identical to full round gates
// for x2, the partial round gates are just a linear combination
// TODO @Tabaie eliminate the x2 partial round gates and have the x1 gates depend on i - rf/2 or so previous x1's

// extKeyGate2 applies the external matrix mul, then adds the round key
type extKeyGate2 struct {
	roundKey *big.Int
	d        int
}

func (g *extKeyGate2) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 2), x[0], g.roundKey)
}

func (g *extKeyGate2) Degree() int {
	return 1
}

// intKeyGate2 applies the internal matrix mul, then adds the round key
type intKeyGate2 struct {
	roundKey *big.Int
	d        int
}

func (g *intKeyGate2) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 3), x[0], g.roundKey)
}

func (g *intKeyGate2) Degree() int {
	return 1
}

// intKeySBoxGate applies the second row of internal matrix mul, then adds the round key, then applies the sBox
type intKeySBoxGate2 struct {
	roundKey *big.Int
	d        int
}

func (g *intKeySBoxGate2) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return power(api, api.Add(api.Mul(x[1], 3), x[0], g.roundKey), g.d)
}

func (g *intKeySBoxGate2) Degree() int {
	return g.d
}

type extGate struct{}

func (g extGate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[0], 2), x[1])
}

func (g extGate) Degree() int {
	return 1
}
