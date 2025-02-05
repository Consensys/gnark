package poseidon2

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	poseidonbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	poseidonbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	poseidonbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/poseidon2"
	poseidonbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/poseidon2"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	poseidonbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/poseidon2"
	poseidonbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

var (
	ErrInvalidSizebuffer = errors.New("the size of the input should match the size of the hash buffer")
)

type Permutation struct {
	params parameters
}

// parameters describing the poseidon2 implementation
type parameters struct {

	// len(preimage)+len(digest)=len(preimage)+ceil(log(2*<security_level>/r))
	t int

	// sbox degree
	d int

	// number of full rounds (even number)
	rF int

	// number of partial rounds
	rP int

	// diagonal elements of the internal matrices, excluding one
	diagInternalMatrices []big.Int

	// round keys: ordered by round then variable
	roundKeys [][]big.Int
}

func NewPermutation(t, d, rf, rp int, curve ecc.ID) Permutation {
	params := parameters{t: t, d: d, rF: rf, rP: rp}
	if curve == ecc.BN254 {
		rc := poseidonbn254.NewParameters(t, rf, rp).RoundKeys
		params.roundKeys = make([][]big.Int, len(rc))
		for i := 0; i < len(rc); i++ {
			params.roundKeys[i] = make([]big.Int, len(rc[i]))
			for j := 0; j < len(rc[i]); j++ {
				rc[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	} else if curve == ecc.BLS12_381 {
		rc := poseidonbls12381.NewParameters(t, rf, rp).RoundKeys
		params.roundKeys = make([][]big.Int, len(rc))
		for i := 0; i < len(rc); i++ {
			params.roundKeys[i] = make([]big.Int, len(rc[i]))
			for j := 0; j < len(rc[i]); j++ {
				rc[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	} else if curve == ecc.BLS12_377 {
		rc := poseidonbls12377.NewParameters(t, rf, rp).RoundKeys
		params.roundKeys = make([][]big.Int, len(rc))
		for i := 0; i < len(rc); i++ {
			params.roundKeys[i] = make([]big.Int, len(rc[i]))
			for j := 0; j < len(rc[i]); j++ {
				rc[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	} else if curve == ecc.BW6_761 {
		rc := poseidonbw6761.NewParameters(t, rf, rp).RoundKeys
		params.roundKeys = make([][]big.Int, len(rc))
		for i := 0; i < len(rc); i++ {
			params.roundKeys[i] = make([]big.Int, len(rc[i]))
			for j := 0; j < len(rc[i]); j++ {
				rc[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	} else if curve == ecc.BW6_633 {
		rc := poseidonbw6633.NewParameters(t, rf, rp).RoundKeys
		params.roundKeys = make([][]big.Int, len(rc))
		for i := 0; i < len(rc); i++ {
			params.roundKeys[i] = make([]big.Int, len(rc[i]))
			for j := 0; j < len(rc[i]); j++ {
				rc[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	} else if curve == ecc.BLS24_315 {
		rc := poseidonbls24315.NewParameters(t, rf, rp).RoundKeys
		params.roundKeys = make([][]big.Int, len(rc))
		for i := 0; i < len(rc); i++ {
			params.roundKeys[i] = make([]big.Int, len(rc[i]))
			for j := 0; j < len(rc[i]); j++ {
				rc[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	} else if curve == ecc.BLS24_317 {
		rc := poseidonbls24317.NewParameters(t, rf, rp).RoundKeys
		params.roundKeys = make([][]big.Int, len(rc))
		for i := 0; i < len(rc); i++ {
			params.roundKeys[i] = make([]big.Int, len(rc[i]))
			for j := 0; j < len(rc[i]); j++ {
				rc[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	}
	return Permutation{params: params}
}

// sBox applies the sBox on buffer[index]
func (h *Permutation) sBox(api frontend.API, index int, input []frontend.Variable) {
	input[index] = power(api, input[index], h.params.d)
}

func power(api frontend.API, x frontend.Variable, n int) frontend.Variable {
	tmp := x
	switch n {
	case 3:
		x = api.Mul(x, x)
		x = api.Mul(tmp, x)
	case 5:
		x = api.Mul(x, x)
		x = api.Mul(x, x)
		x = api.Mul(x, tmp)
	case 7:
		x = api.Mul(x, x)
		x = api.Mul(x, tmp)
		x = api.Mul(x, x)
		x = api.Mul(x, tmp)
	case 17:
		x = api.Mul(x, x)
		x = api.Mul(x, x)
		x = api.Mul(x, x)
		x = api.Mul(x, x)
		x = api.Mul(x, tmp)
	case -1:
		x = api.Inverse(x)
	default:
		panic("unknown sBox degree")
	}
	return x
}

// matMulM4 computes
// s <- M4*s
// where M4=
// (5 7 1 3)
// (4 6 1 1)
// (1 3 5 7)
// (1 1 4 6)
// on chunks of 4 elements on each part of the buffer
// see https://eprint.iacr.org/2023/323.pdf appendix B for the addition chain
func (h *Permutation) matMulM4InPlace(api frontend.API, s []frontend.Variable) {
	c := len(s) / 4
	for i := 0; i < c; i++ {
		t0 := api.Add(s[4*i], s[4*i+1])   // s0+s1
		t1 := api.Add(s[4*i+2], s[4*i+3]) // s2+s3
		t2 := api.Mul(s[4*i+1], 2)
		t2 = api.Add(t2, t1) // 2s1+t1
		t3 := api.Mul(s[4*i+3], 2)
		t3 = api.Add(t3, t0) // 2s3+t0
		t4 := api.Mul(t1, 4)
		t4 = api.Add(t4, t3) // 4t1+t3
		t5 := api.Mul(t0, 4)
		t5 = api.Add(t5, t2)  // 4t0+t2
		t6 := api.Add(t3, t5) // t3+t5
		t7 := api.Add(t2, t4) // t2+t4
		s[4*i] = t6
		s[4*i+1] = t5
		s[4*i+2] = t7
		s[4*i+3] = t4
	}
}

// when t=2,3 the buffer is multiplied by circ(2,1) and circ(2,1,1)
// see https://eprint.iacr.org/2023/323.pdf page 15, case t=2,3
//
// when t=0[4], the buffer is multiplied by circ(2M4,M4,..,M4)
// see https://eprint.iacr.org/2023/323.pdf
func (h *Permutation) matMulExternalInPlace(api frontend.API, input []frontend.Variable) {

	if h.params.t == 2 {
		tmp := api.Add(input[0], input[1])
		input[0] = api.Add(tmp, input[0])
		input[1] = api.Add(tmp, input[1])
	} else if h.params.t == 3 {
		var tmp frontend.Variable
		tmp = api.Add(input[0], input[1])
		tmp = api.Add(tmp, input[2])
		input[0] = api.Add(input[0], tmp)
		input[1] = api.Add(input[1], tmp)
		input[2] = api.Add(input[2], tmp)
	} else if h.params.t == 4 {
		h.matMulM4InPlace(api, input)
	} else {
		// at this stage t is supposed to be a multiple of 4
		// the MDS matrix is circ(2M4,M4,..,M4)
		h.matMulM4InPlace(api, input)
		tmp := make([]frontend.Variable, 4)
		for i := 0; i < h.params.t/4; i++ {
			tmp[0] = api.Add(tmp[0], input[4*i])
			tmp[1] = api.Add(tmp[1], input[4*i+1])
			tmp[2] = api.Add(tmp[2], input[4*i+2])
			tmp[3] = api.Add(tmp[3], input[4*i+3])
		}
		for i := 0; i < h.params.t/4; i++ {
			input[4*i] = api.Add(input[4*i], tmp[0])
			input[4*i+1] = api.Add(input[4*i], tmp[1])
			input[4*i+2] = api.Add(input[4*i], tmp[2])
			input[4*i+3] = api.Add(input[4*i], tmp[3])
		}
	}
}

// when t=2,3 the matrix are respectively [[2,1][1,3]] and [[2,1,1][1,2,1][1,1,3]]
// otherwise the matrix is filled with ones except on the diagonal,
func (h *Permutation) matMulInternalInPlace(api frontend.API, input []frontend.Variable) {
	if h.params.t == 2 {
		sum := api.Add(input[0], input[1])
		input[0] = api.Add(input[0], sum)
		input[1] = api.Mul(2, input[1])
		input[1] = api.Add(input[1], sum)
	} else if h.params.t == 3 {
		var sum frontend.Variable
		sum = api.Add(input[0], input[1])
		sum = api.Add(sum, input[2])
		input[0] = api.Add(input[0], sum)
		input[1] = api.Add(input[1], sum)
		input[2] = api.Mul(input[2], 2)
		input[2] = api.Add(input[2], sum)
	} else {
		var sum frontend.Variable
		sum = input[0]
		for i := 1; i < h.params.t; i++ {
			sum = api.Add(sum, input[i])
		}
		for i := 0; i < h.params.t; i++ {
			input[i] = api.Mul(input[i], h.params.diagInternalMatrices[i])
			input[i] = api.Add(input[i], sum)
		}
	}
}

// addRoundKeyInPlace adds the round-th key to the buffer
func (h *Permutation) addRoundKeyInPlace(api frontend.API, round int, input []frontend.Variable) {
	for i := 0; i < len(h.params.roundKeys[round]); i++ {
		input[i] = api.Add(input[i], h.params.roundKeys[round][i])
	}
}

func (h *Permutation) Permutation(api frontend.API, input []frontend.Variable) error {
	if len(input) != h.params.t {
		return ErrInvalidSizebuffer
	}

	// external matrix multiplication, cf https://eprint.iacr.org/2023/323.pdf page 14 (part 6)
	h.matMulExternalInPlace(api, input)

	rf := h.params.rF / 2
	for i := 0; i < rf; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(api, i, input)
		for j := 0; j < h.params.t; j++ {
			h.sBox(api, j, input)
		}
		h.matMulExternalInPlace(api, input)
	}

	for i := rf; i < rf+h.params.rP; i++ {
		// one round = matMulInternal(sBox_sparse(addRoundKey))
		h.addRoundKeyInPlace(api, i, input)
		h.sBox(api, 0, input)
		h.matMulInternalInPlace(api, input)
	}
	for i := rf + h.params.rP; i < h.params.rF+h.params.rP; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(api, i, input)
		for j := 0; j < h.params.t; j++ {
			h.sBox(api, j, input)
		}
		h.matMulExternalInPlace(api, input)
	}

	return nil
}
