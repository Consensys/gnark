package poseidon2

import (
	"errors"
	"fmt"
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
	"github.com/consensys/gnark/internal/utils"
)

var (
	ErrInvalidSizebuffer = errors.New("the size of the input should match the size of the hash buffer")
)

type Permutation struct {
	api    frontend.API
	params parameters
}

// parameters describing the poseidon2 implementation
type parameters struct {
	// len(preimage)+len(digest)=len(preimage)+ceil(log(2*<security_level>/r))
	width int

	// sbox degree
	degreeSBox int

	// number of full rounds (even number)
	nbFullRounds int

	// number of partial rounds
	nbPartialRounds int

	// round keys: ordered by round then variable
	roundKeys [][]big.Int
}

// NewPoseidon2 returns a new Poseidon2 hasher with default parameters as
// defined in the gnark-crypto library.
func NewPoseidon2(api frontend.API) (*Permutation, error) {
	switch utils.FieldToCurve(api.Compiler().Field()) { // TODO: assumes pairing based builder, reconsider when supporting other backends
	case ecc.BLS12_377:
		params := poseidonbls12377.GetDefaultParameters()
		return NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)
	// TODO: we don't have default parameters for other curves yet. Update this when we do.
	case ecc.BN254:
		params := poseidonbls12377.GetDefaultParameters()
		return NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)
	default:
		return nil, fmt.Errorf("field %s not supported", api.Compiler().Field().String())
	}
}

// NewPoseidon2FromParameters returns a new Poseidon2 hasher with the given parameters.
// The parameters are used to precompute the round keys. The round key computation
// is deterministic and depends on the curve ID. See the corresponding NewParameters
// function in the gnark-crypto library poseidon2 packages for more details.
func NewPoseidon2FromParameters(api frontend.API, width, nbFullRounds, nbPartialRounds int) (*Permutation, error) {
	params := parameters{width: width, nbFullRounds: nbFullRounds, nbPartialRounds: nbPartialRounds}
	switch utils.FieldToCurve(api.Compiler().Field()) { // TODO: assumes pairing based builder, reconsider when supporting other backends
	case ecc.BN254:
		params.degreeSBox = poseidonbn254.DegreeSBox()
		concreteParams := poseidonbn254.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.roundKeys {
			params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.roundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	case ecc.BLS12_381:
		params.degreeSBox = poseidonbls12381.DegreeSBox()
		concreteParams := poseidonbls12381.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.roundKeys {
			params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.roundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	case ecc.BLS12_377:
		params.degreeSBox = poseidonbls12377.DegreeSBox()
		concreteParams := poseidonbls12377.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.roundKeys {
			params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.roundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	case ecc.BW6_761:
		params.degreeSBox = poseidonbw6761.DegreeSBox()
		concreteParams := poseidonbw6761.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.roundKeys {
			params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.roundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	case ecc.BW6_633:
		params.degreeSBox = poseidonbw6633.DegreeSBox()
		concreteParams := poseidonbw6633.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.roundKeys {
			params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.roundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	case ecc.BLS24_315:
		params.degreeSBox = poseidonbls24315.DegreeSBox()
		concreteParams := poseidonbls24315.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.roundKeys {
			params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.roundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	case ecc.BLS24_317:
		params.degreeSBox = poseidonbls24317.DegreeSBox()
		concreteParams := poseidonbls24317.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.roundKeys {
			params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.roundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
			}
		}
	default:
		return nil, fmt.Errorf("field %s not supported", api.Compiler().Field().String())
	}
	return &Permutation{api: api, params: params}, nil
}

// sBox applies the sBox on buffer[index]
func (h *Permutation) sBox(index int, input []frontend.Variable) {
	tmp := input[index]
	if h.params.degreeSBox == 3 {
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(tmp, input[index])
	} else if h.params.degreeSBox == 5 {
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	} else if h.params.degreeSBox == 7 {
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	} else if h.params.degreeSBox == 17 {
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	} else if h.params.degreeSBox == -1 {
		input[index] = h.api.Inverse(input[index])
	}
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
func (h *Permutation) matMulM4InPlace(s []frontend.Variable) {
	c := len(s) / 4
	for i := 0; i < c; i++ {
		t0 := h.api.Add(s[4*i], s[4*i+1])   // s0+s1
		t1 := h.api.Add(s[4*i+2], s[4*i+3]) // s2+s3
		t2 := h.api.Mul(s[4*i+1], 2)
		t2 = h.api.Add(t2, t1) // 2s1+t1
		t3 := h.api.Mul(s[4*i+3], 2)
		t3 = h.api.Add(t3, t0) // 2s3+t0
		t4 := h.api.Mul(t1, 4)
		t4 = h.api.Add(t4, t3) // 4t1+t3
		t5 := h.api.Mul(t0, 4)
		t5 = h.api.Add(t5, t2)  // 4t0+t2
		t6 := h.api.Add(t3, t5) // t3+t5
		t7 := h.api.Add(t2, t4) // t2+t4
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
func (h *Permutation) matMulExternalInPlace(input []frontend.Variable) {

	if h.params.width == 2 {
		tmp := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(tmp, input[0])
		input[1] = h.api.Add(tmp, input[1])
	} else if h.params.width == 3 {
		tmp := h.api.Add(input[0], input[1])
		tmp = h.api.Add(tmp, input[2])
		input[0] = h.api.Add(input[0], tmp)
		input[1] = h.api.Add(input[1], tmp)
		input[2] = h.api.Add(input[2], tmp)
	} else if h.params.width == 4 {
		h.matMulM4InPlace(input)
	} else {
		// at this stage t is supposed to be a multiple of 4
		// the MDS matrix is circ(2M4,M4,..,M4)
		h.matMulM4InPlace(input)
		tmp := make([]frontend.Variable, 4)
		for i := 0; i < h.params.width/4; i++ {
			tmp[0] = h.api.Add(tmp[0], input[4*i])
			tmp[1] = h.api.Add(tmp[1], input[4*i+1])
			tmp[2] = h.api.Add(tmp[2], input[4*i+2])
			tmp[3] = h.api.Add(tmp[3], input[4*i+3])
		}
		for i := 0; i < h.params.width/4; i++ {
			input[4*i] = h.api.Add(input[4*i], tmp[0])
			input[4*i+1] = h.api.Add(input[4*i], tmp[1])
			input[4*i+2] = h.api.Add(input[4*i], tmp[2])
			input[4*i+3] = h.api.Add(input[4*i], tmp[3])
		}
	}
}

// when t=2,3 the matrix are respectively [[2,1][1,3]] and [[2,1,1][1,2,1][1,1,3]]
// otherwise the matrix is filled with ones except on the diagonal,
func (h *Permutation) matMulInternalInPlace(input []frontend.Variable) {
	if h.params.width == 2 {
		sum := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Mul(2, input[1])
		input[1] = h.api.Add(input[1], sum)
	} else if h.params.width == 3 {
		sum := h.api.Add(input[0], input[1])
		sum = h.api.Add(sum, input[2])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Add(input[1], sum)
		input[2] = h.api.Mul(input[2], 2)
		input[2] = h.api.Add(input[2], sum)
	} else {
		// TODO: we don't have general case implemented in gnark-crypto side.
		// Currently we only have the hardcoded matrices for t=2,3. If we would
		// use `h.params.diagInternalMatrices` we would need to set it, but
		// currently they are nil.

		// var sum frontend.Variable
		// sum = input[0]
		// for i := 1; i < h.params.width; i++ {
		// 	sum = api.Add(sum, input[i])
		// }
		// for i := 0; i < h.params.width; i++ {
		// 	input[i] = api.Mul(input[i], h.params.diagInternalMatrices[i])
		// 	input[i] = api.Add(input[i], sum)
		// }
		panic("only T=2,3 is supported")
	}
}

// addRoundKeyInPlace adds the round-th key to the buffer
func (h *Permutation) addRoundKeyInPlace(round int, input []frontend.Variable) {
	for i := 0; i < len(h.params.roundKeys[round]); i++ {
		input[i] = h.api.Add(input[i], h.params.roundKeys[round][i])
	}
}

// Permutation applies the permutation on input, and stores the result in input.
func (h *Permutation) Permutation(input []frontend.Variable) error {
	if len(input) != h.params.width {
		return ErrInvalidSizebuffer
	}

	// external matrix multiplication, cf https://eprint.iacr.org/2023/323.pdf page 14 (part 6)
	h.matMulExternalInPlace(input)

	rf := h.params.nbFullRounds / 2
	for i := 0; i < rf; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}

	for i := rf; i < rf+h.params.nbPartialRounds; i++ {
		// one round = matMulInternal(sBox_sparse(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		h.sBox(0, input)
		h.matMulInternalInPlace(input)
	}
	for i := rf + h.params.nbPartialRounds; i < h.params.nbFullRounds+h.params.nbPartialRounds; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}

	return nil
}

// Compress applies the permutation on left and right and returns the right lane
// of the result. Panics if the permutation instance is not initialized with a
// width of 2.
//
// Implements the [hash.Compressor] interface for building a Merkle-Damgard
// hash construction.
func (h *Permutation) Compress(left, right frontend.Variable) frontend.Variable {
	if h.params.width != 2 {
		panic("poseidon2: Compress can only be used when t=2")
	}
	vars := [2]frontend.Variable{left, right}
	if err := h.Permutation(vars[:]); err != nil {
		panic(err) // this would never happen
	}
	return vars[1]
}
