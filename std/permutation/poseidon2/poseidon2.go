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
	params Parameters
}

// Parameters describing the poseidon2 implementation
type Parameters struct {
	// len(preimage)+len(digest)=len(preimage)+ceil(log(2*<security_level>/r))
	Width int

	// sbox degree
	DegreeSBox int

	// number of full rounds (even number)
	NbFullRounds int

	// number of partial rounds
	NbPartialRounds int

	// round keys: ordered by round then variable
	RoundKeys [][]big.Int
}

func GetDefaultParameters(curve ecc.ID) (Parameters, error) {
	switch curve { // TODO: assumes pairing based builder, reconsider when supporting other backends
	case ecc.BN254:
		p := poseidonbn254.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbn254.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BLS12_381:
		p := poseidonbls12381.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbls12381.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BLS12_377:
		p := poseidonbls12377.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbls12377.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BW6_761:
		p := poseidonbw6761.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbw6761.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BW6_633:
		p := poseidonbw6633.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbw6633.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BLS24_315:
		p := poseidonbls24315.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbls24315.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BLS24_317:
		p := poseidonbls24317.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbls24317.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	default:
		return Parameters{}, fmt.Errorf("curve %s not supported", curve)
	}
}

// NewPoseidon2 returns a new Poseidon2 hasher with default parameters as
// defined in the gnark-crypto library.
func NewPoseidon2(api frontend.API) (*Permutation, error) {
	params, err := GetDefaultParameters(utils.FieldToCurve(api.Compiler().Field()))
	if err != nil {
		return nil, err
	}
	return &Permutation{
		api:    api,
		params: params,
	}, nil
}

// NewPoseidon2FromParameters returns a new Poseidon2 hasher with the given parameters.
// The parameters are used to precompute the round keys. The round key computation
// is deterministic and depends on the curve ID. See the corresponding NewParameters
// function in the gnark-crypto library poseidon2 packages for more details.
func NewPoseidon2FromParameters(api frontend.API, width, nbFullRounds, nbPartialRounds int) (*Permutation, error) {
	params := Parameters{Width: width, NbFullRounds: nbFullRounds, NbPartialRounds: nbPartialRounds}
	switch utils.FieldToCurve(api.Compiler().Field()) { // TODO: assumes pairing based builder, reconsider when supporting other backends
	case ecc.BN254:
		params.DegreeSBox = poseidonbn254.DegreeSBox()
		concreteParams := poseidonbn254.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BLS12_381:
		params.DegreeSBox = poseidonbls12381.DegreeSBox()
		concreteParams := poseidonbls12381.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BLS12_377:
		params.DegreeSBox = poseidonbls12377.DegreeSBox()
		concreteParams := poseidonbls12377.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BW6_761:
		params.DegreeSBox = poseidonbw6761.DegreeSBox()
		concreteParams := poseidonbw6761.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BW6_633:
		params.DegreeSBox = poseidonbw6633.DegreeSBox()
		concreteParams := poseidonbw6633.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BLS24_315:
		params.DegreeSBox = poseidonbls24315.DegreeSBox()
		concreteParams := poseidonbls24315.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BLS24_317:
		params.DegreeSBox = poseidonbls24317.DegreeSBox()
		concreteParams := poseidonbls24317.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
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
	switch h.params.DegreeSBox {
	case 3:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(tmp, input[index])
	case 5:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case 7:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case 17:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case -1:
		input[index] = h.api.Inverse(input[index])
	default:
		panic("sbox degree not supported")
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

	switch h.params.Width {
	case 2:
		// i0 := input[0]
		// i1 := input[1]
		// input[0] = 2*i0 + i1
		// input[1] = i0 + 2*i1
		// input[0] = h.api.Add(h.api.Mul(i0, 2), i1)
		// input[1] = h.api.Add(i0, h.api.Mul(i1, 2))
		tmp := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(tmp, input[0])
		input[1] = h.api.Add(tmp, input[1])
	case 3:
		tmp := h.api.Add(input[0], input[1])
		tmp = h.api.Add(tmp, input[2])
		input[0] = h.api.Add(input[0], tmp)
		input[1] = h.api.Add(input[1], tmp)
		input[2] = h.api.Add(input[2], tmp)
	case 4:
		h.matMulM4InPlace(input)
	default:
		// at this stage t is supposed to be a multiple of 4
		// the MDS matrix is circ(2M4,M4,..,M4)
		h.matMulM4InPlace(input)
		tmp := make([]frontend.Variable, 4)
		for i := 0; i < h.params.Width/4; i++ {
			tmp[0] = h.api.Add(tmp[0], input[4*i])
			tmp[1] = h.api.Add(tmp[1], input[4*i+1])
			tmp[2] = h.api.Add(tmp[2], input[4*i+2])
			tmp[3] = h.api.Add(tmp[3], input[4*i+3])
		}
		for i := 0; i < h.params.Width/4; i++ {
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
	switch h.params.Width {
	case 2:
		// i0 := input[0]
		// i1 := input[1]
		// input[0] = 2*i0 + i1
		// input[1] = i0 + 3*i1
		// input[0] = h.api.Add(h.api.Mul(i0, 2), i1)
		// input[1] = h.api.Add(i0, h.api.Mul(i1, 3))
		sum := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Mul(2, input[1])
		input[1] = h.api.Add(input[1], sum)
	case 3:
		sum := h.api.Add(input[0], input[1])
		sum = h.api.Add(sum, input[2])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Add(input[1], sum)
		input[2] = h.api.Mul(input[2], 2)
		input[2] = h.api.Add(input[2], sum)
	default:
		// TODO: we don't have general case implemented in gnark-crypto side.
		panic("only T=2,3 is supported")
	}
}

// addRoundKeyInPlace adds the round-th key to the buffer
func (h *Permutation) addRoundKeyInPlace(round int, input []frontend.Variable) {
	for i := 0; i < len(h.params.RoundKeys[round]); i++ {
		input[i] = h.api.Add(input[i], h.params.RoundKeys[round][i])
	}
}

// Permutation applies the permutation on input, and stores the result in input.
func (h *Permutation) Permutation(input []frontend.Variable) error {
	if len(input) != h.params.Width {
		return ErrInvalidSizebuffer
	}

	if h.params.Width == 2 {
		return h.permutationW2(input)
	}

	// external matrix multiplication, cf https://eprint.iacr.org/2023/323.pdf page 14 (part 6)
	h.matMulExternalInPlace(input)

	rf := h.params.NbFullRounds / 2
	for i := 0; i < rf; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.Width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}

	for i := rf; i < rf+h.params.NbPartialRounds; i++ {
		// one round = matMulInternal(sBox_sparse(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		h.sBox(0, input)
		h.matMulInternalInPlace(input)
	}
	for i := rf + h.params.NbPartialRounds; i < h.params.NbFullRounds+h.params.NbPartialRounds; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.Width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}

	return nil
}

func (h *Permutation) permutationW2(input []frontend.Variable) error {
	// TODO @gbotrel really what this does is inline the whole permutation for width=2
	// and minimize constraints by packing additions together.
	// should be generalized to other widths if needed.

	// Optimized permutation for width=2
	// This implementation inlines matrix operations and merges round key additions
	// to minimize constraint count.
	//
	// Key insight: In PLONK, multiplication by constants is free, and adding multiple
	// constants in one api.Add call uses a single constraint. We merge round key
	// additions into the preceding matrix multiplication wherever possible.
	//
	// matMulExternalInPlace for width=2:
	//   output[0] = 2*input[0] + input[1]
	//   output[1] = input[0] + 2*input[1]
	//
	// matMulInternalInPlace for width=2:
	//   output[0] = 2*input[0] + input[1]
	//   output[1] = input[0] + 3*input[1]

	rf := h.params.NbFullRounds / 2
	rp := h.params.NbPartialRounds

	// Initial external matrix multiplication merged with first full round's keys
	// matMulExternal + addRoundKey[0]:
	// output[0] = 2*i0 + i1 + rk[0][0]
	// output[1] = i0 + 2*i1 + rk[0][1]
	{
		i0 := input[0]
		i1 := input[1]
		input[0] = h.api.Add(h.api.Mul(i0, 2), i1, &h.params.RoundKeys[0][0])
		input[1] = h.api.Add(i0, h.api.Mul(i1, 2), &h.params.RoundKeys[0][1])
	}

	// =========================================================================
	// First half of full rounds
	// =========================================================================
	// Each round: sBox (keys already added) -> matMulExternal merged with next keys

	for i := 0; i < rf-1; i++ {
		// sBox on both elements (round keys already merged from previous step)
		h.sBox(0, input)
		h.sBox(1, input)

		// matMulExternal merged with next full round's keys
		// output[0] = 2*s0 + s1 + rk[i+1][0]
		// output[1] = s0 + 2*s1 + rk[i+1][1]
		s0 := input[0]
		s1 := input[1]
		input[0] = h.api.Add(h.api.Mul(s0, 2), s1, &h.params.RoundKeys[i+1][0])
		input[1] = h.api.Add(s0, h.api.Mul(s1, 2), &h.params.RoundKeys[i+1][1])
	}

	// Last full round of first half: merge with first partial round's key (only input[0])
	{
		h.sBox(0, input)
		h.sBox(1, input)

		s0 := input[0]
		s1 := input[1]
		// matMulExternal merged with first partial round's key
		// output[0] = 2*s0 + s1 + rk[rf][0]
		// output[1] = s0 + 2*s1 (no key for input[1] in partial rounds)
		input[0] = h.api.Add(h.api.Mul(s0, 2), s1, &h.params.RoundKeys[rf][0])
		input[1] = h.api.Add(s0, h.api.Mul(s1, 2))
	}

	// =========================================================================
	// Partial rounds - optimized with merged round key additions
	// =========================================================================
	// In partial rounds, only input[0] gets a round key (keys have length 1).
	// input[0] already has first partial round's key merged from above.

	firstPartialRound := rf
	lastPartialRound := rf + rp - 1
	firstSecondHalfRound := rf + rp

	if rp == 1 {
		// Only one partial round: sBox + matMulInternal merged with second half's first round keys
		h.sBox(0, input)
		i0 := input[0]
		i1 := input[1]
		// output[0] = 2*i0 + i1 + rk[firstSecondHalfRound][0]
		// output[1] = i0 + 3*i1 + rk[firstSecondHalfRound][1]
		input[0] = h.api.Add(h.api.Mul(i0, 2), i1, &h.params.RoundKeys[firstSecondHalfRound][0])
		input[1] = h.api.Add(i0, h.api.Mul(i1, 3), &h.params.RoundKeys[firstSecondHalfRound][1])
	} else {
		// First partial round: sBox + matMulInternal merged with second partial round's key
		h.sBox(0, input)
		{
			s0 := input[0]
			i1 := input[1]
			input[0] = h.api.Add(h.api.Mul(s0, 2), i1, &h.params.RoundKeys[firstPartialRound+1][0])
			input[1] = h.api.Add(s0, h.api.Mul(i1, 3))
		}

		// Middle partial rounds (not first, not last)
		for i := firstPartialRound + 1; i < lastPartialRound; i++ {
			h.sBox(0, input)
			s0 := input[0]
			i1 := input[1]
			input[0] = h.api.Add(h.api.Mul(s0, 2), i1, &h.params.RoundKeys[i+1][0])
			input[1] = h.api.Add(s0, h.api.Mul(i1, 3))
		}

		// Last partial round: sBox + matMulInternal merged with second half's first round keys
		h.sBox(0, input)
		{
			i0 := input[0]
			i1 := input[1]
			// output[0] = 2*i0 + i1 + rk[firstSecondHalfRound][0]
			// output[1] = i0 + 3*i1 + rk[firstSecondHalfRound][1]
			input[0] = h.api.Add(h.api.Mul(i0, 2), i1, &h.params.RoundKeys[firstSecondHalfRound][0])
			input[1] = h.api.Add(i0, h.api.Mul(i1, 3), &h.params.RoundKeys[firstSecondHalfRound][1])
		}
	}

	// =========================================================================
	// Second half of full rounds
	// =========================================================================
	// First round's keys already merged from partial rounds above.

	for i := firstSecondHalfRound; i < firstSecondHalfRound+rf-1; i++ {
		// sBox on both elements (round keys already merged)
		h.sBox(0, input)
		h.sBox(1, input)

		// matMulExternal merged with next round's keys
		s0 := input[0]
		s1 := input[1]
		input[0] = h.api.Add(h.api.Mul(s0, 2), s1, &h.params.RoundKeys[i+1][0])
		input[1] = h.api.Add(s0, h.api.Mul(s1, 2), &h.params.RoundKeys[i+1][1])
	}

	// Very last full round: no merge needed (nothing after)
	{
		h.sBox(0, input)
		h.sBox(1, input)

		i0 := input[0]
		i1 := input[1]
		input[0] = h.api.Add(h.api.Mul(i0, 2), i1)
		input[1] = h.api.Add(i0, h.api.Mul(i1, 2))
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
	if h.params.Width != 2 {
		panic("poseidon2: Compress can only be used when t=2")
	}
	vars := [2]frontend.Variable{left, right}
	if err := h.Permutation(vars[:]); err != nil {
		panic(err) // this would never happen
	}
	return h.api.Add(vars[1], right)
}
