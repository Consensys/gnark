package hash

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// PoseidonT2 is a hasher with T = 2
var PoseidonT2 PoseidonHasher

// PoseidonT4 is a hasher with T = 4
var PoseidonT4 PoseidonHasher

// PoseidonT8 is a hasher with T = 8
var PoseidonT8 PoseidonHasher

// PoseidonHasher contains all the parameters to specify a poseidon hash function
type PoseidonHasher struct {
	t        int // size of Cauchy matrix
	cauchy   [][]fr.Element
	nRoundsF int
	nRoundsP int
}

// Hash hashes a full message
func (p *PoseidonHasher) Hash(msg []fr.Element) fr.Element {
	state := make([]fr.Element, p.t)

	for i := 0; i < len(msg); i += p.t {
		block := make([]fr.Element, p.t)
		if i+p.t >= len(msg) {
			// Only zero-pad the input
			copy(block, msg[i:])
		} else {
			copy(block, msg[i:i+p.t])
		}
		p.Update(state, block)
	}

	return state[0]
}

// Update uses the poseidon permutation in a Miyaguchi-Preenel
// construction to create the hash function.
// https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi.E2.80.93Preneel
func (p *PoseidonHasher) Update(state, block []fr.Element) {

	// Deep-copies the state
	oldState := append([]fr.Element{}, state...)

	// Runs the cipher
	for i := 0; i < p.nRoundsF; i++ {
		AddArkAndKeysInplace(state, block, Arks[i])
		FullRoundInPlace(state)
		state = MatrixMultiplication(p.cauchy, state)
	}

	for i := p.nRoundsF; i < p.nRoundsF+p.nRoundsP; i++ {
		AddArkAndKeysInplace(state, block, Arks[i])
		PartialRoundInplace(state)
		state = MatrixMultiplication(p.cauchy, state)
	}

	for i := p.nRoundsF + p.nRoundsP; i < 2*p.nRoundsF+p.nRoundsP; i++ {
		AddArkAndKeysInplace(state, block, Arks[i])
		FullRoundInPlace(state)
		state = MatrixMultiplication(p.cauchy, state)
	}

	// Recombine with the old state
	for i := range state {
		state[i].Add(&state[i], &oldState[i])
		state[i].Add(&state[i], &block[i])
	}
}

// GenerateMDSMatrix returns the MDS matrix for a given size
func GenerateMDSMatrix(t int) [][]fr.Element {
	result := make([][]fr.Element, t)
	for i := range result {
		result[i] = make([]fr.Element, t)
		for j := range result[i] {
			result[i][j].Set(&xArr[i])
			result[i][j].Add(&result[i][j], &yArr[j])
			result[i][j].Inverse(&result[i][j])
		}
	}
	return result
}

// MatrixMultiplication by a vector
// The dimensions are mat[k][n] * vec[n] = res[k]
func MatrixMultiplication(mat [][]fr.Element, vec []fr.Element) []fr.Element {
	res := make([]fr.Element, len(mat))
	var tmp fr.Element
	for i := range mat {
		for j := range mat[i] {
			tmp.Set(&vec[j])
			tmp.Mul(&tmp, &mat[i][j])
			res[i].Add(&res[i], &tmp)
		}
	}
	return res
}

// SBoxInplace computes x^7 in-place
func SBoxInplace(x *fr.Element) {
	tmp := *x
	x.Square(x)
	x.Mul(x, &tmp)
	x.Square(x)
	x.Mul(x, &tmp)
}

// FullRoundInPlace applies the SBox on all entries
// of the state
func FullRoundInPlace(state []fr.Element) {
	for i := range state {
		SBoxInplace(&state[i])
	}
}

// AddArkAndKeysInplace adds the
func AddArkAndKeysInplace(state []fr.Element, keys []fr.Element, ark fr.Element) {
	for i := range state {
		state[i].Add(&state[i], &keys[i])
		state[i].Add(&state[i], &ark)
	}
}

// PartialRoundInplace applies the SBox on the first entry
func PartialRoundInplace(state []fr.Element) {
	SBoxInplace(&state[0])
}
