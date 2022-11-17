package keccak

import (
	"github.com/consensys/gnark/frontend"
)

// -------------------------------------------------------------------------------------------------
//the permutation part of the kecackHash is known as  KeccakF
//keccakHash calles KeccakF many times (depending on the length of the message)
// this is  an implementation of kaccakF in gnark api (but not keccakHash)
// kaccakF = permutation of keccak-hash

type Kapi struct {
	api frontend.API
	one frontend.Variable
	rc  [24]frontend.Variable
}

func KeccakF(api frontend.API, a [25][]frontend.Variable) [25][]frontend.Variable {
	var kapi Kapi
	kapi.api = api
	var one uint64 = 18446744073709551615
	kapi.one = one
	// round constant for kaccakf
	var rc = [24]uint64{
		0x0000000000000001,
		0x0000000000008082,
		0x800000000000808A,
		0x8000000080008000,
		0x000000000000808B,
		0x0000000080000001,
		0x8000000080008081,
		0x8000000000008009,
		0x000000000000008A,
		0x0000000000000088,
		0x0000000080008009,
		0x000000008000000A,
		0x000000008000808B,
		0x800000000000008B,
		0x8000000000008089,
		0x8000000000008003,
		0x8000000000008002,
		0x8000000000000080,
		0x000000000000800A,
		0x800000008000000A,
		0x8000000080008081,
		0x8000000000008080,
		0x0000000080000001,
		0x8000000080008008,
	}

	for i := range rc {
		kapi.rc[i] = rc[i]
	}

	return KeccakFF(kapi, a)
}

// for KeccakF1600 state represented as a slice of 25 uint64s.
func KeccakFF(api Kapi, a [25][]frontend.Variable) [25][]frontend.Variable {

	var bc0, bc1, bc2, bc3, bc4 []frontend.Variable
	var t, d0, d1, d2, d3, d4 []frontend.Variable

	for i := 0; i < 24; i += 4 {
		// Combines the 5 steps in each round into 2 steps.
		// Unrolls 4 rounds per loop and spreads some steps across rounds.

		// Round 1
		bc0 = api.nXor(api.nXor(api.nXor(api.nXor(a[0], a[5]), a[10]), a[15]), a[20])
		bc1 = api.nXor(api.nXor(api.nXor(api.nXor(a[1], a[6]), a[11]), a[16]), a[21])
		bc2 = api.nXor(api.nXor(api.nXor(api.nXor(a[2], a[7]), a[12]), a[17]), a[22])
		bc3 = api.nXor(api.nXor(api.nXor(api.nXor(a[3], a[8]), a[13]), a[18]), a[23])
		bc4 = api.nXor(api.nXor(api.nXor(api.nXor(a[4], a[9]), a[14]), a[19]), a[24])
		d0 = api.nXor(bc4, api.LeftRotate(bc1, 1))
		d1 = api.nXor(bc0, api.LeftRotate(bc2, 1))
		d2 = api.nXor(bc1, api.LeftRotate(bc3, 1))
		d3 = api.nXor(bc2, api.LeftRotate(bc4, 1))
		d4 = api.nXor(bc3, api.LeftRotate(bc0, 1))

		bc0 = api.nXor(a[0], d0)
		t = api.nXor(a[6], d1)
		bc1 = api.LeftRotate(t, 44)
		t = api.nXor(a[12], d2)
		bc2 = api.LeftRotate(t, 43)
		t = api.nXor(a[18], d3)
		bc3 = api.LeftRotate(t, 21)
		t = api.nXor(a[24], d4)
		bc4 = api.LeftRotate(t, 14)

		a[0] = api.nXor(api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1))), api.api.ToBinary(api.rc[i]))
		a[6] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[12] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[18] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[24] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[10], d0)
		bc2 = api.LeftRotate(t, 3)
		t = api.nXor(a[16], d1)
		bc3 = api.LeftRotate(t, 45)
		t = api.nXor(a[22], d2)
		bc4 = api.LeftRotate(t, 61)
		t = api.nXor(a[3], d3)
		bc0 = api.LeftRotate(t, 28)
		t = api.nXor(a[9], d4)
		bc1 = api.LeftRotate(t, 20)

		a[10] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[16] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[22] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[3] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[9] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[20], d0)
		bc4 = api.LeftRotate(t, 18)
		t = api.nXor(a[1], d1)
		bc0 = api.LeftRotate(t, 1)
		t = api.nXor(a[7], d2)
		bc1 = api.LeftRotate(t, 6)
		t = api.nXor(a[13], d3)
		bc2 = api.LeftRotate(t, 25)
		t = api.nXor(a[19], d4)
		bc3 = api.LeftRotate(t, 8)
		a[20] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[1] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[7] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[13] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[19] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[5], d0)
		bc1 = api.LeftRotate(t, 36)
		t = api.nXor(a[11], d1)
		bc2 = api.LeftRotate(t, 10)
		t = api.nXor(a[17], d2)
		bc3 = api.LeftRotate(t, 15)
		t = api.nXor(a[23], d3)
		bc4 = api.LeftRotate(t, 56)
		t = api.nXor(a[4], d4)
		bc0 = api.LeftRotate(t, 27)

		a[5] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[11] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[17] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[23] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[4] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[15], d0)
		bc3 = api.LeftRotate(t, 41)
		t = api.nXor(a[21], d1)
		bc4 = api.LeftRotate(t, 2)
		t = api.nXor(a[2], d2)
		bc0 = api.LeftRotate(t, 62)
		t = api.nXor(a[8], d3)
		bc1 = api.LeftRotate(t, 55)
		t = api.nXor(a[14], d4)
		bc2 = api.LeftRotate(t, 39)

		a[15] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[21] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[2] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[8] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[14] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		// Round 2
		bc0 = api.nXor(api.nXor(api.nXor(api.nXor(a[0], a[5]), a[10]), a[15]), a[20])
		bc1 = api.nXor(api.nXor(api.nXor(api.nXor(a[1], a[6]), a[11]), a[16]), a[21])
		bc2 = api.nXor(api.nXor(api.nXor(api.nXor(a[2], a[7]), a[12]), a[17]), a[22])
		bc3 = api.nXor(api.nXor(api.nXor(api.nXor(a[3], a[8]), a[13]), a[18]), a[23])
		bc4 = api.nXor(api.nXor(api.nXor(api.nXor(a[4], a[9]), a[14]), a[19]), a[24])
		d0 = api.nXor(bc4, api.LeftRotate(bc1, 1))
		d1 = api.nXor(bc0, api.LeftRotate(bc2, 1))
		d2 = api.nXor(bc1, api.LeftRotate(bc3, 1))
		d3 = api.nXor(bc2, api.LeftRotate(bc4, 1))
		d4 = api.nXor(bc3, api.LeftRotate(bc0, 1))

		bc0 = api.nXor(a[0], d0)
		t = api.nXor(a[16], d1)
		bc1 = api.LeftRotate(t, 44)
		t = api.nXor(a[7], d2)
		bc2 = api.LeftRotate(t, 43)
		t = api.nXor(a[23], d3)
		bc3 = api.LeftRotate(t, 21)
		t = api.nXor(a[14], d4)
		bc4 = api.LeftRotate(t, 14)
		a[0] = api.nXor(api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1))), api.api.ToBinary(api.rc[i+1]))
		a[16] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[7] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[23] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[14] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[20], d0)
		bc2 = api.LeftRotate(t, 3)
		t = api.nXor(a[11], d1)
		bc3 = api.LeftRotate(t, 45)
		t = api.nXor(a[2], d2)
		bc4 = api.LeftRotate(t, 61)
		t = api.nXor(a[18], d3)
		bc0 = api.LeftRotate(t, 28)
		t = api.nXor(a[9], d4)
		bc1 = api.LeftRotate(t, 20)
		a[20] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[11] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[2] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[18] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[9] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[15], d0)
		bc4 = api.LeftRotate(t, 18)
		t = api.nXor(a[6], d1)
		bc0 = api.LeftRotate(t, 1)
		t = api.nXor(a[22], d2)
		bc1 = api.LeftRotate(t, 6)
		t = api.nXor(a[13], d3)
		bc2 = api.LeftRotate(t, 25)
		t = api.nXor(a[4], d4)
		bc3 = api.LeftRotate(t, 8)
		a[15] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[6] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[22] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[13] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[4] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[10], d0)
		bc1 = api.LeftRotate(t, 36)
		t = api.nXor(a[1], d1)
		bc2 = api.LeftRotate(t, 10)
		t = api.nXor(a[17], d2)
		bc3 = api.LeftRotate(t, 15)
		t = api.nXor(a[8], d3)
		bc4 = api.LeftRotate(t, 56)
		t = api.nXor(a[24], d4)
		bc0 = api.LeftRotate(t, 27)
		a[10] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[1] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[17] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[8] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[24] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[5], d0)
		bc3 = api.LeftRotate(t, 41)
		t = api.nXor(a[21], d1)
		bc4 = api.LeftRotate(t, 2)
		t = api.nXor(a[12], d2)
		bc0 = api.LeftRotate(t, 62)
		t = api.nXor(a[3], d3)
		bc1 = api.LeftRotate(t, 55)
		t = api.nXor(a[19], d4)
		bc2 = api.LeftRotate(t, 39)
		a[5] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[21] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[12] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[3] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[19] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		// Round 3
		bc0 = api.nXor(api.nXor(api.nXor(api.nXor(a[0], a[5]), a[10]), a[15]), a[20])
		bc1 = api.nXor(api.nXor(api.nXor(api.nXor(a[1], a[6]), a[11]), a[16]), a[21])
		bc2 = api.nXor(api.nXor(api.nXor(api.nXor(a[2], a[7]), a[12]), a[17]), a[22])
		bc3 = api.nXor(api.nXor(api.nXor(api.nXor(a[3], a[8]), a[13]), a[18]), a[23])
		bc4 = api.nXor(api.nXor(api.nXor(api.nXor(a[4], a[9]), a[14]), a[19]), a[24])
		d0 = api.nXor(bc4, api.LeftRotate(bc1, 1))
		d1 = api.nXor(bc0, api.LeftRotate(bc2, 1))
		d2 = api.nXor(bc1, api.LeftRotate(bc3, 1))
		d3 = api.nXor(bc2, api.LeftRotate(bc4, 1))
		d4 = api.nXor(bc3, api.LeftRotate(bc0, 1))

		bc0 = api.nXor(a[0], d0)
		t = api.nXor(a[11], d1)
		bc1 = api.LeftRotate(t, 44)
		t = api.nXor(a[22], d2)
		bc2 = api.LeftRotate(t, 43)
		t = api.nXor(a[8], d3)
		bc3 = api.LeftRotate(t, 21)
		t = api.nXor(a[19], d4)
		bc4 = api.LeftRotate(t, 14)

		a[0] = api.nXor(api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1))), api.api.ToBinary(api.rc[i+2]))
		a[11] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[22] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[8] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[19] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[15], d0)
		bc2 = api.LeftRotate(t, 3)
		t = api.nXor(a[1], d1)
		bc3 = api.LeftRotate(t, 45)
		t = api.nXor(a[12], d2)
		bc4 = api.LeftRotate(t, 61)
		t = api.nXor(a[23], d3)
		bc0 = api.LeftRotate(t, 28)
		t = api.nXor(a[9], d4)
		bc1 = api.LeftRotate(t, 20)
		a[15] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[1] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[12] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[23] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[9] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[5], d0)
		bc4 = api.LeftRotate(t, 18)
		t = api.nXor(a[16], d1)
		bc0 = api.LeftRotate(t, 1)
		t = api.nXor(a[2], d2)
		bc1 = api.LeftRotate(t, 6)
		t = api.nXor(a[13], d3)
		bc2 = api.LeftRotate(t, 25)
		t = api.nXor(a[24], d4)
		bc3 = api.LeftRotate(t, 8)
		a[5] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[16] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[2] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[13] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[24] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[20], d0)
		bc1 = api.LeftRotate(t, 36)
		t = api.nXor(a[6], d1)
		bc2 = api.LeftRotate(t, 10)
		t = api.nXor(a[17], d2)
		bc3 = api.LeftRotate(t, 15)
		t = api.nXor(a[3], d3)
		bc4 = api.LeftRotate(t, 56)
		t = api.nXor(a[14], d4)
		bc0 = api.LeftRotate(t, 27)
		a[20] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[6] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[17] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[3] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[14] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[10], d0)
		bc3 = api.LeftRotate(t, 41)
		t = api.nXor(a[21], d1)
		bc4 = api.LeftRotate(t, 2)
		t = api.nXor(a[7], d2)
		bc0 = api.LeftRotate(t, 62)
		t = api.nXor(a[18], d3)
		bc1 = api.LeftRotate(t, 55)
		t = api.nXor(a[4], d4)
		bc2 = api.LeftRotate(t, 39)
		a[10] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[21] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[7] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[18] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[4] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		// Round 4
		bc0 = api.nXor(api.nXor(api.nXor(api.nXor(a[0], a[5]), a[10]), a[15]), a[20])
		bc1 = api.nXor(api.nXor(api.nXor(api.nXor(a[1], a[6]), a[11]), a[16]), a[21])
		bc2 = api.nXor(api.nXor(api.nXor(api.nXor(a[2], a[7]), a[12]), a[17]), a[22])
		bc3 = api.nXor(api.nXor(api.nXor(api.nXor(a[3], a[8]), a[13]), a[18]), a[23])
		bc4 = api.nXor(api.nXor(api.nXor(api.nXor(a[4], a[9]), a[14]), a[19]), a[24])
		d0 = api.nXor(bc4, api.LeftRotate(bc1, 1))
		d1 = api.nXor(bc0, api.LeftRotate(bc2, 1))
		d2 = api.nXor(bc1, api.LeftRotate(bc3, 1))
		d3 = api.nXor(bc2, api.LeftRotate(bc4, 1))
		d4 = api.nXor(bc3, api.LeftRotate(bc0, 1))

		bc0 = api.nXor(a[0], d0)
		t = api.nXor(a[1], d1)
		bc1 = api.LeftRotate(t, 44)
		t = api.nXor(a[2], d2)
		bc2 = api.LeftRotate(t, 43)
		t = api.nXor(a[3], d3)
		bc3 = api.LeftRotate(t, 21)
		t = api.nXor(a[4], d4)
		bc4 = api.LeftRotate(t, 14)
		a[0] = api.nXor(api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1))), api.api.ToBinary(api.rc[i+3]))
		a[1] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[2] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[3] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[4] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[5], d0)
		bc2 = api.LeftRotate(t, 3)
		t = api.nXor(a[6], d1)
		bc3 = api.LeftRotate(t, 45)
		t = api.nXor(a[7], d2)
		bc4 = api.LeftRotate(t, 61)
		t = api.nXor(a[8], d3)
		bc0 = api.LeftRotate(t, 28)
		t = api.nXor(a[9], d4)
		bc1 = api.LeftRotate(t, 20)
		a[5] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[6] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[7] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[8] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[9] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[10], d0)
		bc4 = api.LeftRotate(t, 18)
		t = api.nXor(a[11], d1)
		bc0 = api.LeftRotate(t, 1)
		t = api.nXor(a[12], d2)
		bc1 = api.LeftRotate(t, 6)
		t = api.nXor(a[13], d3)
		bc2 = api.LeftRotate(t, 25)
		t = api.nXor(a[14], d4)
		bc3 = api.LeftRotate(t, 8)
		a[10] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[11] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[12] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[13] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[14] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[15], d0)
		bc1 = api.LeftRotate(t, 36)
		t = api.nXor(a[16], d1)
		bc2 = api.LeftRotate(t, 10)
		t = api.nXor(a[17], d2)
		bc3 = api.LeftRotate(t, 15)
		t = api.nXor(a[18], d3)
		bc4 = api.LeftRotate(t, 56)
		t = api.nXor(a[19], d4)
		bc0 = api.LeftRotate(t, 27)
		a[15] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[16] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[17] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[18] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[19] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))

		t = api.nXor(a[20], d0)
		bc3 = api.LeftRotate(t, 41)
		t = api.nXor(a[21], d1)
		bc4 = api.LeftRotate(t, 2)
		t = api.nXor(a[22], d2)
		bc0 = api.LeftRotate(t, 62)
		t = api.nXor(a[23], d3)
		bc1 = api.LeftRotate(t, 55)
		t = api.nXor(a[24], d4)
		bc2 = api.LeftRotate(t, 39)
		a[20] = api.nXor(bc0, api.nAnd(bc2, api.nNot(bc1)))
		a[21] = api.nXor(bc1, api.nAnd(bc3, api.nNot(bc2)))
		a[22] = api.nXor(bc2, api.nAnd(bc4, api.nNot(bc3)))
		a[23] = api.nXor(bc3, api.nAnd(bc0, api.nNot(bc4)))
		a[24] = api.nXor(bc4, api.nAnd(bc1, api.nNot(bc0)))
	}
	return a
}

func (kapi Kapi) nXor(a, b []frontend.Variable) []frontend.Variable {
	c := make([]frontend.Variable, 64)
	for i := range a {
		c[i] = kapi.api.Xor(a[i], b[i])
	}
	return c
}

// left rotation  by n element
func (kapi Kapi) LeftRotate(a []frontend.Variable, n int) []frontend.Variable {
	b := append(a[63-n+1:64], a[0:63-n+1]...)
	return b
}

func (kapi Kapi) nAnd(a, b []frontend.Variable) []frontend.Variable {
	c := make([]frontend.Variable, 64)
	for i := range a {
		c[i] = kapi.api.And(a[i], b[i])
	}
	return c
}

func (kapi Kapi) nNot(a []frontend.Variable) []frontend.Variable {
	b := kapi.nXor(a, kapi.api.ToBinary(kapi.one))
	return b
}
