package sw_bls12381

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// b is Marshalled following gnark-crypto marshall function, that is
// [MSB ... LSB]
// bitsFromU8 returns the bits of the element it represents, in little endian:
//
//		  b = [   0x..  , ..  ,    0x..    ]
//	   b' = [   0x..  , ..  ,    0x..    ] <- bitReverse(b)
//					 [ lsb..Msb||    ||  lsb..MSB ]
func bitsFromU8(api frontend.API, b []uints.U8) []frontend.Variable {

	nbBits := 8 * len(b)
	res := make([]frontend.Variable, nbBits)

	lb := len(b)
	for i := 0; i < len(b); i++ {
		buf := api.ToBinary(b[i].Val, 8)
		copy(res[8*(lb-1-i):8*(lb-i)], buf) // <- bit reverse op is done here
	}

	return res
}

// deserialise build the finite field element from its bytes representation.
// The byte representation follows the format of gnark-crypto's marshal function, that
// is [MSB || ... || LSB ]
// Should we move it elsewhere ?
func deserialise[F emulated.FieldParams](api frontend.API, b []uints.U8) (*emulated.Element[F], error) {

	emApi, err := emulated.NewField[F](api)
	if err != nil {
		return nil, err
	}

	bs := bitsFromU8(api, b)

	res := emApi.FromBits(bs...)

	return res, nil
}

// UnmarshalCompressed unmarshal a compressed point.
// See https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/11/.
func (g1 *G1) UnmarshalCompressed(compressedPoint [48]uints.U8) *G1Affine {

	// 1 - compute the x coordinate (so it fits in Fp)

	// 1 - hint the result

	// forced to convert the mask to emulated variable...

	// 3 - subgroup check

	// 4 - check logic with the mask

	return nil
}
