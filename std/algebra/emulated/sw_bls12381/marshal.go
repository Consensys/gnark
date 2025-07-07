package sw_bls12381

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

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

func bitsToU8(api frontend.API, b []frontend.Variable) []uints.U8 {
	nbBits := len(b)
	nbBytes := (nbBits + 7) / 8
	res := make([]uints.U8, nbBytes)

	for i := 0; i < nbBytes; i++ {
		buf := make([]frontend.Variable, 8)
		for j := 0; j < 8; j++ {
			if 8*i+j < nbBits {
				buf[j] = b[8*i+j]
			} else {
				buf[j] = 0
			}
		}
		res[i].Val = bits.FromBinary(api, buf)
	}

	return res
}

func Unmarshal[F emulated.FieldParams](api frontend.API, b []uints.U8) (*emulated.Element[F], error) {
	emApi, err := emulated.NewField[F](api)
	if err != nil {
		return nil, err
	}
	bs := bitsFromU8(api, b)
	res := emApi.FromBits(bs...)
	return res, nil
}

func Marshal[F emulated.FieldParams](api frontend.API, e *emulated.Element[F]) ([]uints.U8, error) {
	emApi, err := emulated.NewField[F](api)
	if err != nil {
		return nil, err
	}
	bs := emApi.ToBits(e)
	res := bitsToU8(api, bs)
	return res, nil
}
