package backend

import (
	"math/big"
	"strconv"

	fr_bls377 "github.com/consensys/gurvy/bls377/fr"
	fr_bls381 "github.com/consensys/gurvy/bls381/fr"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

func FromInterface(i1 interface{}) big.Int {
	var val big.Int

	switch c1 := i1.(type) {
	case uint64:
		val.SetUint64(c1)
	case int:
		if _, ok := val.SetString(strconv.Itoa(c1), 10); !ok {
			panic("unable to set big.Int from base10 string")
		}
	case string:
		if _, ok := val.SetString(c1, 10); !ok {
			panic("unable to set big.Int from base10 string")
		}
	case big.Int:
		val = c1
	case *big.Int:
		val.Set(c1)
	case fr_bn256.Element:
		c1.ToBigIntRegular(&val)
	case *fr_bn256.Element:
		c1.ToBigIntRegular(&val)
	case fr_bls381.Element:
		c1.ToBigIntRegular(&val)
	case *fr_bls381.Element:
		c1.ToBigIntRegular(&val)
	case fr_bls377.Element:
		c1.ToBigIntRegular(&val)
	case *fr_bls377.Element:
		c1.ToBigIntRegular(&val)
	default:
		panic("invalid type")
	}

	return val
}
