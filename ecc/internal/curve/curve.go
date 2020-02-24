package curve

import (
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
)

type FamilyType int

const (
	BLS12 FamilyType = iota
	BN
)

type Data struct {
	Family     FamilyType
	X, P, R    *big.Int
	RandReader io.Reader
}

func New(f FamilyType, x, p string) *Data {
	// TODO eliminate p argument; compute P from X
	d := Data{
		Family: f,
		X:      newInt(x),
		P:      newInt(p),
	}

	// pseudorandom points from a fixed seed
	seed := int64(d.X.Bits()[0]) // use the low word of X as a fixed seed
	d.RandReader = mrand.New(mrand.NewSource(seed))

	return &d
}

func newInt(s string) *big.Int {
	r, success := new(big.Int).SetString(s, 10)
	if !success {
		panic(fmt.Sprintf("can't convert string to integer: %s", s))
	}
	return r
}
