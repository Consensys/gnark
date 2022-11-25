package field

import "math/big"

type El interface {
	comparable
}

type PtEl[T any] interface {
	SetInt64(int64) *T
	SetUint64(uint64) *T
	SetOne() *T
	SetZero() *T
	SetString(string) *T
	SetInterface(i1 interface{}) (*T, error)
	Exp(T, *big.Int) *T
	Inverse(*T) *T
	Neg(*T) *T
	Double(*T) *T
	Mul(*T, *T) *T
	Add(*T, *T) *T
	Sub(*T, *T) *T
	Div(*T, *T) *T
	BitLen() int
	FromMont() *T
	Bit(i uint64) uint64
	Marshal() []byte
	IsUint64() bool
	Uint64() uint64

	ToBigIntRegular(res *big.Int) *big.Int
	SetBigInt(*big.Int) *T

	IsZero() bool
	IsOne() bool

	Equal(*T) bool
	String() string

	*T
}

func Zero[E El, ptE PtEl[E]]() E {
	var e E
	ptE(&e).SetZero()
	return e
}

func One[E El, ptE PtEl[E]]() E {
	var e E
	ptE(&e).SetOne()
	return e
}

func NegOne[E El, ptE PtEl[E]]() E {
	var e E
	ptE(&e).SetOne()
	ptE(&e).Neg(&e)
	return e
}
