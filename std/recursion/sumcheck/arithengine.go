package sumcheck

import "math/big"

type bigIntEngine struct {
	mod *big.Int
}

func (be *bigIntEngine) Add(dst, a, b *big.Int) *big.Int {
	dst.Add(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *bigIntEngine) Mul(dst, a, b *big.Int) *big.Int {
	dst.Mul(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *bigIntEngine) Sub(dst, a, b *big.Int) *big.Int {
	dst.Sub(a, b)
	dst.Mod(dst, be.mod)
	return dst
}
