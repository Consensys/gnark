package sumcheck

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type element interface{}
type arithEngine[E element] interface {
	Add(a, b E) E
	Mul(a, b E) E
	Sub(a, b E) E

	One() E
	Const(i *big.Int) E
}
type bigIntEngine struct {
	mod *big.Int
}

// TODO: use pool

func (be *bigIntEngine) Add(a, b *big.Int) *big.Int {
	dst := new(big.Int)
	dst.Add(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *bigIntEngine) Mul(a, b *big.Int) *big.Int {
	dst := new(big.Int)
	dst.Mul(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *bigIntEngine) Sub(a, b *big.Int) *big.Int {
	dst := new(big.Int)
	dst.Sub(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *bigIntEngine) One() *big.Int {
	return big.NewInt(1)
}

func (be *bigIntEngine) Const(i *big.Int) *big.Int {
	return new(big.Int).Set(i)
}

func newBigIntEngine(mod *big.Int) *bigIntEngine {
	return &bigIntEngine{mod: new(big.Int).Set(mod)}
}

type emuEngine[FR emulated.FieldParams] struct {
	f *emulated.Field[FR]
}

func (ee *emuEngine[FR]) Add(a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Add(a, b)
}

func (ee *emuEngine[FR]) Mul(a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Mul(a, b)
}

func (ee *emuEngine[FR]) Sub(a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Sub(a, b)
}

func (ee *emuEngine[FR]) One() *emulated.Element[FR] {
	return ee.f.One()
}

func (ee *emuEngine[FR]) Const(i *big.Int) *emulated.Element[FR] {
	return ee.f.NewElement(i)
}

func newEmulatedEngine[FR emulated.FieldParams](api frontend.API) (*emuEngine[FR], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	return &emuEngine[FR]{f: f}, nil
}
