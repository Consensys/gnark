package sumcheck

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Element interface{}
type ArithEngine[E Element] interface {
	Add(dst, a, b E) E
	Mul(dst, a, b E) E
	Sub(dst, a, b E) E
}
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

func newBigIntEngine(mod *big.Int) *bigIntEngine {
	return &bigIntEngine{mod: new(big.Int).Set(mod)}
}

type emuEngine[FR emulated.FieldParams] struct {
	f *emulated.Field[FR]
}

func (ee *emuEngine[FR]) Add(_, a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Add(a, b)
}

func (ee *emuEngine[FR]) Mul(_, a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Mul(a, b)
}

func (ee *emuEngine[FR]) Sub(_, a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Sub(a, b)
}

func newEmulatedEngine[FR emulated.FieldParams](api frontend.API) (*emuEngine[FR], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	return &emuEngine[FR]{f: f}, nil
}
