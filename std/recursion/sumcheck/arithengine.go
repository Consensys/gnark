package sumcheck

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// element is a field element to be used with [arithEngine].
type element any

// arithEngine defines a minimal arithmetic interface for defining the gate. In
// case of prover, it is initialized with a finite field arithmetic engine
// defined over [*big.Int] or field arithmetic packages. In case of verifier, is
// initialized with non-native arithmetic.
type ArithEngine[E element] interface {
	Add(a, b E) E
	Mul(a, b E) E
	Sub(a, b E) E

	One() E
	Const(i *big.Int) E
}

// BigIntEngine performs computation reducing with given modulus.
type BigIntEngine struct {
	mod *big.Int
	// TODO: we should also add pools for more efficient memory management.
}

func (be *BigIntEngine) Add(a, b *big.Int) *big.Int {
	dst := new(big.Int)
	dst.Add(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *BigIntEngine) Mul(a, b *big.Int) *big.Int {
	dst := new(big.Int)
	dst.Mul(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *BigIntEngine) Sub(a, b *big.Int) *big.Int {
	dst := new(big.Int)
	dst.Sub(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *BigIntEngine) One() *big.Int {
	return big.NewInt(1)
}

func (be *BigIntEngine) Const(i *big.Int) *big.Int {
	return new(big.Int).Set(i)
}

func NewBigIntEngine(mod *big.Int) *BigIntEngine {
	return &BigIntEngine{mod: new(big.Int).Set(mod)}
}

// EmuEngine uses non-native arithmetic for operations.
type EmuEngine[FR emulated.FieldParams] struct {
	f *emulated.Field[FR]
}

func (ee *EmuEngine[FR]) Add(a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Add(a, b)
}

func (ee *EmuEngine[FR]) Mul(a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Mul(a, b)
}

func (ee *EmuEngine[FR]) Sub(a, b *emulated.Element[FR]) *emulated.Element[FR] {
	return ee.f.Sub(a, b)
}

func (ee *EmuEngine[FR]) One() *emulated.Element[FR] {
	return ee.f.One()
}

func (ee *EmuEngine[FR]) Const(i *big.Int) *emulated.Element[FR] {
	return ee.f.NewElement(i)
}

func newEmulatedEngine[FR emulated.FieldParams](api frontend.API) (*EmuEngine[FR], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	return &EmuEngine[FR]{f: f}, nil
}
