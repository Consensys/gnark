package uintexp

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/std/math/bits"
)

// U8 is a width marker for 8-bit unsigned integers.
type U8 struct{}

// NbBits returns the bit width of the integer type.
func (U8) NbBits() int { return 8 }

// U16 is a width marker for 16-bit unsigned integers.
type U16 struct{}

// NbBits returns the bit width of the integer type.
func (U16) NbBits() int { return 16 }

// Width is the type parameter constraint for the supported integer widths.
type Width interface {
	U8 | U16
	NbBits() int
}

// Uint represents an unsigned integer a ∈ [0, 2^k) in exponent encoding: the
// stored variable is the field element ω^a, where ω is a fixed element of
// multiplicative order 2^k in the native field. It is not the plain integer;
// use [Field.ValueOf] and [Field.Value] to convert at the boundaries and
// [Encode] for witness assignment.
type Uint[W Width] struct {
	// V is the encoded value ω^a. NB! don't access it directly!
	V        frontend.Variable
	internal bool
}

// Encode returns the exponent encoding of v for the given field modulus. It
// is used out-of-circuit to assign a [Uint] witness value.
func Encode[W Width](field *big.Int, v uint64) (Uint[W], error) {
	var w W
	k := w.NbBits()
	om, err := omega(field, k)
	if err != nil {
		return Uint[W]{}, err
	}
	e := new(big.Int).SetUint64(v)
	e.Mod(e, new(big.Int).Lsh(big.NewInt(1), uint(k)))
	return Uint[W]{V: new(big.Int).Exp(om, e, field)}, nil
}

type ctxKey[W Width] struct{}

// Field performs unsigned integer arithmetic in exponent encoding over the
// native field. Use [New] to create a new instance.
type Field[W Width] struct {
	api       frontend.API
	k         int
	q         *big.Int
	omegaPows []*big.Int // omegaPows[i] = ω^(2^i) mod q, i = 0..k-1
	// decoded caches the plain exponent of already-decoded (hence already
	// constrained) variables, keyed by HashCode.
	decoded map[[16]byte]frontend.Variable
	zero    Uint[W]
}

// New returns a new [Field] for the given width. It errors if the
// multiplicative group of the native field has insufficient 2-adicity, i.e.
// v2(q-1) < NbBits. This is a caching constructor: it returns the same
// instance if called multiple times with the same width.
func New[W Width](api frontend.API) (*Field[W], error) {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		panic("compiler does not implement kvstore.Store")
	}
	if cached := kv.GetKeyValue(ctxKey[W]{}); cached != nil {
		if f, ok := cached.(*Field[W]); ok {
			return f, nil
		}
	}
	var w W
	k := w.NbBits()
	q := api.Compiler().Field()
	om, err := omega(q, k)
	if err != nil {
		return nil, fmt.Errorf("exponent encoding of width %d: %w", k, err)
	}
	pows := make([]*big.Int, k)
	pows[0] = om
	for i := 1; i < k; i++ {
		pows[i] = new(big.Int).Mul(pows[i-1], pows[i-1])
		pows[i].Mod(pows[i], q)
	}
	f := &Field[W]{
		api:       api,
		k:         k,
		q:         q,
		omegaPows: pows,
		decoded:   make(map[[16]byte]frontend.Variable),
	}
	f.zero = Uint[W]{V: 1, internal: true}
	kv.SetKeyValue(ctxKey[W]{}, f)
	return f, nil
}

func (f *Field[W]) packInternal(v frontend.Variable) Uint[W] {
	return Uint[W]{V: v, internal: true}
}

// Constant returns the encoding of the constant v mod 2^k. It uses no
// constraints.
func (f *Field[W]) Constant(v uint64) Uint[W] {
	e := new(big.Int).SetUint64(v)
	e.Mod(e, new(big.Int).Lsh(big.NewInt(1), uint(f.k)))
	c := new(big.Int).Exp(f.omegaPows[0], e, f.q)
	return f.packInternal(c)
}

// enforce ensures that the encoded value is in the order-2^k subgroup. Values
// produced by this package are in the subgroup by closure; a value arriving
// as a raw witness is constrained on first use through the decode-and-reencode
// path, which proves both subgroup membership and well-formedness.
func (f *Field[W]) enforce(a Uint[W]) frontend.Variable {
	if a.internal {
		return a.V
	}
	if a.V == nil {
		// not assigned, treated as the zero value (encoding 1), mirroring
		// the uints package convention
		return f.zero.V
	}
	if c, isConst := f.api.ConstantValue(a.V); isConst {
		if _, err := decodeExp(f.q, f.k, new(big.Int).Mod(c, f.q)); err != nil {
			panic(fmt.Sprintf("constant %s is not a valid width-%d exponent encoding", c, f.k))
		}
		return a.V
	}
	f.decode(a.V)
	return a.V
}

// decode returns the range-checked plain exponent of the encoded variable v,
// constraining v to be a valid encoding. Results are cached so a variable is
// constrained only once.
func (f *Field[W]) decode(v frontend.Variable) frontend.Variable {
	var h [16]byte
	hashable, canCache := v.(interface{ HashCode() [16]byte })
	if canCache {
		h = hashable.HashCode()
		if x, ok := f.decoded[h]; ok {
			return x
		}
	}
	xs, err := f.api.Compiler().NewHint(decodeHint, 1, f.k, v)
	if err != nil {
		panic(err)
	}
	x := xs[0]
	// re-encode the hinted exponent and pin it to the input: this both range
	// checks x < 2^k (via the bit decomposition) and proves v ∈ ⟨ω⟩
	bs := bits.ToBinary(f.api, x, bits.WithNbDigits(f.k))
	f.api.AssertIsEqual(f.encodeBits(bs), v)
	if canCache {
		f.decoded[h] = x
	}
	return x
}

// encodeBits returns Π_i (1 + b_i·(ω^(2^i) - 1)) for the given bits. Each
// factor is affine in b_i, so the cost is one multiplication per bit beyond
// the first.
func (f *Field[W]) encodeBits(bs []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(1)
	for i := range bs {
		pm1 := new(big.Int).Sub(f.omegaPows[i], big.NewInt(1))
		term := f.api.Add(f.api.Mul(bs[i], pm1), 1)
		acc = f.api.Mul(acc, term)
	}
	return acc
}

// ValueOf converts a plain variable a into its exponent encoding, range
// checking a < 2^k in the process. It uses ≈2k constraints; a constant input
// folds to a constant encoding with no constraints.
func (f *Field[W]) ValueOf(a frontend.Variable) Uint[W] {
	if c, isConst := f.api.ConstantValue(a); isConst {
		if c.BitLen() > f.k {
			panic(fmt.Sprintf("constant value %s is too large for a width-%d integer", c, f.k))
		}
		return f.Constant(c.Uint64())
	}
	bs := bits.ToBinary(f.api, a, bits.WithNbDigits(f.k))
	return f.packInternal(f.encodeBits(bs))
}

// Value converts an encoded integer back into a plain, range-checked
// variable. The discrete logarithm is solved by a hint out-of-circuit (the
// group order is a power of two, so it is efficiently computable) and
// constrained by re-encoding. It uses ≈2k constraints; repeated calls on the
// same variable are cached.
func (f *Field[W]) Value(a Uint[W]) frontend.Variable {
	if a.V == nil {
		return 0
	}
	if c, isConst := f.api.ConstantValue(a.V); isConst {
		x, err := decodeExp(f.q, f.k, new(big.Int).Mod(c, f.q))
		if err != nil {
			panic(fmt.Sprintf("constant %s is not a valid width-%d exponent encoding", c, f.k))
		}
		return x
	}
	return f.decode(a.V)
}

// Add returns the sum of all inputs modulo 2^k. Each pairwise addition is a
// single multiplication constraint; the reduction modulo 2^k is free as it is
// the order of the encoding group.
func (f *Field[W]) Add(a ...Uint[W]) Uint[W] {
	switch len(a) {
	case 0:
		return f.zero
	case 1:
		return a[0]
	}
	vs := make([]frontend.Variable, len(a))
	for i := range a {
		vs[i] = f.enforce(a[i])
	}
	return f.packInternal(f.api.Mul(vs[0], vs[1], vs[2:]...))
}

// AddConstant returns a + c mod 2^k. It uses no constraints: the constant
// encoding ω^c folds into the linear combination.
func (f *Field[W]) AddConstant(a Uint[W], c uint64) Uint[W] {
	e := new(big.Int).SetUint64(c)
	e.Mod(e, new(big.Int).Lsh(big.NewInt(1), uint(f.k)))
	if e.Sign() == 0 {
		return a
	}
	v := f.enforce(a)
	wc := new(big.Int).Exp(f.omegaPows[0], e, f.q)
	return f.packInternal(f.api.Mul(v, wc))
}

// Neg returns -a mod 2^k using one constraint (a witnessed group inverse; the
// inverse of a subgroup element is in the subgroup).
func (f *Field[W]) Neg(a Uint[W]) Uint[W] {
	v := f.enforce(a)
	return f.packInternal(f.api.Inverse(v))
}

// Sub returns a - b mod 2^k using two constraints.
func (f *Field[W]) Sub(a, b Uint[W]) Uint[W] {
	return f.Add(a, f.Neg(b))
}

// Lsh returns a << c mod 2^k (wrapping shift left, i.e. a·2^c mod 2^k) using
// c squaring constraints. For c >= k the result is the constant zero.
func (f *Field[W]) Lsh(a Uint[W], c int) Uint[W] {
	if c < 0 {
		panic("negative shift")
	}
	if c == 0 {
		return a
	}
	if c >= f.k {
		return f.zero
	}
	v := f.enforce(a)
	for i := 0; i < c; i++ {
		v = f.api.Mul(v, v)
	}
	return f.packInternal(v)
}

// Select returns a if sel is true and b otherwise.
func (f *Field[W]) Select(sel frontend.Variable, a, b Uint[W]) Uint[W] {
	va := f.enforce(a)
	vb := f.enforce(b)
	return f.packInternal(f.api.Select(sel, va, vb))
}

// IsZero returns 1 if a == 0 and 0 otherwise (a == 0 iff the encoding is 1).
func (f *Field[W]) IsZero(a Uint[W]) frontend.Variable {
	v := f.enforce(a)
	return f.api.IsZero(f.api.Sub(v, 1))
}

// AssertIsEqual asserts that two encoded integers are equal.
func (f *Field[W]) AssertIsEqual(a, b Uint[W]) {
	va := f.enforce(a)
	vb := f.enforce(b)
	f.api.AssertIsEqual(va, vb)
}
