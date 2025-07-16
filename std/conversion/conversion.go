// Package conversion provides methods for converting between different primitive types.
//
// gnark provides different wrappers for extending the usage beyond native field
// elements (bytes, bits, non-native elements etc.). This package implements
// some conversion methods between these types.
//
// It is still work in progress and interfaces may change in the future.
package conversion

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
)

// should have:
//  - convert from bytes to native field element ✅
//  - convert from bytes to emulated field element ✅
//    * same, but allow for overflow? maybe could add an option ✅
//  - convert from native field element to bytes ✅
//  - convert from emulated field element to bytes ✅
//  - convert from native field element to emulated field element
//  - convert from emulated field element to another emulated field element (ECDSA)
//  - convert from bits to native field element (duplicate existing method, for completeness)
//  - convert from bits to emulated field element (? duplicate existing method, for completeness)

// Option allows to configure the conversion functions behavior.
type Option func(*config) error

type config struct {
	allowOverflow bool
}

func newConfig(opts ...Option) (*config, error) {
	c := new(config)
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("nil conversion option provided")
		}
		if err := opt(c); err != nil {
			return nil, fmt.Errorf("apply conversion option: %w", err)
		}
	}
	return c, nil
}

// WithAllowOverflow allows for overflowing the modulus when converting bytes to
// emulated field element. When not set, then we assert that the constructed
// element is strictly less than the modulus.
func WithAllowOverflow() Option {
	return func(c *config) error {
		c.allowOverflow = true
		return nil
	}
}

// BytesToNative converts the bytes in MSB order to a native field element. If
// the option [WithAllowOverflow] is set, then the method does not check that
// the input is strictly less than the modulus of the field. Otherwise, it
// checks that the input is strictly less than the modulus of the field.
//
// It errors when the the provided bytes slice is too large to fit into a native
// field element.
func BytesToNative(api frontend.API, b []uints.U8, opts ...Option) (frontend.Variable, error) {
	if (api.Compiler().Field().BitLen() + 7) < 8*len(b) {
		return nil, fmt.Errorf("input too large to fit into field element")
	}
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	res := bytesToNative(api, b)
	// check that the input was in range of the field modulus. Omit if cfg.allowOverflow is set.
	if !cfg.allowOverflow {
		assertBytesLeq(api, b, api.Compiler().Field())
	}
	return res, nil
}

func bytesToNative(api frontend.API, b []uints.U8) frontend.Variable {
	var res frontend.Variable = 0
	shift := big.NewInt(1)
	for i := len(b) - 1; i >= 0; i-- {
		res = api.Add(res, api.Mul(b[i].Val, shift))
		// shift the value to the left by 8 bits
		shift.Lsh(shift, 8)
	}
	return res
}

// BytesToEmulated converts the bytes in MSB order to an emulated field element.
// If the option [WithAllowOverflow] is set, then the method does not check that
// the input is strictly less than the modulus of the field. Otherwise, it
// checks that the input is strictly less than the modulus of the field.
//
// It errors when the provided bytes slice is too large to fit into an emulated
// field element.
//
// NB! Currently it supports only the case when the emulated field element limb
// width is divisible by 8 bits. If the limb width is not divisible by 8 bits,
// then the method panics. Please open an issue if you need this functionality.
// Otherwise, we will implement it when needed.
func BytesToEmulated[T emulated.FieldParams](api frontend.API, b []uints.U8, opts ...Option) (*emulated.Element[T], error) {
	// panics when couldn't fit
	// we can have several approaches - when the limb width is divisible by 8, then we can just compose the limbs without needing to move to bits
	// otherwise if not, we construct the limb and then move the excess part over

	// first we check that the bytes can fit in the field element. But we don't check yet if the byte representation is smaller than the modulus.
	// we do it later after we have already constructed the field element
	effNbLimbs, effNbBits := emulated.GetEffectiveFieldParams[T](api.Compiler().Field())
	if effNbLimbs*effNbBits < uint(len(b))*8 {
		return nil, fmt.Errorf("input too large to fit into field element")
	}

	// 0 - we don't support when the emulated element limb width is smaller than 8 bits
	if effNbBits < 8 {
		return nil, fmt.Errorf("bytes to emulated conversion not supported for field with limb width smaller than 8 bits, got %d bits", effNbBits)
	}

	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}

	// 1 - handle the case where the limb width is divisible by 8
	if effNbBits%8 == 0 {
		return bytesToEmulatedDivisible[T](cfg, api, b)
	}
	// 2 - handle the case where the limb width is not divisible by 8
	return bytesToEmulatedNotDivisible[T](cfg, api, b)
}

func bytesToEmulatedDivisible[T emulated.FieldParams](cfg *config, api frontend.API, b []uints.U8) (*emulated.Element[T], error) {
	effNbLimbs, effNbBits := emulated.GetEffectiveFieldParams[T](api.Compiler().Field())
	// pad the input bytes to be exactly the number of bytes needed for the emulated field element
	paddingLen := int(effNbLimbs*effNbBits/8) - len(b)
	bPadded := make([]uints.U8, 0, paddingLen+len(b))
	// we left-pad with zeros
	bPadded = append(bPadded, uints.NewU8Array(make([]uint8, paddingLen))...)
	// now we append the original bytes
	bPadded = append(bPadded, b...)
	limbs := make([]frontend.Variable, effNbLimbs)
	for i := range limbs {
		limbs[i] = 0
		shift := big.NewInt(1)
		for j := range int(effNbBits) / 8 {
			limbs[i] = api.Add(limbs[i], api.Mul(bPadded[len(bPadded)-1-i*int(effNbBits)/8-j].Val, shift))
			shift.Lsh(shift, 8)
		}
	}
	f, err := emulated.NewField[T](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	e := f.NewElement(limbs)
	if !cfg.allowOverflow {
		f.AssertIsInRange(e)
	}
	return e, nil
}

func bytesToEmulatedNotDivisible[T emulated.FieldParams](cfg *config, api frontend.API, b []uints.U8) (*emulated.Element[T], error) {
	panic("todo")
}

// NativeToBytes converts a native field element to a slice of bytes in MSB order.
// The number of bytes is determined by the field bit length, rounded up to the
// nearest byte. The method returns a slice of [uints.U8] values, which
// represent the bytes of the native field element.
//
// If the option [WithAllowOverflow] is set, then the method does not check that
// the input is strictly less than the modulus of the field. This may happen in case
// of malicious hint execution. The user could bypass the overflow checking if it is done later,
// i.e. when composing the bytes back to a native field element using [BytesToNative].
func NativeToBytes(api frontend.API, v frontend.Variable, opts ...Option) ([]uints.U8, error) {
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	nbBytes := (api.Compiler().Field().BitLen() + 7) / 8
	res, err := api.NewHint(nativeToBytesHint, nbBytes, v)
	if err != nil {
		return nil, fmt.Errorf("new hint: %w", err)
	}
	if len(res) != nbBytes {
		return nil, fmt.Errorf("expected %d bytes, got %d", nbBytes, len(res))
	}
	resU8 := make([]uints.U8, nbBytes)
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("new uints: %w", err)
	}
	for i := range nbBytes {
		resU8[i] = uapi.ValueOf(res[i])
	}
	// check that the decomposed bytes compose to the original value
	computed := bytesToNative(api, resU8)
	api.AssertIsEqual(v, computed)
	// assert that the bytes are in range of the field modulus. We can omit the
	// check if we don't care about the uniqueness (in case later when composing
	// back to native element the check is done there).
	if !cfg.allowOverflow {
		assertBytesLeq(api, resU8, api.Compiler().Field())
	}
	return resU8, nil
}

// EmulatedToBytes converts an emulated field element to a slice of bytes in MSB
// order. The number of bytes is determined by the emulated field element bit
// length, rounded up to the nearest byte. The method returns a slice of
// [uints.U8] values, which represent the bytes of the emulated field element.
//
// If the option [WithAllowOverflow] is set, then the method does not check that
// the input is strictly less than the modulus of the field. This may happen in case
// of malicious hint execution. The user could bypass the overflow checking if it
// is done later, i.e. when composing the bytes back to a native field element
// using [BytesToEmulated].
//
// NB! Currently it supports only the case when the emulated field element limb
// width is divisible by 8 bits. If the limb width is not divisible by 8 bits,
// then the method panics. Please open an issue if you need this functionality.
func EmulatedToBytes[T emulated.FieldParams](api frontend.API, v *emulated.Element[T], opts ...Option) ([]uints.U8, error) {
	var fr T
	if fr.BitsPerLimb()%8 != 0 {
		panic("EmulatedToBytes: not supported for field with limb width not divisible by 8 bits")
	}
	f, err := emulated.NewField[T](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	var vr *emulated.Element[T]
	if cfg.allowOverflow {
		vr = f.Reduce(v)
	} else {
		vr = f.ReduceStrict(v)
	}

	nbBytes := (api.Compiler().Field().BitLen() + 7) / 8
	nbLimbBytes := fr.BitsPerLimb() / 8
	resU8 := make([]uints.U8, (fr.Modulus().BitLen()+7)/8)
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("new uints: %w", err)
	}
	for i := range vr.Limbs {
		res, err := api.NewHint(nativeToBytesHint, nbBytes, vr.Limbs[len(vr.Limbs)-i-1])
		if err != nil {
			return nil, fmt.Errorf("new hint: %w", err)
		}
		if len(res) != nbBytes {
			return nil, fmt.Errorf("expected %d bytes, got %d", nbBytes, len(res))
		}
		res = res[uint(nbBytes)-nbLimbBytes:] // take only the last nbLimbBytes bytes
		for j := range nbLimbBytes {
			resU8[uint(i)*nbLimbBytes+j] = uapi.ValueOf(res[j])
		}
		computed := bytesToNative(api, resU8[uint(i)*nbLimbBytes:uint(i+1)*nbLimbBytes])
		api.AssertIsEqual(vr.Limbs[len(vr.Limbs)-i-1], computed)
	}
	return resU8, nil
}

// func NativeToEmulated[T emulated.FieldParams](api frontend.API, v frontend.Variable) *emulated.Element[T] {
// 	panic("todo")
// }

// assertBytesLeq checks that the bytes in MSB order are less or equal than the
// bound. The method internally decomposes the bound into MSB bytes.
func assertBytesLeq(api frontend.API, b []uints.U8, bound *big.Int) {
	// we check that the bytes are in range of the field modulus
	// we do it by checking that the first byte is smaller than the first byte of the modulus

	// for this, we first decompose the modulus into bytes
	mBytes := bound.Bytes()
	// if there are less bytes than the modulus, then we don't need to perform the check, it is always smaller
	if len(b) < len(mBytes) {
		return // nothing to check
	}
	// if there are more bytes than the modulus, then we need to check that the high bytes are zero
	for i := 0; i < len(b)-len(mBytes); i++ {
		api.AssertIsEqual(b[i].Val, 0)
	}
	bb := b[len(b)-len(mBytes):] // take the last bytes that correspond to the modulus length
	rchecker := rangecheck.New(api)
	// now we can check the bytes against modulus bytes. The method is
	// generalization of bitwise comparison, but we compare byte-wise. We need
	// to have that for every either
	//  - b[i] < mBytes[i]. If this happens then for the rest of the bytes b[j] (j < i)
	//    we don't have any restrictions. For this we're setting the eq_i variable to 0
	//    to indicate that we have found a byte that is smaller than the modulus byte.
	//  - b[i] == mBytes[i]. If this happens then we need to have the same checks for
	//    b[i-i] and mBytes[i-1] etc.
	//
	// Now, to check that b[i] <= mBytes[i] we can use the range checker gadget
	// to ensure that the difference mBytes[i]-b[i] is non-negative by checking
	// that it has up to |mBytes[i]| bits.
	var eq_i frontend.Variable = 1
	for i := range mBytes {
		// compute the difference
		diff := api.Sub(mBytes[i], bb[i].Val)
		// check that the difference is non-negative. Compute the number of bits to represent the modulus byte
		nbBits := bits.Len8(mBytes[i])
		rchecker.Check(api.Mul(eq_i, diff), nbBits)
		isEq := api.IsZero(diff)
		eq_i = api.Mul(eq_i, isEq)
	}
}
