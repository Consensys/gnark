package conversion

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type BytesToEmulatedCircuit[T emulated.FieldParams] struct {
	In       []uints.U8
	Expected emulated.Element[T]

	allowOverflow bool
}

func (c *BytesToEmulatedCircuit[T]) Define(api frontend.API) error {
	var opts []Option
	if c.allowOverflow {
		opts = append(opts, WithAllowOverflow())
	}
	res, err := BytesToEmulated[T](api, c.In, opts...)
	if err != nil {
		return fmt.Errorf("to emulated: %w", err)
	}
	f, err := emulated.NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	f.AssertIsEqual(&c.Expected, res)
	return nil
}

func TestBytesToEmulatedDivisible(t *testing.T) {
	assert := test.NewAssert(t)

	// case when the number of bytes is exactly the length of the emulated field element
	assert.Run(func(assert *test.Assert) {
		var S fp_bls12381.Element
		S.MustSetRandom()
		sbytes := S.Marshal()
		sint := S.BigInt(new(big.Int))
		assert.CheckCircuit(
			&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: uints.NewU8Array(sbytes), Expected: emulated.ValueOf[emparams.BLS12381Fp](sint)}),
			test.WithCurves(ecc.BLS12_377),
		)
	}, "length=exact")

	// case when the number of bytes is smaller than the length of the emulated field element
	assert.Run(func(assert *test.Assert) {
		sint := new(big.Int).SetUint64(0xffffffffffffffff)
		sbytes := sint.Bytes()
		assert.CheckCircuit(
			&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: uints.NewU8Array(sbytes), Expected: emulated.ValueOf[emparams.BLS12381Fp](sint)}),
			test.WithCurves(ecc.BLS12_377),
		)
	}, "length=smaller")

	// case when the number of bytes is larger than the length of the emulated field element
	assert.Run(func(assert *test.Assert) {
		var S fp_bls12381.Element
		S.MustSetRandom()
		sbytes := S.Marshal()
		sbytes = append([]byte{0x00}, sbytes...)
		sint := S.BigInt(new(big.Int))
		assert.CheckCircuit(
			&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: make([]uints.U8, len(sbytes))},
			test.WithInvalidAssignment(&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: uints.NewU8Array(sbytes), Expected: emulated.ValueOf[emparams.BLS12381Fp](sint)}),
			test.WithCurves(ecc.BLS12_377),
		)
	}, "length=larger")

	// case where everything is good, but the bytes represent element larger than the modulus
	assert.Run(func(assert *test.Assert) {
		smallValue := big.NewInt(5)
		S := new(big.Int).Add(smallValue, fp_bls12381.Modulus())
		sbytes := S.Bytes()
		assert.CheckCircuit(
			&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: make([]uints.U8, len(sbytes))},
			test.WithInvalidAssignment(&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: uints.NewU8Array(sbytes), Expected: emulated.ValueOf[emparams.BLS12381Fp](smallValue)}),
			test.WithCurves(ecc.BLS12_377),
		)
	}, "length=overflow")

	// case where everything is good, but the bytes represent element larger than the modulus, but we allow overflow
	assert.Run(func(assert *test.Assert) {
		smallValue := big.NewInt(5)
		S := new(big.Int).Add(smallValue, fp_bls12381.Modulus())
		sbytes := S.Bytes()
		assert.CheckCircuit(
			&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: make([]uints.U8, len(sbytes)), allowOverflow: true},
			test.WithValidAssignment(&BytesToEmulatedCircuit[emparams.BLS12381Fp]{In: uints.NewU8Array(sbytes), Expected: emulated.ValueOf[emparams.BLS12381Fp](smallValue)}),
			test.WithCurves(ecc.BLS12_377),
		)
	}, "length=overflow-allow")
}

type BytesToNativeCircuit struct {
	In       []uints.U8
	Expected frontend.Variable

	allowOverflow bool
}

func (c *BytesToNativeCircuit) Define(api frontend.API) error {
	var opts []Option
	if c.allowOverflow {
		opts = append(opts, WithAllowOverflow())
	}
	res, err := BytesToNative(api, c.In, opts...)
	if err != nil {
		return fmt.Errorf("to native: %w", err)
	}
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestBytesToNative(t *testing.T) {
	assert := test.NewAssert(t)

	// case when the number of bytes is exactly the length of the native field element
	assert.Run(func(assert *test.Assert) {
		var S fr_bn254.Element
		S.MustSetRandom()
		sbytes := S.Marshal()
		sint := S.BigInt(new(big.Int))
		assert.CheckCircuit(
			&BytesToNativeCircuit{In: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&BytesToNativeCircuit{In: uints.NewU8Array(sbytes), Expected: sint}),
			test.WithCurves(ecc.BN254),
		)
	}, "length=exact")

	// case when the number of bytes is smaller than the length of the native field element
	assert.Run(func(assert *test.Assert) {
		sint := new(big.Int).SetUint64(0xffffffffffffffff)
		sbytes := sint.Bytes()
		assert.CheckCircuit(
			&BytesToNativeCircuit{In: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&BytesToNativeCircuit{In: uints.NewU8Array(sbytes), Expected: sint}),
			test.WithCurves(ecc.BN254),
		)
	}, "length=smaller")

	// case when the number of bytes is larger than the length of the native field element
	assert.Run(func(assert *test.Assert) {
		var S fr_bn254.Element
		S.MustSetRandom()
		sbytes := S.Marshal()
		sbytes = append([]byte{0x00}, sbytes...)
		sint := S.BigInt(new(big.Int))
		assert.CheckCircuit(
			&BytesToNativeCircuit{In: make([]uints.U8, len(sbytes))},
			test.WithInvalidAssignment(&BytesToNativeCircuit{In: uints.NewU8Array(sbytes), Expected: sint}),
			test.WithCurves(ecc.BN254),
		)
	}, "length=larger")

	// case where everything is good, but the bytes represent element larger than the modulus
	assert.Run(func(assert *test.Assert) {
		smallValue := big.NewInt(5)
		S := new(big.Int).Add(smallValue, fr_bn254.Modulus())
		sbytes := S.Bytes()
		assert.CheckCircuit(
			&BytesToNativeCircuit{In: make([]uints.U8, len(sbytes))},
			test.WithInvalidAssignment(&BytesToNativeCircuit{In: uints.NewU8Array(sbytes), Expected: smallValue}),
			test.WithCurves(ecc.BN254),
		)
	}, "length=overflow")

	// case where everything is good, but the bytes represent element larger than the modulus, but we allow overflow
	assert.Run(func(assert *test.Assert) {
		smallValue := big.NewInt(5)
		S := new(big.Int).Add(smallValue, fr_bn254.Modulus())
		sbytes := S.Bytes()
		assert.CheckCircuit(
			&BytesToNativeCircuit{In: make([]uints.U8, len(sbytes)), allowOverflow: true},
			test.WithValidAssignment(&BytesToNativeCircuit{In: uints.NewU8Array(sbytes), Expected: smallValue}),
			test.WithCurves(ecc.BN254),
		)
	}, "length=overflow-allow")
}

type NativeToBytesCircuit struct {
	In       frontend.Variable
	Expected []uints.U8
}

func (c *NativeToBytesCircuit) Define(api frontend.API) error {
	res, err := NativeToBytes(api, c.In)
	if err != nil {
		return fmt.Errorf("to bytes: %w", err)
	}
	if len(res) != len(c.Expected) {
		return fmt.Errorf("expected %d bytes, got %d", len(c.Expected), len(res))
	}
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("new bytes: %w", err)
	}
	for i := range res {
		uapi.AssertIsEqual(res[i], c.Expected[i])
	}
	return nil
}

func TestNativeToBytes(t *testing.T) {
	assert := test.NewAssert(t)

	// case when the number of bytes is exactly the length of the emulated field element
	assert.Run(func(assert *test.Assert) {
		var S fr_bn254.Element
		S.MustSetRandom()
		sbytes := S.Marshal()
		sint := S.BigInt(new(big.Int))
		assert.CheckCircuit(
			&NativeToBytesCircuit{Expected: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&NativeToBytesCircuit{In: sint, Expected: uints.NewU8Array(sbytes)}),
			test.WithCurves(ecc.BN254),
		)

		sbuf := make([]byte, fr_bn254.Bytes)
		sint.FillBytes(sbuf)
		assert.CheckCircuit(
			&NativeToBytesCircuit{Expected: make([]uints.U8, len(sbuf))},
			test.WithValidAssignment(&NativeToBytesCircuit{In: sint, Expected: uints.NewU8Array(sbuf)}),
			test.WithCurves(ecc.BN254),
		)
	}, "length=exact")

	// case when the number of bytes is smaller than the length of the emulated field element
	assert.Run(func(assert *test.Assert) {
		bound := new(big.Int).Lsh(big.NewInt(1), fr_bn254.Bytes-1)
		sint, err := rand.Int(rand.Reader, bound)
		assert.NoError(err, "failed to generate random int")
		sbytes := make([]byte, fr_bn254.Bytes)
		sint.FillBytes(sbytes)
		assert.CheckCircuit(
			&NativeToBytesCircuit{Expected: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&NativeToBytesCircuit{In: sint, Expected: uints.NewU8Array(sbytes)}),
			test.WithCurves(ecc.BN254),
		)
	}, "length=smaller")
}

type EmulatedToBytesCircuit[T emulated.FieldParams] struct {
	In       emulated.Element[T]
	Expected []uints.U8
}

func (c *EmulatedToBytesCircuit[T]) Define(api frontend.API) error {
	res, err := EmulatedToBytes(api, &c.In)
	if err != nil {
		return fmt.Errorf("to bytes: %w", err)
	}
	if len(res) != len(c.Expected) {
		return fmt.Errorf("expected %d bytes, got %d", len(c.Expected), len(res))
	}
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("new bytes: %w", err)
	}
	for i := range res {
		uapi.AssertIsEqual(res[i], c.Expected[i])
	}
	return nil
}

func TestEmulatedToBytes(t *testing.T) {
	assert := test.NewAssert(t)

	// case when the number of bytes is exactly the length of the emulated field element
	assert.Run(func(assert *test.Assert) {
		var S fp_bls12381.Element
		S.MustSetRandom()
		sbytes := S.Marshal()
		sint := S.BigInt(new(big.Int))
		assert.CheckCircuit(
			&EmulatedToBytesCircuit[emparams.BLS12381Fp]{Expected: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&EmulatedToBytesCircuit[emparams.BLS12381Fp]{In: emulated.ValueOf[emparams.BLS12381Fp](sint), Expected: uints.NewU8Array(sbytes)}),
			test.WithCurves(ecc.BLS12_377),
		)

		sbuf := make([]byte, fp_bls12381.Bytes)
		sint.FillBytes(sbuf)
		assert.CheckCircuit(
			&EmulatedToBytesCircuit[emparams.BLS12381Fp]{Expected: make([]uints.U8, len(sbuf))},
			test.WithValidAssignment(&EmulatedToBytesCircuit[emparams.BLS12381Fp]{In: emulated.ValueOf[emparams.BLS12381Fp](sint), Expected: uints.NewU8Array(sbuf)}),
			test.WithCurves(ecc.BLS12_377),
		)
	}, "length=exact")

	// case when the number of bytes is smaller than the length of the emulated field element
	assert.Run(func(assert *test.Assert) {
		bound := new(big.Int).Lsh(big.NewInt(1), fp_bls12381.Bytes-1)
		sint, err := rand.Int(rand.Reader, bound)
		assert.NoError(err, "failed to generate random int")
		sbytes := make([]byte, fp_bls12381.Bytes)
		sint.FillBytes(sbytes)
		assert.CheckCircuit(
			&EmulatedToBytesCircuit[emparams.BLS12381Fp]{Expected: make([]uints.U8, len(sbytes))},
			test.WithValidAssignment(&EmulatedToBytesCircuit[emparams.BLS12381Fp]{In: emulated.ValueOf[emparams.BLS12381Fp](sint), Expected: uints.NewU8Array(sbytes)}),
			test.WithCurves(ecc.BLS12_377),
		)
	}, "length=smaller")
}

type AssertBytesLeq struct {
	In    []uints.U8
	bound *big.Int
}

func (c *AssertBytesLeq) Define(api frontend.API) error {
	assertBytesLeq(api, c.In, c.bound)
	return nil
}

func TestAssertBytesLeq(t *testing.T) {
	// all in MSB order, how big.Int is represented in bytes (most significant byte first)
	assert := test.NewAssert(t)

	tc := func(assert *test.Assert, bound []byte, val []byte, isSuccess bool) {
		assert.Run(func(assert *test.Assert) {
			boundInt := new(big.Int).SetBytes(bound)
			circuit := &AssertBytesLeq{In: make([]uints.U8, len(val)), bound: boundInt}
			witness := &AssertBytesLeq{In: uints.NewU8Array(val)}
			var opts []test.TestingOption
			if isSuccess {
				opts = append(opts, test.WithValidAssignment(witness))
			} else {
				opts = append(opts, test.WithInvalidAssignment(witness))
			}
			assert.CheckCircuit(circuit, opts...)
			assert.Run(func(assert *test.Assert) {
				// sanity check that actual big ints compare the same way. We do it in a separate test to avoid
				// shadowing the circuit check test failure.
				valInt := new(big.Int).SetBytes(val)
				if boundInt.Cmp(valInt) >= 0 != isSuccess {
					fmt.Println("boundInt:", boundInt, "valInt:", valInt, "expected:", isSuccess)
					assert.Fail("boundInt.Cmp(valInt) >= 0 != expected")
				}
			}, "sanity")
		}, fmt.Sprintf("bound=0x%x/val=0x%x/expected=%t", bound, val, isSuccess))
	}

	//  -- first byte is smaller than the bound
	//  - second byte is smaller than the bound
	tc(assert, []byte{253, 253}, []byte{252, 252}, true)
	tc(assert, []byte{253, 253}, []byte{0, 252, 252}, true)
	tc(assert, []byte{253, 253}, []byte{1, 252, 252}, false)
	//  - second byte is equal to the bound
	tc(assert, []byte{253, 253}, []byte{252, 253}, true)
	tc(assert, []byte{253, 253}, []byte{0, 252, 253}, true)
	tc(assert, []byte{253, 253}, []byte{1, 252, 253}, false)
	//  - second byte is bigger than the bound
	tc(assert, []byte{253, 253}, []byte{252, 254}, true)
	tc(assert, []byte{253, 253}, []byte{0, 252, 254}, true)
	tc(assert, []byte{253, 253}, []byte{1, 252, 254}, false)

	// -- first byte is equal to the bound
	//  - second byte is smaller than the bound
	tc(assert, []byte{253, 253}, []byte{253, 252}, true)
	tc(assert, []byte{253, 253}, []byte{0, 253, 252}, true)
	tc(assert, []byte{253, 253}, []byte{1, 253, 252}, false)
	//  - second byte is equal to the bound
	tc(assert, []byte{253, 253}, []byte{253, 253}, true)
	tc(assert, []byte{253, 253}, []byte{0, 253, 253}, true)
	tc(assert, []byte{253, 253}, []byte{1, 253, 253}, false)
	//  - second byte is bigger than the bound
	tc(assert, []byte{253, 253}, []byte{253, 254}, false)
	tc(assert, []byte{253, 253}, []byte{0, 253, 254}, false)
	tc(assert, []byte{253, 253}, []byte{1, 253, 254}, false)

	// -- first byte is bigger than the bound
	//  - second byte is smaller than the bound
	tc(assert, []byte{253, 253}, []byte{254, 252}, false)
	tc(assert, []byte{253, 253}, []byte{0, 254, 252}, false)
	tc(assert, []byte{253, 253}, []byte{1, 254, 252}, false)
	//  - second byte is equal to the bound
	tc(assert, []byte{253, 253}, []byte{254, 253}, false)
	tc(assert, []byte{253, 253}, []byte{0, 254, 253}, false)
	tc(assert, []byte{253, 253}, []byte{1, 254, 253}, false)
	//  - second byte is bigger than the bound
	tc(assert, []byte{253, 253}, []byte{254, 254}, false)
	tc(assert, []byte{253, 253}, []byte{0, 254, 254}, false)
	tc(assert, []byte{253, 253}, []byte{1, 254, 254}, false)

	// -- bound longer than the value
	//  - first byte is smaller than the bound
	tc(assert, []byte{253, 253, 253}, []byte{252, 252}, true)
	tc(assert, []byte{253, 253, 253}, []byte{0, 252, 252}, true)
	//  - first byte is equal to the bound
	tc(assert, []byte{253, 253, 253}, []byte{253, 252}, true)
	tc(assert, []byte{253, 253, 253}, []byte{0, 253, 252}, true)
	//  - first byte is bigger than the bound
	tc(assert, []byte{253, 253, 253}, []byte{254, 252}, true)
	tc(assert, []byte{253, 253, 253}, []byte{0, 254, 252}, true)
}
