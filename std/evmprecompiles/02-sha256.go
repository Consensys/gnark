package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/sha2"
)

// SHA256Permute implements the SHA256 permutation function as used inside the
// [SHA256] precompile call.
//
// The input prevDigest is the previous digest, blocks is the block of data to
// be hashed and expectedDigest is the expected digest. This function computes
// the new digest by hashing the previous digest and the block of data, and then
// asserts that the computed digest is equal to the expected digest.
//
// We assume the inputs prevDigest, block and expectedDigest are arrays of
// 16-bit integers. We also assume that the caller has already range checked the
// values to be in range.
//
// [SHA256]: https://ethereum.github.io/execution-specs/src/ethereum/paris/vm/precompiled_contracts/sha256.py.html
func SHA256Permute(api frontend.API, prevDigest [16]frontend.Variable, block [32]frontend.Variable, expectedDigest [16]frontend.Variable) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(fmt.Sprintf("new uapi: %v", err))
	}
	// map inputs to supported by gnark
	var prevDigestU32 [8]uints.U32
	var blockU32 [16]uints.U32
	var expectedDigestU32 [8]uints.U32
	toComposeInput := append(prevDigest[:], block[:]...)
	toComposeInput = append(toComposeInput, expectedDigest[:]...)
	byteSplit, err := api.Compiler().NewHint(uint16ToUint8, 128, toComposeInput...)
	if err != nil {
		panic(fmt.Sprintf("convert u16 to u8: %v", err))
	}
	for i := 0; i < len(byteSplit)/2; i++ {
		recomposed := api.Add(api.Mul(byteSplit[i*2+1], 1<<8), byteSplit[i*2])
		api.AssertIsEqual(recomposed, toComposeInput[i])
	}
	for i := range prevDigestU32 {
		prevDigestU32[i] = uapi.PackLSB(
			uapi.ByteValueOf(byteSplit[i*4+0]),
			uapi.ByteValueOf(byteSplit[i*4+1]),
			uapi.ByteValueOf(byteSplit[i*4+2]),
			uapi.ByteValueOf(byteSplit[i*4+3]),
		)
	}
	for i := range blockU32 {
		blockU32[i] = uapi.PackMSB(
			uapi.ByteValueOf(byteSplit[32+i*4+0]),
			uapi.ByteValueOf(byteSplit[32+i*4+1]),
			uapi.ByteValueOf(byteSplit[32+i*4+2]),
			uapi.ByteValueOf(byteSplit[32+i*4+3]),
		)
	}
	for i := range expectedDigestU32 {
		expectedDigestU32[i] = uapi.PackLSB(
			uapi.ByteValueOf(byteSplit[96+i*4+0]),
			uapi.ByteValueOf(byteSplit[96+i*4+1]),
			uapi.ByteValueOf(byteSplit[96+i*4+2]),
			uapi.ByteValueOf(byteSplit[96+i*4+3]),
		)
	}
	// compute in-circuit new digest from prevDigest and block
	computedDigest := sha2.PermuteU32(uapi, prevDigestU32, blockU32)
	// assert that in-circuit computed digest == expectedDigest
	for i := range computedDigest {
		uapi.AssertEq(computedDigest[i], expectedDigestU32[i])
	}
}
