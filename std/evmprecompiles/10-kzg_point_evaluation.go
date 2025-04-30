package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	blobVerifyInputLength          = 192  // Max input length for the point evaluation precompile.
	blobCommitmentVersionKZG uint8 = 0x01 // Version byte for the point evaluation precompile.
)

var (
	blobPrecompileReturnValueBytes = [64]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01}
)

// KzgPointEvaluation implements the [KZG_POINT_EVALUATION] precompile at adress 0xa.
//
// The data is encoded as follows:
//
// [versioned_hash | z     | y   | commitment | proof     ]
// <-- 32b -->      <-32b-><-32b-><-- 48b   --><-- 48b -->
//
// with z and y being padded 32 byte big endian values.
// commitment and proof are 48 bytes, encoded following https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/11/
// or Appendix C.  ZCash serialization format for BLS12_381.
//
// [KZG_POINT_EVALUATION] https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md
//
// TODO vk should be hardcoded
func KzgPointEvaluation(
	api frontend.API,
	z, y emulated.Element[sw_bls12381.ScalarField],
	comSerialised []uints.U8,
	proofSerialised []uints.U8,
	vk kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine],
) ([]uints.U8, error) {

	// Verify KZG proof
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		panic(err)
	}

	com, err := g1.UnmarshalCompressed(comSerialised)
	if err != nil {
		panic(err)
	}
	commitmentKzgFormat := kzg.Commitment[sw_bls12381.G1Affine]{
		G1El: *com,
	}
	// verify commitment matches versioned_hash
	// sizeCompressedPoint := 48
	// h, err := sha2.New(api, hash.WithMinimalLength(sizeCompressedPoint))
	// if err != nil {
	// 	return nil, err
	// }
	// h.Write(comSerialised)
	// hashedKzg := h.FixedLengthSum(32)
	// api.AssertIsEqual(hashedKzg[0].Val, blobCommitmentVersionKZG)
	// for i := 1; i < len(hashedKzg); i++ {
	// 	api.AssertIsEqual(hashedKzg[i].Val, data[i].Val)
	// }

	quotient, err := g1.UnmarshalCompressed(proofSerialised)
	if err != nil {
		panic(err)
	}
	proofKzgFormat := kzg.OpeningProof[emulated.BLS12381Fr, sw_bls12381.G1Affine]{
		Quotient:     *quotient,
		ClaimedValue: y,
	}

	v, err := kzg.NewVerifier[emulated.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](api)
	v.CheckOpeningProof(commitmentKzgFormat, proofKzgFormat, z, vk)

	// Return FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS as padded 32 byte big endian values
	var res [64]uints.U8
	for i := 0; i < 64; i++ {
		res[i] = uints.NewU8(blobPrecompileReturnValueBytes[i])
	}

	return res[:], nil
}
